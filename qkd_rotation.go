package main

import (
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/arnika-project/arnika/auth"
	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/services"
	"github.com/arnika-project/arnika/transport"
)

// qkdWindow is shared by peers regardless of startup time or KMS retries.
// Exchanging in the middle leaves room for clock skew and for PQC to publish
// the boundary's key before either peer derives the PSK.
type qkdWindow struct {
	round       uint64
	sendAt, end time.Time
}

func qkdWindowAt(now time.Time, interval time.Duration) qkdWindow {
	round := now.UnixNano() / int64(interval)
	start := time.Unix(0, round*int64(interval))
	return qkdWindow{uint64(round), start.Add(interval / 2), start.Add(interval)}
}

type qkdRotation struct {
	cfg      *config.Config
	writer   *services.KeyWriterService
	pqc, qkd *services.KeyReaderService
	log      *slog.Logger
	now      func() time.Time
	send     func(transport.ClientConfig) error

	mu             sync.Mutex // installation and expiry must not race
	haveInstalled  bool
	installedRound uint64
	installedID    string
	invalidated    bool
	stagedRound    uint64
}

func newQKDRotation(cfg *config.Config, writer *services.KeyWriterService, pqc, qkd *services.KeyReaderService, log *slog.Logger) *qkdRotation {
	return &qkdRotation{cfg: cfg, writer: writer, pqc: pqc, qkd: qkd, log: log, now: time.Now, send: transport.SendKeyID}
}

func (r *qkdRotation) current(round uint64) bool {
	return round != 0 && qkdWindowAt(r.now(), r.cfg.Interval).round == round
}

func (r *qkdRotation) failedLocked(round uint64, reason string, attrs ...any) {
	if r.haveInstalled && r.installedRound >= round {
		return // a late error must not invalidate a successful or newer install
	}
	r.log.Error(reason, append(attrs, "round", round)...)
	if shouldSetPSKOnQKDFailure(r.cfg) && !r.invalidated {
		setPSK(r.writer, r.pqc, nil, r.cfg, r.log)
		r.invalidated = true
	}
}

func (r *qkdRotation) installedLocked(round uint64, id string) {
	r.haveInstalled, r.installedRound, r.installedID = true, round, id
	r.invalidated = false
	r.stagedRound = 0
}

// install only accepts the elected peer's current numbered round. Old or
// legacy packets cannot reinstall a key or satisfy another round's deadline.
func (r *qkdRotation) install(req transport.KeyIDRequest) bool {
	if !r.current(req.Round) || r.cfg.IsPrimary(req.Round) {
		r.log.Warn("key_id is not from the primary for the current QKD round", "round", req.Round)
		return false
	}
	r.mu.Lock()
	if r.haveInstalled && r.installedRound == req.Round {
		ok := r.installedID == req.KeyID && !r.invalidated
		r.mu.Unlock()
		return ok
	}
	r.mu.Unlock()

	log := r.log.With("role", "backup", "round", req.Round)
	log.Info("requesting the QKD key for the peer's key_id", "key_id", req.KeyID, "kms", r.cfg.KMSURL)
	key, err := r.qkd.GetKeyByID(req.KeyID)
	if key != nil {
		defer key.Zero()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.current(req.Round) {
		return false // the lookup finished after its round expired
	}
	if err != nil {
		r.failedLocked(req.Round, "failed to retrieve the QKD key for the peer's key_id", "err", err)
		return false
	}
	psk := buildPSK(r.writer, r.pqc, key.Key, r.cfg, log)
	if psk == nil {
		r.invalidated = true
		return false
	}
	defer clear(psk)
	// The primary staged its RX before sending this numbered request.
	if err := r.writer.StagePSKForRound(psk, req.Round); err != nil {
		invalidate(r.writer, log, "failed to stage the PSK", "err", err)
		r.invalidated = true
		return false
	}
	if !r.current(req.Round) {
		return false
	}
	if !commitPSK(r.writer, psk, true, r.cfg, log) {
		r.invalidated = true
		return false
	}
	if !r.current(req.Round) {
		r.failedLocked(req.Round, "QKD key installation finished after its deadline")
		return false
	}
	r.installedLocked(req.Round, req.KeyID)
	return true
}

func (r *qkdRotation) expire(round uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if qkdWindowAt(r.now(), r.cfg.Interval).round <= round {
		return
	}
	r.failedLocked(round, "no successful QKD key installation by the round deadline")
}

func waitQKDUntil(done <-chan bool, at time.Time) bool {
	timer := time.NewTimer(time.Until(at))
	defer timer.Stop()
	select {
	case <-done:
		return false
	case <-timer.C:
		return true
	}
}

// Deadlines run separately so even a KMS call that outlives its round cannot
// indefinitely keep a required QKD key in use.
func (r *qkdRotation) runDeadlines(done <-chan bool) {
	now := r.now()
	w := qkdWindowAt(now, r.cfg.Interval)
	check := !now.After(w.sendAt) // joining after the exchange gets one partial-round grace
	for waitQKDUntil(done, w.end) {
		if check {
			r.expire(w.round)
		}
		w = qkdWindowAt(r.now(), r.cfg.Interval)
		check = true
	}
}

func (r *qkdRotation) runPrimary(done <-chan bool) {
	for {
		w := qkdWindowAt(r.now(), r.cfg.Interval)
		if r.now().After(w.sendAt) {
			w = qkdWindowAt(w.end, r.cfg.Interval)
		}
		if !waitQKDUntil(done, w.sendAt) {
			return
		}
		if r.current(w.round) && r.cfg.IsPrimary(w.round) {
			r.rotate(done, w)
		}
		if !waitQKDUntil(done, w.end) {
			return
		}
	}
}

func (r *qkdRotation) rotate(done <-chan bool, w qkdWindow) {
	log := r.log.With("role", "primary", "round", w.round)
	var key *services.Key
	for {
		log.Info("requesting a new QKD key", "kms", r.cfg.KMSURL)
		var err error
		key, err = r.qkd.GetNewKey()
		if err == nil {
			break
		}
		log.Error("failed to retrieve a QKD key", "err", err)
		retry := r.now().Add(r.cfg.KMSRetryInterval)
		if !retry.Before(w.end) || !waitQKDUntil(done, retry) || !r.current(w.round) {
			return
		}
	}
	defer key.Zero()
	r.mu.Lock()
	if !r.current(w.round) || key.ID == "" {
		r.mu.Unlock()
		return
	}
	psk := buildPSK(r.writer, r.pqc, key.Key, r.cfg, log)
	if psk == nil {
		r.invalidated = true
		r.mu.Unlock()
		return
	}
	defer clear(psk)
	if err := r.writer.StagePSKForRound(psk, w.round); err != nil {
		invalidate(r.writer, log, "failed to stage the PSK", "err", err)
		r.invalidated = true
		r.mu.Unlock()
		return
	}
	if !r.current(w.round) {
		r.mu.Unlock()
		return
	}
	r.stagedRound = w.round
	r.mu.Unlock()

	id, _ := strconv.Atoi(r.cfg.ArnikaID)
	dirOut, dirIn := auth.DirectionFor(id)
	log.Info("sending the key_id to the peer", "key_id", key.ID, "peer", r.cfg.ServerAddress)
	err := r.send(transport.ClientConfig{
		Address: r.cfg.ServerAddress, PSK: r.cfg.ArnikaPSK,
		DirOut: dirOut, DirIn: dirIn, KeyID: key.ID, Round: w.round,
		Timeout: r.cfg.ArnikaPeerTimeout, Deadline: w.end,
		MaxClockSkew: r.cfg.MaxClockSkew, Log: log,
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.failedLocked(w.round, "the peer did not confirm the QKD round", "err", err)
		return
	}
	if !r.current(w.round) {
		return
	}
	if !commitPSK(r.writer, psk, true, r.cfg, log) {
		r.invalidated = true
		return
	}
	if !r.current(w.round) {
		r.failedLocked(w.round, "QKD key installation finished after its deadline")
		return
	}
	r.installedLocked(w.round, key.ID)
}

func (r *qkdRotation) installFallback() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current(r.stagedRound) || time.Since(time.Unix(0, lastQKDPSKAt.Load())) < 2*r.cfg.Interval {
		return
	}
	r.log.Warn("no QKD key, installing a PQC-only PSK", "mode", r.cfg.Mode)
	setPSK(r.writer, r.pqc, nil, r.cfg, r.log)
}
