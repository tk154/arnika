package main

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/services"
	"github.com/arnika-project/arnika/transport"
)

type rotationWriter struct {
	stages, commits, invalidations int
	stageErr, commitErr            error
	round                          uint64
	onCommit                       func()
}

func (w *rotationWriter) SetPSK([]byte) error   { return errors.New("unexpected uncoordinated write") }
func (w *rotationWriter) StagePSK([]byte) error { w.stages++; return w.stageErr }
func (w *rotationWriter) StagePSKForRound(p []byte, round uint64) error {
	w.round = round
	return w.StagePSK(p)
}
func (w *rotationWriter) CommitPSK() error {
	w.commits++
	if w.onCommit != nil {
		w.onCommit()
	}
	return w.commitErr
}
func (w *rotationWriter) InvalidateTunnel() error { w.invalidations++; return nil }

type rotationReader struct{ resolve func(string) error }

func (r rotationReader) GetNewKey() (string, []byte, error) {
	return "shared-key-id", bytes.Repeat([]byte{3}, 32), nil
}
func (r rotationReader) GetKeyByID(id string) ([]byte, error) {
	if r.resolve != nil {
		if err := r.resolve(id); err != nil {
			return nil, err
		}
	}
	return bytes.Repeat([]byte{3}, 32), nil
}

func rotationTestPair(t *testing.T) (*qkdRotation, *qkdRotation, *rotationWriter, *rotationWriter, *time.Time) {
	t.Helper()
	now := time.Unix(1700000005, 0)
	newPeer := func(id string) (*qkdRotation, *rotationWriter) {
		cfg := &config.Config{Interval: 10 * time.Second, KMSRetryInterval: time.Millisecond,
			Mode: "AtLeastQkdRequired", ArnikaID: id, ArnikaPSK: bytes.Repeat([]byte{9}, 32)}
		w := &rotationWriter{}
		r := newQKDRotation(cfg, services.NewKeyWriterService(w), nil,
			services.NewKeyReaderService(rotationReader{}), slog.New(slog.DiscardHandler))
		r.now = func() time.Time { return now }
		return r, w
	}
	a, aw := newPeer("9999")
	b, bw := newPeer("9998")
	if !a.cfg.IsPrimary(qkdWindowAt(now, a.cfg.Interval).round) {
		a, b, aw, bw = b, a, bw, aw
	}
	return a, b, aw, bw, &now
}

func TestQKDWindowsDoNotDependOnStartupOrRetry(t *testing.T) {
	for _, interval := range []time.Duration{10 * time.Second, 2 * time.Second, 100 * time.Millisecond} {
		start := time.Unix(1700000000, 0)
		want := qkdWindowAt(start, interval)
		for _, offset := range []time.Duration{time.Millisecond, interval / 3, interval - time.Nanosecond} {
			if got := qkdWindowAt(start.Add(offset), interval); got != want {
				t.Fatalf("interval %s, startup offset %s: got %+v, want %+v", interval, offset, got, want)
			}
		}
	}
}

func TestQKDBothReceiveKeysReadyBeforeEitherTransmitSwitch(t *testing.T) {
	primary, backup, pw, bw, now := rotationTestPair(t)
	w := qkdWindowAt(*now, primary.cfg.Interval)
	primary.send = func(c transport.ClientConfig) error {
		if pw.stages != 1 || pw.commits != 0 {
			t.Fatal("primary did not stage before sending")
		}
		if !backup.install(transport.KeyIDRequest{KeyID: c.KeyID, Round: c.Round}) {
			t.Fatal("backup rejected current round")
		}
		if bw.commits != 1 {
			t.Fatal("backup acknowledged before committing")
		}
		return nil
	}
	primary.rotate(make(chan bool), w)
	if pw.commits != 1 || pw.round != bw.round {
		t.Fatalf("commits=%d, primary round=%d backup round=%d", pw.commits, pw.round, bw.round)
	}
	// The old per-process counter bug invalidated the backup at this boundary.
	*now = w.end
	primary.expire(w.round)
	backup.expire(w.round)
	if pw.invalidations+bw.invalidations != 0 {
		t.Fatal("successful round was invalidated at its deadline")
	}
}

func TestQKDResendsDoNotResetSAsAndExpiredPacketsCannotRestoreTraffic(t *testing.T) {
	_, backup, _, bw, now := rotationTestPair(t)
	round := qkdWindowAt(*now, backup.cfg.Interval).round
	req := transport.KeyIDRequest{KeyID: "shared-key-id", Round: round}
	if !backup.install(req) || !backup.install(req) {
		t.Fatal("successful install or resend rejected")
	}
	if bw.stages != 1 || bw.commits != 1 {
		t.Fatal("resend reinstalled key and reset packet numbers")
	}
	for _, bad := range []transport.KeyIDRequest{{KeyID: req.KeyID}, {KeyID: req.KeyID, Round: round - 1}, {KeyID: req.KeyID, Round: round + 1}, {KeyID: "different-id", Round: round}} {
		if backup.install(bad) {
			t.Fatalf("accepted invalid request %+v", bad)
		}
	}
	*now = now.Add(20 * time.Second)
	backup.expire(round + 1)
	backup.expire(round + 1)
	if bw.invalidations != 1 {
		t.Fatalf("invalidations=%d, want 1", bw.invalidations)
	}
	if backup.install(req) || bw.stages != 1 {
		t.Fatal("expired resend restored traffic")
	}
}

func TestQKDLateKMSResultAndAcknowledgementDoNotActivateExpiredKeys(t *testing.T) {
	t.Run("KMS lookup", func(t *testing.T) {
		_, backup, _, bw, now := rotationTestPair(t)
		round := qkdWindowAt(*now, backup.cfg.Interval).round
		backup.qkd = services.NewKeyReaderService(rotationReader{resolve: func(string) error { *now = now.Add(10 * time.Second); backup.expire(round); return nil }})
		if backup.install(transport.KeyIDRequest{KeyID: "slow", Round: round}) {
			t.Fatal("accepted late KMS result")
		}
		if bw.stages != 0 || bw.invalidations != 1 {
			t.Fatalf("stages=%d invalidations=%d", bw.stages, bw.invalidations)
		}
	})
	t.Run("acknowledgement", func(t *testing.T) {
		primary, _, pw, _, now := rotationTestPair(t)
		w := qkdWindowAt(*now, primary.cfg.Interval)
		primary.send = func(transport.ClientConfig) error { *now = w.end; primary.expire(w.round); return nil }
		primary.rotate(make(chan bool), w)
		if pw.commits != 0 || pw.invalidations != 1 {
			t.Fatalf("commits=%d invalidations=%d", pw.commits, pw.invalidations)
		}
	})
}

func TestQKDFailedInstallNeverAcknowledges(t *testing.T) {
	for _, phase := range []string{"stage", "commit"} {
		t.Run(phase, func(t *testing.T) {
			_, backup, _, bw, now := rotationTestPair(t)
			if phase == "stage" {
				bw.stageErr = errors.New("netlink failure")
			} else {
				bw.commitErr = errors.New("netlink failure")
			}
			if backup.install(transport.KeyIDRequest{KeyID: "failed", Round: qkdWindowAt(*now, backup.cfg.Interval).round}) {
				t.Fatal("acknowledged failed install")
			}
			if bw.invalidations != 1 {
				t.Fatal("failed install did not fail closed")
			}
		})
	}
}

func TestQKDBackendCommitCrossingDeadlineFailsClosed(t *testing.T) {
	_, backup, _, bw, now := rotationTestPair(t)
	w := qkdWindowAt(*now, backup.cfg.Interval)
	bw.onCommit = func() { *now = w.end }
	if backup.install(transport.KeyIDRequest{KeyID: "slow-commit", Round: w.round}) {
		t.Fatal("acknowledged installation completed after deadline")
	}
	if bw.invalidations != 1 || backup.haveInstalled {
		t.Fatal("late backend completion kept the expired key")
	}
}

func TestQKDMissedAcknowledgementRecoversInANextSharedRound(t *testing.T) {
	a, b, aw, bw, now := rotationTestPair(t)
	w := qkdWindowAt(*now, a.cfg.Interval)
	a.send = func(c transport.ClientConfig) error {
		if !b.install(transport.KeyIDRequest{KeyID: c.KeyID, Round: c.Round}) {
			t.Fatal("backup install failed")
		}
		return errors.New("ACK lost")
	}
	a.rotate(make(chan bool), w)
	if aw.invalidations != 1 || bw.commits != 1 {
		t.Fatal("did not reproduce asymmetric ACK loss")
	}
	*now = now.Add(10 * time.Second)
	if !a.cfg.IsPrimary(w.round + 1) {
		a, b, aw, bw = b, a, bw, aw
	}
	a.send = func(c transport.ClientConfig) error {
		if !b.install(transport.KeyIDRequest{KeyID: c.KeyID, Round: c.Round}) {
			t.Fatal("recovery install failed")
		}
		return nil
	}
	a.rotate(make(chan bool), qkdWindowAt(*now, a.cfg.Interval))
	if !a.haveInstalled || !b.haveInstalled || a.installedRound != b.installedRound || aw.round != bw.round {
		t.Fatal("peers did not converge on the next shared round")
	}
}
