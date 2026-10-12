// Arnika rotates a WireGuard pre-shared key derived from a QKD key and a post-quantum key agreement with the peer.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/arnika-project/arnika/auth"
	"log/slog"
	"strconv"

	"os"

	"runtime"
	"runtime/secret"
	"sync/atomic"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/hardening"
	"github.com/arnika-project/arnika/kdf"
	"github.com/arnika-project/arnika/repositories/pqchpke"
	"github.com/arnika-project/arnika/services"
	"github.com/arnika-project/arnika/transport"
)

var (
	Version string
	APPName string
)

// shouldSetPSKOnQKDFailure is false exactly when runPQCSetPSKLoop takes over the rotation instead.
func shouldSetPSKOnQKDFailure(cfg *config.Config) bool {
	return cfg.IsQKDRequired() || !cfg.UsePQC()
}

func shouldRunQKD(cfg *config.Config) bool {
	return qkdCompiled && !cfg.IsPQCOnly()
}

var lastQKDPSKAt atomic.Int64

func setPSK(keyWriter *services.KeyWriterService, pqc *services.KeyReaderService, qkd []byte, cfg *config.Config, logger *slog.Logger) bool {
	psk := buildPSK(keyWriter, pqc, qkd, cfg, logger)
	return psk != nil && writePSK(keyWriter, psk, qkd != nil, cfg, logger)
}

// buildPSK invalidates the tunnel and returns nil when no valid PSK can be built, so a failed rotation never keeps the old key.
func buildPSK(keyWriter *services.KeyWriterService, pqc *services.KeyReaderService, qkd []byte, cfg *config.Config, logger *slog.Logger) (psk []byte) {
	if cfg.IsPQCOnly() {
		qkd = nil
	}
	if qkd != nil {
		psk = make([]byte, len(qkd))
		copy(psk, qkd)
	}
	var failure string
	var failureAttrs []any
	defer func() {
		if failure == "" {
			return
		}
		clear(psk)
		psk = nil
		invalidate(keyWriter, logger, failure, failureAttrs...)
	}()
	if len(qkd) == 0 {
		if cfg.IsQKDRequired() {
			failure, failureAttrs = "no QKD key received", []any{"mode", cfg.Mode}
			return
		}
		if qkdCompiled && !cfg.IsPQCOnly() {
			logger.Warn("no QKD key, falling back to the PQC key", "mode", cfg.Mode)
		}
	}
	if cfg.UsePQC() {
		pqcKey, err := pqc.GetNewKey()
		if err != nil {
			if cfg.IsPQCRequired() {
				failure, failureAttrs = "failed to retrieve the PQC key", []any{"err", err, "mode", cfg.Mode}
				return
			}
			logger.Warn("no PQC key, falling back to the QKD key", "err", err, "mode", cfg.Mode)
		} else {
			defer pqcKey.Zero()
			var derivedKey []byte
			secret.Do(func() {
				derivedKey, err = kdf.DeriveKey(psk, pqcKey.Key)
			})
			if err != nil {
				failure, failureAttrs = "failed to derive the PSK", []any{"err", err, "mode", cfg.Mode}
				return
			}
			clear(psk)
			psk = derivedKey
			if qkd == nil {
				logger.Info("HKDF derivation completed for the PQC-only key")
			} else {
				logger.Info("HKDF derivation completed for the QKD+PQC key")
			}
		}
	}
	if len(psk) == 0 {
		failure = "no key material available for a PSK"
		return
	}
	return psk
}

func writePSK(keyWriter *services.KeyWriterService, psk []byte, fromQKD bool, cfg *config.Config, logger *slog.Logger) bool {
	return finishPSK(keyWriter, keyWriter.SetPSK, psk, fromQKD, cfg, logger)
}

func commitPSK(keyWriter *services.KeyWriterService, psk []byte, fromQKD bool, cfg *config.Config, logger *slog.Logger) bool {
	return finishPSK(keyWriter, keyWriter.CommitPSK, psk, fromQKD, cfg, logger)
}

func finishPSK(keyWriter *services.KeyWriterService, write func([]byte) error, psk []byte, fromQKD bool, cfg *config.Config, logger *slog.Logger) bool {
	defer clear(psk)
	if err := write(psk); err != nil {
		invalidate(keyWriter, logger, "failed to configure the PSK via key writer", "err", err)
		return false
	}
	if fromQKD {
		lastQKDPSKAt.Store(time.Now().UnixNano())
	}
	if cfg.WireGuardInterface == "" {
		logger.Info("PSK configured via key writer")
		return true
	}
	logger.Info("PSK configured on WireGuard interface", // message counted by ci/local-darwin/run.sh and ci/e2e
		"iface", cfg.WireGuardInterface, "peer", cfg.WireguardPeerPublicKey)
	return true
}

func invalidate(keyWriter *services.KeyWriterService, logger *slog.Logger, reason string, attrs ...any) {
	logger.Error(reason, attrs...)
	logger.Error("invalidating the tunnel via key writer")
	if err := keyWriter.InvalidateTunnel(); err != nil {
		logger.Error("failed to invalidate the tunnel", "err", err)
	}
}

// nextPQCSetPSKAt falls between two rounds on the scheduler's RoundSeconds grid, so both peers read the same round's key.
func nextPQCSetPSKAt(now time.Time, roundInterval, roundTimeout time.Duration) time.Time {
	secs := pqchpke.RoundSeconds(roundInterval)
	boundary := time.Unix((now.Unix()/secs+1)*secs, 0)
	quiet := time.Duration(secs)*time.Second - roundTimeout
	if quiet <= 0 {
		return boundary
	}
	return boundary.Add(quiet / 2)
}

func runPQCSetPSKLoop(keyWriter *services.KeyWriterService, pqc *services.KeyReaderService, cfg *config.Config, logger *slog.Logger, install func()) {
	for {
		time.Sleep(time.Until(nextPQCSetPSKAt(time.Now(), cfg.PQCRoundInterval, cfg.PQCRoundTimeout)))
		if install != nil {
			install()
		} else {
			setPSK(keyWriter, pqc, nil, cfg, logger)
		}
	}
}

func main() {
	logLevelWarning := setUpLogging()
	versionLong := flag.Bool("version", false, "print version and exit")
	versionShort := flag.Bool("v", false, "alias for version")
	help := flag.Bool("help", false, "print usage and exit")
	switch {
	case *versionLong || *versionShort:
		fmt.Printf("%s version %s\n", APPName, Version)
		os.Exit(0)
	case *help:
		flag.Usage()
		os.Exit(0)
	}

	if logLevelWarning != "" {
		slog.Warn(logLevelWarning)
	}
	for _, err := range hardening.Process() { // before config.Parse, so ARNIKA_PSK never sits in a dumpable, ptraceable or swappable process
		slog.Warn("process hardening incomplete", "err", err)
	}
	var secretErasure bool
	secret.Do(func() { secretErasure = secret.Enabled() })
	if !secretErasure {
		slog.Warn("runtime/secret erasure is inert on this platform: key material is not wiped from registers, stack or freed heap",
			"goos", runtime.GOOS, "goarch", runtime.GOARCH)
	}

	cfg, err := config.Parse()
	if err != nil {
		fatal("failed to parse the configuration", "err", err)
	}
	if err := cfg.ValidateKeySources(qkdCompiled); err != nil {
		fatal(err.Error())
	}
	if err := os.Unsetenv("ARNIKA_PSK"); err != nil {
		slog.Warn("failed to drop ARNIKA_PSK from the environment", "err", err)
	}
	limit, budget, warning := transport.EffectiveRateLimit(cfg)
	if warning != "" {
		slog.Warn(warning)
	}
	cfg.RateLimit = limit
	arnikaID, _ := strconv.Atoi(cfg.ArnikaID)
	setLogIdentity(arnikaID)
	arnikaLog := slog.Default()
	arnikaLog.Info("per-IP rate limit",
		"limit", cfg.RateLimit, "window", cfg.RateWindow, "calculated_budget", budget)
	cfg.PrintStartupConfig()
	done := make(chan bool)
	result := make(chan transport.KeyIDRequest, transport.QKDQueueDepth)
	keyWriter, err := getKeyWriterService(cfg)
	if err != nil {
		fatal("failed to create the key writer", "err", err)
	}
	dirOut, dirIn := auth.DirectionFor(arnikaID)
	var pqc *services.KeyReaderService
	var pqcHandle transport.PQCHandler
	if cfg.UsePQC() {
		pqcService, pqcRun, handle, err := getPQCService(cfg, arnikaLog, dirOut, dirIn)
		if err != nil {
			fatal("failed to create the PQC key reader", "err", err)
		}
		pqc, pqcHandle = pqcService, handle
		pqcCtx, cancelPQC := context.WithCancel(context.Background())
		defer cancelPQC()
		go pqcRun(pqcCtx)
	}

	go func() {
		if err := transport.Serve(transport.ServerConfig{
			Address:      cfg.ListenAddress,
			PSK:          cfg.ArnikaPSK,
			DirOut:       dirOut,
			DirIn:        dirIn,
			KeyIDs:       result,
			Done:         done,
			PQC:          pqcHandle,
			RateLimit:    cfg.RateLimit,
			RateWindow:   cfg.RateWindow,
			MaxClockSkew: cfg.MaxClockSkew,
			Log:          arnikaLog,
		}); err != nil {
			fatal("UDP server stopped", "err", err)
		}
	}()
	if shouldRunQKD(cfg) {
		qkd := getQKDService(cfg)
		rotation := newQKDRotation(cfg, keyWriter, pqc, qkd, arnikaLog)
		if cfg.UsePQC() && !cfg.IsQKDRequired() {
			lastQKDPSKAt.Store(time.Now().UnixNano())
			go runPQCSetPSKLoop(keyWriter, pqc, cfg, arnikaLog, rotation.installFallback)
		}
		go transport.RunKeyIDWorker(done, result, rotation.install)
		go rotation.runDeadlines(done)
		go rotation.runPrimary(done)
	} else {
		go transport.RunKeyIDWorker(done, result, func(req transport.KeyIDRequest) bool {
			arnikaLog.Warn("received a key_id from the peer, but QKD is disabled", "key_id", req.KeyID, "mode", cfg.Mode)
			return false
		})
		go runPQCSetPSKLoop(keyWriter, pqc, cfg, arnikaLog, nil)
	}
	<-done
	cfg.ZeroSecrets()
}
