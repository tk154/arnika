package services

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeWriter struct {
	mu          sync.Mutex
	writes      [][]byte
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	delay       time.Duration
}

func (f *fakeWriter) SetPSK(psk []byte) error {
	n := f.inFlight.Add(1)
	for {
		peak := f.maxInFlight.Load()
		if n <= peak || f.maxInFlight.CompareAndSwap(peak, n) {
			break
		}
	}
	time.Sleep(f.delay)
	f.mu.Lock()
	f.writes = append(f.writes, bytes.Clone(psk))
	f.mu.Unlock()
	f.inFlight.Add(-1)
	return nil
}

func TestInvalidateTunnelInstallsAFreshRandomKey(t *testing.T) {
	f := &fakeWriter{}
	s := NewKeyWriterService(f)

	for range 2 {
		if err := s.InvalidateTunnel(); err != nil {
			t.Fatalf("InvalidateTunnel: %v", err)
		}
	}
	if len(f.writes) != 2 {
		t.Fatalf("got %d writes, want 2", len(f.writes))
	}
	for i, w := range f.writes {
		if len(w) != pskLen {
			t.Errorf("write %d is %d bytes, want %d", i, len(w), pskLen)
		}
		if bytes.Equal(w, make([]byte, pskLen)) {
			t.Errorf("write %d is all zeroes, so no key was generated", i)
		}
	}
	if bytes.Equal(f.writes[0], f.writes[1]) {
		t.Error("two invalidations produced the same key; it must be fresh each time")
	}
}

func TestSetPSKIsSerialised(t *testing.T) {
	f := &fakeWriter{delay: time.Millisecond}
	s := NewKeyWriterService(f)

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			psk := make([]byte, pskLen)
			psk[0] = byte(i)
			if err := s.SetPSK(psk); err != nil {
				t.Errorf("SetPSK: %v", err)
			}
		}()
	}
	wg.Wait()

	if peak := f.maxInFlight.Load(); peak != 1 {
		t.Errorf("%d concurrent writes reached the adapter, want 1", peak)
	}
	if len(f.writes) != 8 {
		t.Errorf("got %d writes, want 8", len(f.writes))
	}
}

type invalidatingWriter struct {
	fakeWriter
	invalidations int
}

func (w *invalidatingWriter) InvalidateTunnel() error {
	w.invalidations++
	return nil
}

func TestInvalidateTunnelPrefersTheAdapterHook(t *testing.T) {
	w := &invalidatingWriter{}
	s := NewKeyWriterService(w)

	if err := s.InvalidateTunnel(); err != nil {
		t.Fatalf("InvalidateTunnel: %v", err)
	}
	if w.invalidations != 1 {
		t.Errorf("adapter InvalidateTunnel called %d times, want 1", w.invalidations)
	}
	if len(w.writes) != 0 {
		t.Errorf("got %d random-PSK writes, want none when the adapter invalidates itself", len(w.writes))
	}
}

func TestNonStagedWriterWaitsForCommit(t *testing.T) {
	w := &fakeWriter{}
	s := NewKeyWriterService(w)
	key := bytes.Repeat([]byte{5}, 32)
	if err := s.StagePSKForRound(key, 42); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 0 {
		t.Fatal("WireGuard writer wrote before the peer acknowledgement")
	}
	if err := s.CommitPSK(key); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 1 || !bytes.Equal(w.writes[0], key) {
		t.Fatal("commit did not write the prepared PSK")
	}
}
