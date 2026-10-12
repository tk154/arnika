package services

import (
	"crypto/rand"
	"fmt"
	"sync"
)

const pskLen = 32

// keyWriterRepository takes bytes, not a string, because an immutable string PSK can never be cleared.
type keyWriterRepository interface {
	SetPSK(psk []byte) error
}

// tunnelInvalidator is optional, for adapters where a random PSK would not cut traffic:
// a MACsec writer would keep the current key's RX SA and go on accepting the peer's frames.
type tunnelInvalidator interface {
	InvalidateTunnel() error
}

// stagedKeyWriter lets MACsec prepare RX before the peer starts transmitting.
// Other adapters retain the ACK-before-write behavior through CommitPSK.
type stagedKeyWriter interface {
	StagePSK(psk []byte) error
	CommitPSK() error
}

type roundKeyWriter interface {
	StagePSKForRound(psk []byte, round uint64) error
}

type KeyWriterService struct {
	mu   sync.Mutex
	repo keyWriterRepository
}

func NewKeyWriterService(repo keyWriterRepository) *KeyWriterService {
	return &KeyWriterService{repo: repo}
}

func (s *KeyWriterService) InvalidateTunnel() error {
	if inv, ok := s.repo.(tunnelInvalidator); ok {
		s.mu.Lock()
		defer s.mu.Unlock()
		return inv.InvalidateTunnel()
	}
	var psk [pskLen]byte
	defer clear(psk[:])
	if _, err := rand.Read(psk[:]); err != nil {
		return fmt.Errorf("failed to generate random PSK: %w", err)
	}
	return s.SetPSK(psk[:])
}

// SetPSK is serialised because the QKD rotation loop and the wall-clock fallback timer call it concurrently.
func (s *KeyWriterService) SetPSK(psk []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.repo.SetPSK(psk)
}

func (s *KeyWriterService) StagePSK(psk []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if staged, ok := s.repo.(stagedKeyWriter); ok {
		return staged.StagePSK(psk)
	}
	return nil
}

func (s *KeyWriterService) StagePSKForRound(psk []byte, round uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if staged, ok := s.repo.(roundKeyWriter); ok {
		return staged.StagePSKForRound(psk, round)
	}
	if staged, ok := s.repo.(stagedKeyWriter); ok {
		return staged.StagePSK(psk)
	}
	return nil
}

func (s *KeyWriterService) CommitPSK(psk []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if staged, ok := s.repo.(stagedKeyWriter); ok {
		return staged.CommitPSK()
	}
	return s.repo.SetPSK(psk)
}
