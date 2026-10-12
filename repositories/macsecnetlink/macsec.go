//go:build linux

// Platform constraint only: generic netlink and rtnetlink are Linux-only.
// This is not a writer-selection tag; the adapter still compiles,
// vets, lints and tests on every ordinary `go test ./...` run.

// Package macsecnetlink writes the key as MACsec SAs through generic netlink.
package macsecnetlink

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// MACsec genetlink constants from linux/if_macsec.h.
const (
	macsecGenlName    = "macsec"
	macsecGenlVersion = 1

	macsecCmdAddRxsc = 1
	macsecCmdAddTxsa = 4
	macsecCmdDelTxsa = 5
	macsecCmdUpdTxsa = 6
	macsecCmdAddRxsa = 7
	macsecCmdDelRxsa = 8
	macsecCmdUpdRxsa = 9

	macsecAttrIfindex    = 1
	macsecAttrRxscConfig = 2
	macsecAttrSaConfig   = 3

	macsecRxscAttrSci    = 1
	macsecRxscAttrActive = 2

	macsecSaAttrAn     = 1
	macsecSaAttrActive = 2
	macsecSaAttrPn     = 3
	macsecSaAttrKey    = 4
	macsecSaAttrKeyid  = 5
	macsecSaAttrSsci   = 8
	macsecSaAttrSalt   = 9

	macsecNumAN   = 4
	macsecSaltLen = 12
)

// MACsec cipher suite identifiers (IEEE 802.1AE), as reported in
// IFLA_MACSEC_CIPHER_SUITE.
const (
	macsecCipherGCMAES128    uint64 = 0x0080C20001000001
	macsecCipherGCMAES256    uint64 = 0x0080C20001000002
	macsecCipherGCMAESXPN128 uint64 = 0x0080C20001000003
	macsecCipherGCMAESXPN256 uint64 = 0x0080C20001000004
)

// Labels for values both peers derive from the shared key.
const (
	macsecANLabel   = "arnika macsec an"
	macsecSaltLabel = "arnika macsec xpn salt"
)

// Repository injects 256-bit keys into a MACsec interface via the
// kernel's macsec generic netlink family, with hitless SA rotation.
//
// The cipher suite is whatever the interface was created with, read from the
// kernel on every call: GCM-AES-256, or GCM-AES-XPN-256 with 64-bit packet
// numbers for high-speed links. The 128-bit suites are rejected because the key
// is 32 bytes.
//
// Coordinated QKD rotations choose AN = round modulo four, install RX before
// notifying the peer, and commit TX after the receiving keys are ready. The
// previous SA remains available for frames in flight. Numbered rounds keep AN
// selection consistent after restarts and lost acknowledgements.
//
// Standalone SetPSK callers use a key-derived AN that skips the current TX slot
// and a deferred switch; they require matching current slots on both peers.
type Repository struct {
	interfaceName string
	rxSCI         uint64
	switchDelay   time.Duration

	mu        sync.Mutex
	pending   *time.Timer // deferred encoding SA switch, nil if none
	pendingAN uint8
	stagedAN  *uint8               // installed for RX/TX, awaiting the peer's readiness
	switchSA  func(an uint8) error // replaced in tests
}

// macsecSwitchDelay is how long TX keeps using the previous SA after a new
// one is installed. It only needs to cover the time between the two peers'
// SetPSK calls, which is milliseconds, and stay well below the rotation
// interval.
const macsecSwitchDelay = time.Second

func NewRepository(interfaceName, rxSCI string) (*Repository, error) {
	if interfaceName == "" {
		return nil, errors.New("MACsec interface name must be set")
	}
	sciBytes, err := hex.DecodeString(rxSCI)
	if err != nil || len(sciBytes) != 8 {
		return nil, fmt.Errorf("MACsec RX SCI must be 16 hex characters (8 bytes), got %q", rxSCI)
	}
	r := &Repository{
		interfaceName: interfaceName,
		rxSCI:         binary.BigEndian.Uint64(sciBytes),
		switchDelay:   macsecSwitchDelay,
	}
	r.switchSA = r.setEncodingSA
	return r, nil
}

// InvalidateTunnel removes every TX and RX SA. Without a TX SA the interface
// drops outgoing frames, and without RX SAs it drops everything the peer
// sends, so both directions are cut at once. Installing a random key instead
// would leave the RX SAs of the current key in place and keep accepting the
// peer's frames.
func (r *Repository) InvalidateTunnel() (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending != nil {
		r.pending.Stop()
		r.pending = nil
	}
	r.stagedAN = nil
	s, closeSession, err := r.openSession()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeSession()) }()
	for an := uint8(0); an < macsecNumAN; an++ {
		if err := s.retireTxSA(an); err != nil {
			return fmt.Errorf("failed to remove TX SA %d on %s: %w", an, r.interfaceName, err)
		}
		if err := s.retireRxSA(an); err != nil {
			return fmt.Errorf("failed to remove RX SA %d on %s: %w", an, r.interfaceName, err)
		}
	}
	return nil
}

// SetPSK installs the key as a new SA pair and switches TX to it after
// switchDelay. It resolves the interface, its MACsec settings and the macsec
// family on every call, so a recreated interface or reloaded module is picked
// up without restarting.
func (r *Repository) SetPSK(key []byte) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.stagePSKLocked(key, nil); err != nil {
		return err
	}
	an := *r.stagedAN
	r.stagedAN = nil
	return r.scheduleSwitchLocked(an)
}

// StagePSK installs the receiving SA before the primary sends the key ID.
// CommitPSK can then activate TX as soon as the peer acknowledges its install.
func (r *Repository) StagePSK(key []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stagePSKLocked(key, nil)
}

// StagePSKForRound uses the authenticated shared round to choose the same AN
// even when a missed acknowledgement left the peers on different TX SAs.
func (r *Repository) StagePSKForRound(key []byte, round uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	an := uint8(round % macsecNumAN)
	return r.stagePSKLocked(key, &an)
}

func (r *Repository) CommitPSK() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stagedAN == nil {
		return errors.New("no MACsec key has been staged")
	}
	if err := r.switchSA(*r.stagedAN); err != nil {
		return err
	}
	r.stagedAN = nil
	return nil
}

func (r *Repository) stagePSKLocked(key []byte, roundAN *uint8) (err error) {
	if len(key) != 32 {
		return fmt.Errorf("PSK must be 32 bytes, got %d", len(key))
	}
	r.stagedAN = nil

	// Apply a switch still pending from the previous key first: until it
	// happens, TX encrypts with an SA this call is about to remove.
	if err := r.flushPendingLocked(); err != nil {
		return err
	}

	s, closeSession, err := r.openSession()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeSession()) }()

	sa, err := newMacsecSAParams(key, s.link, r.rxSCI)
	if err != nil {
		return fmt.Errorf("%s: %w", r.interfaceName, err)
	}
	defer sa.clear()

	current := s.link.encodingSA
	next := macsecChooseAN(key, current)
	if roundAN != nil {
		next = *roundAN
	}
	for an := uint8(0); an < macsecNumAN; an++ {
		if an == current && an != next {
			continue
		}
		if err := s.retireTxSA(an); err != nil {
			return fmt.Errorf("failed to remove TX SA %d on %s: %w", an, r.interfaceName, err)
		}
		if err := s.retireRxSA(an); err != nil {
			return fmt.Errorf("failed to remove RX SA %d on %s: %w", an, r.interfaceName, err)
		}
	}
	if err := s.ensureRxSC(); err != nil {
		return fmt.Errorf("failed to ensure RX SC: %w", err)
	}
	if err := s.addRxSA(next, sa); err != nil {
		return fmt.Errorf("failed to add RX SA %d on %s: %w", next, r.interfaceName, err)
	}
	if err := s.addTxSA(next, sa); err != nil {
		return fmt.Errorf("failed to add TX SA %d on %s: %w", next, r.interfaceName, err)
	}
	r.stagedAN = &next
	return nil
}

// openSession resolves the interface and its MACsec settings and opens a
// generic netlink connection to the macsec family.
func (r *Repository) openSession() (macsecSession, func() error, error) {
	iface, err := net.InterfaceByName(r.interfaceName)
	if err != nil {
		return macsecSession{}, nil, fmt.Errorf("interface %s not found: %w", r.interfaceName, err)
	}
	link, err := getMacsecLink(uint32(iface.Index))
	if err != nil {
		return macsecSession{}, nil, fmt.Errorf("failed to read MACsec settings of %s: %w", r.interfaceName, err)
	}
	c, err := genetlink.Dial(nil)
	if err != nil {
		return macsecSession{}, nil, fmt.Errorf("failed to open generic netlink: %w", err)
	}
	closeConn := func() error {
		if err := c.Close(); err != nil {
			return fmt.Errorf("failed to close generic netlink: %w", err)
		}
		return nil
	}
	family, err := c.GetFamily(macsecGenlName)
	if err != nil {
		return macsecSession{}, nil, errors.Join(fmt.Errorf("macsec netlink family not found: %w", err), closeConn())
	}
	return macsecSession{c: c, family: family, ifIndex: uint32(iface.Index), rxSCI: r.rxSCI, link: link}, closeConn, nil
}

// scheduleSwitchLocked switches TX to an after switchDelay.
func (r *Repository) scheduleSwitchLocked(an uint8) error {
	if r.switchDelay <= 0 {
		return r.switchSA(an)
	}
	r.pendingAN = an
	var t *time.Timer
	t = time.AfterFunc(r.switchDelay, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.pending != t {
			return // flushed, superseded or invalidated
		}
		r.pending = nil
		if err := r.switchSA(an); err != nil {
			slog.Error("deferred MACsec encoding SA switch failed", "an", an, "iface", r.interfaceName, "err", err)
		}
	})
	r.pending = t
	return nil
}

// flushPendingLocked applies a deferred encoding SA switch immediately.
func (r *Repository) flushPendingLocked() error {
	if r.pending == nil {
		return nil
	}
	r.pending.Stop()
	r.pending = nil
	return r.switchSA(r.pendingAN)
}

func (r *Repository) setEncodingSA(an uint8) error {
	iface, err := net.InterfaceByName(r.interfaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", r.interfaceName, err)
	}
	if err := setMacsecEncodingSA(uint32(iface.Index), an); err != nil {
		return fmt.Errorf("failed to set encoding SA to %d on %s: %w", an, r.interfaceName, err)
	}
	return nil
}

// macsecChooseAN picks the AN for a new key. It depends only on the key and
// the AN currently used for TX, which both peers share while they are in sync,
// so both put the same key under the same AN. The current AN is skipped
// because its SA must stay installed for frames still in flight.
func macsecChooseAN(key []byte, current uint8) uint8 {
	h := sha256.New()
	h.Write([]byte(macsecANLabel))
	h.Write(key)
	an := h.Sum(nil)[0] % macsecNumAN
	if an == current {
		an = (an + 1) % macsecNumAN
	}
	return an
}

// macsecLink is the part of a MACsec interface's configuration the adapter
// needs, read with RTM_GETLINK.
type macsecLink struct {
	sci        uint64 // own SCI
	cipher     uint64
	encodingSA uint8
}

// macsecSAParams is everything that goes into one SA pair for a key.
type macsecSAParams struct {
	key, keyID []byte
	xpn        bool
	txSSCI     uint32 // own short SCI (XPN only)
	rxSSCI     uint32 // the peer's short SCI (XPN only)
	salt       []byte // XPN only
}

func newMacsecSAParams(key []byte, link macsecLink, rxSCI uint64) (*macsecSAParams, error) {
	p := &macsecSAParams{key: key}
	switch link.cipher {
	case macsecCipherGCMAES256:
	case macsecCipherGCMAESXPN256:
		p.xpn = true
	case macsecCipherGCMAES128, macsecCipherGCMAESXPN128:
		return nil, fmt.Errorf("MACsec cipher suite %#x uses 128-bit keys, but Arnika installs 256-bit keys: create the interface with cipher gcm-aes-256 or gcm-aes-xpn-256", link.cipher)
	default:
		return nil, fmt.Errorf("unsupported MACsec cipher suite %#x", link.cipher)
	}

	// The key ID only has to be unique per SA; derive it from the key so both
	// peers agree on it without exchanging anything.
	keyIDFull := sha256.Sum256(key)
	p.keyID = keyIDFull[:16]

	if p.xpn {
		// Both peers must use the same salt and agree on who is which SSCI.
		// The salt is not secret (MKA derives it from public values); here it
		// comes from the key so no extra exchange is needed. SSCIs follow
		// MKA's rule: numbered from 1 in ascending SCI order.
		if link.sci == rxSCI {
			return nil, fmt.Errorf("own SCI and MACSEC_RX_SCI are both %016x", rxSCI)
		}
		p.txSSCI, p.rxSSCI = 1, 2
		if link.sci > rxSCI {
			p.txSSCI, p.rxSSCI = 2, 1
		}
		h := sha256.New()
		h.Write([]byte(macsecSaltLabel))
		h.Write(key)
		p.salt = h.Sum(nil)[:macsecSaltLen]
	}
	return p, nil
}

func (p *macsecSAParams) clear() {
	clear(p.salt)
}

// macsecSession bundles the per-call netlink state for SA management.
type macsecSession struct {
	c       *genetlink.Conn
	family  genetlink.Family
	ifIndex uint32
	rxSCI   uint64
	link    macsecLink
}

func (s macsecSession) addTxSA(an uint8, p *macsecSAParams) error {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(macsecAttrIfindex, s.ifIndex)
	ae.Nested(macsecAttrSaConfig, encodeMacsecSAConfig(an, p, p.txSSCI))
	return s.execute(macsecCmdAddTxsa, ae)
}

func (s macsecSession) addRxSA(an uint8, p *macsecSAParams) error {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(macsecAttrIfindex, s.ifIndex)
	ae.Nested(macsecAttrSaConfig, encodeMacsecSAConfig(an, p, p.rxSSCI))
	ae.Nested(macsecAttrRxscConfig, s.encodeRxSCI(false))
	return s.execute(macsecCmdAddRxsa, ae)
}

// retireTxSA deactivates and then deletes a TX SA; the kernel refuses to
// delete an active SA with EBUSY. An SA that is already gone (ENODEV) is fine.
func (s macsecSession) retireTxSA(an uint8) error {
	return ignoreENODEV(s.txSA(macsecCmdUpdTxsa, an), s.txSA(macsecCmdDelTxsa, an))
}

// retireRxSA is the RX counterpart of retireTxSA.
func (s macsecSession) retireRxSA(an uint8) error {
	return ignoreENODEV(s.rxSA(macsecCmdUpdRxsa, an), s.rxSA(macsecCmdDelRxsa, an))
}

// txSA sends an UPD (deactivate) or DEL command for the TX SA with the given AN.
func (s macsecSession) txSA(command uint8, an uint8) func() error {
	return func() error {
		ae := netlink.NewAttributeEncoder()
		ae.Uint32(macsecAttrIfindex, s.ifIndex)
		ae.Nested(macsecAttrSaConfig, encodeMacsecAN(an, command == macsecCmdUpdTxsa))
		return s.execute(command, ae)
	}
}

// rxSA sends an UPD (deactivate) or DEL command for the RX SA with the given AN.
func (s macsecSession) rxSA(command uint8, an uint8) func() error {
	return func() error {
		ae := netlink.NewAttributeEncoder()
		ae.Uint32(macsecAttrIfindex, s.ifIndex)
		ae.Nested(macsecAttrSaConfig, encodeMacsecAN(an, command == macsecCmdUpdRxsa))
		ae.Nested(macsecAttrRxscConfig, s.encodeRxSCI(false))
		return s.execute(command, ae)
	}
}

// ignoreENODEV runs the steps in order and treats a missing SA as success.
func ignoreENODEV(steps ...func() error) error {
	for _, step := range steps {
		if err := step(); err != nil {
			if errors.Is(err, unix.ENODEV) {
				return nil
			}
			return err
		}
	}
	return nil
}

// ensureRxSC creates the RX secure channel for the peer on first use.
func (s macsecSession) ensureRxSC() error {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(macsecAttrIfindex, s.ifIndex)
	ae.Nested(macsecAttrRxscConfig, s.encodeRxSCI(true))
	err := s.execute(macsecCmdAddRxsc, ae)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

func (s macsecSession) encodeRxSCI(active bool) func(*netlink.AttributeEncoder) error {
	return func(nae *netlink.AttributeEncoder) error {
		// sci_t is kept in network byte order by the kernel (iproute2 sends
		// htonll(sci)), so it must not go through the native-endian Uint64.
		nae.Bytes(macsecRxscAttrSci, binary.BigEndian.AppendUint64(nil, s.rxSCI))
		if active {
			nae.Uint8(macsecRxscAttrActive, 1)
		}
		return nil
	}
}

func (s macsecSession) execute(command uint8, ae *netlink.AttributeEncoder) error {
	attrs, err := ae.Encode()
	defer clear(attrs)
	if err != nil {
		return err
	}
	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: command,
			Version: macsecGenlVersion,
		},
		Data: attrs,
	}
	_, err = s.c.Execute(msg, s.family.ID, netlink.Request|netlink.Acknowledge)
	return err
}

// encodeMacsecSAConfig builds the SA attributes. The kernel checks the PN
// length against the cipher suite (4 bytes, or 8 with XPN) and requires SSCI
// and salt for XPN SAs.
func encodeMacsecSAConfig(an uint8, p *macsecSAParams, ssci uint32) func(*netlink.AttributeEncoder) error {
	return func(nae *netlink.AttributeEncoder) error {
		nae.Uint8(macsecSaAttrAn, an)
		if p.xpn {
			nae.Uint64(macsecSaAttrPn, 1)
			// ssci_t is big-endian in the kernel, like sci_t.
			nae.Bytes(macsecSaAttrSsci, binary.BigEndian.AppendUint32(nil, ssci))
			nae.Bytes(macsecSaAttrSalt, p.salt)
		} else {
			nae.Uint32(macsecSaAttrPn, 1)
		}
		nae.Bytes(macsecSaAttrKey, p.key)
		nae.Bytes(macsecSaAttrKeyid, p.keyID)
		nae.Uint8(macsecSaAttrActive, 1)
		return nil
	}
}

// encodeMacsecAN selects an SA by AN; with deactivate it also sets ACTIVE=0.
func encodeMacsecAN(an uint8, deactivate bool) func(*netlink.AttributeEncoder) error {
	return func(nae *netlink.AttributeEncoder) error {
		nae.Uint8(macsecSaAttrAn, an)
		if deactivate {
			nae.Uint8(macsecSaAttrActive, 0)
		}
		return nil
	}
}

// getMacsecLink reads the SCI, cipher suite and encoding SA of a MACsec
// interface with RTM_GETLINK.
func getMacsecLink(ifIndex uint32) (macsecLink, error) {
	rc, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return macsecLink{}, err
	}
	defer func() { _ = rc.Close() }()

	ifinfo := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(ifinfo[4:8], ifIndex)
	msgs, err := rc.Execute(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_GETLINK, Flags: netlink.Request},
		Data:   ifinfo,
	})
	if err != nil {
		return macsecLink{}, err
	}
	if len(msgs) != 1 || len(msgs[0].Data) < unix.SizeofIfInfomsg {
		return macsecLink{}, fmt.Errorf("unexpected RTM_GETLINK reply")
	}
	return parseMacsecLink(msgs[0].Data[unix.SizeofIfInfomsg:])
}

// parseMacsecLink extracts the MACsec settings from the attributes of an
// RTM_NEWLINK message (after the ifinfomsg header).
func parseMacsecLink(attrs []byte) (macsecLink, error) {
	var l macsecLink
	var kind string
	var sawSCI, sawCipher bool
	ad, err := netlink.NewAttributeDecoder(attrs)
	if err != nil {
		return l, err
	}
	for ad.Next() {
		if ad.Type() != unix.IFLA_LINKINFO {
			continue
		}
		ad.Nested(func(nad *netlink.AttributeDecoder) error {
			for nad.Next() {
				switch nad.Type() {
				case unix.IFLA_INFO_KIND:
					kind = nad.String()
				case unix.IFLA_INFO_DATA:
					nad.Nested(func(dad *netlink.AttributeDecoder) error {
						for dad.Next() {
							switch dad.Type() {
							case unix.IFLA_MACSEC_SCI:
								if b := dad.Bytes(); len(b) == 8 {
									l.sci = binary.BigEndian.Uint64(b)
									sawSCI = true
								}
							case unix.IFLA_MACSEC_CIPHER_SUITE:
								l.cipher = dad.Uint64()
								sawCipher = true
							case unix.IFLA_MACSEC_ENCODING_SA:
								l.encodingSA = dad.Uint8()
							}
						}
						return nil
					})
				}
			}
			return nil
		})
	}
	if err := ad.Err(); err != nil {
		return l, err
	}
	if kind != "macsec" {
		return l, fmt.Errorf("interface is of kind %q, not macsec", kind)
	}
	if !sawSCI || !sawCipher {
		return l, errors.New("kernel did not report the MACsec SCI and cipher suite")
	}
	return l, nil
}

// setMacsecEncodingSA switches the active TX SA via rtnetlink.
func setMacsecEncodingSA(ifIndex uint32, an uint8) error {
	msg, err := macsecEncodingSAMessage(ifIndex, an)
	if err != nil {
		return err
	}
	rc, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	_, err = rc.Execute(msg)
	return err
}

// macsecEncodingSAMessage builds the request that changes the encoding SA.
// It must be RTM_NEWLINK on the existing device (as `ip link set ... type
// macsec encodingsa N` sends): RTM_SETLINK never passes IFLA_INFO_DATA to the
// driver's changelink and silently succeeds without changing anything.
func macsecEncodingSAMessage(ifIndex uint32, an uint8) (netlink.Message, error) {
	ae := netlink.NewAttributeEncoder()
	ae.Nested(unix.IFLA_LINKINFO, func(nae *netlink.AttributeEncoder) error {
		nae.String(unix.IFLA_INFO_KIND, "macsec")
		nae.Nested(unix.IFLA_INFO_DATA, func(nnae *netlink.AttributeEncoder) error {
			nnae.Uint8(unix.IFLA_MACSEC_ENCODING_SA, an)
			return nil
		})
		return nil
	})
	attrBytes, err := ae.Encode()
	if err != nil {
		return netlink.Message{}, err
	}

	ifinfo := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(ifinfo[4:8], ifIndex)

	return netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_NEWLINK,
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: append(ifinfo, attrBytes...),
	}, nil
}
