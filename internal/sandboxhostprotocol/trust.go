package sandboxhostprotocol

import (
	"bytes"
	"crypto/ed25519"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
)

// SigningKey is one versioned public control-signing authority. The private
// counterpart remains outside the trust bundle.
type SigningKey struct {
	ID        string
	Version   uint64
	PublicKey ed25519.PublicKey
	NotBefore time.Time
	NotAfter  time.Time
}

// TrustBundle is an atomically applied current/next control-key snapshot.
// RevocationEpoch invalidates envelopes issued under an earlier epoch.
type TrustBundle struct {
	Version         uint64
	RevocationEpoch uint64
	Current         SigningKey
	Next            *SigningKey
}

// AtomicTrust owns one replace-only control trust snapshot.
type AtomicTrust struct {
	mu                sync.RWMutex
	bundle            TrustBundle
	knownKeys         map[string]SigningKey
	retiredKeyIDs     map[string]struct{}
	maximumKeyVersion uint64
}

// NewAtomicTrust validates and retains an initial control trust snapshot.
func NewAtomicTrust(bundle TrustBundle) (*AtomicTrust, error) {
	if !validTrustBundle(bundle) {
		return nil, errors.New("create host control trust: invalid versioned key bundle")
	}
	knownKeys := make(map[string]SigningKey, 2)
	for _, key := range trustKeys(bundle) {
		knownKeys[key.ID] = copySigningKey(key)
	}
	return &AtomicTrust{bundle: copyTrustBundle(bundle), knownKeys: knownKeys, retiredKeyIDs: make(map[string]struct{}), maximumKeyVersion: maximumTrustKeyVersion(bundle)}, nil
}

// Snapshot returns one immutable copy of the current trust snapshot.
func (trust *AtomicTrust) Snapshot() TrustBundle {
	trust.mu.RLock()
	defer trust.mu.RUnlock()
	return copyTrustBundle(trust.bundle)
}

// Update atomically replaces trust with a strictly newer, non-regressing
// revocation epoch. A key ID is immutable for its lifetime; once it leaves a
// snapshot it is retired permanently, and a newly introduced key must have a
// key version greater than every previously observed key. Readers observe
// either complete snapshot, never a mix.
func (trust *AtomicTrust) Update(bundle TrustBundle) error {
	if !validTrustBundle(bundle) {
		return errors.New("update host control trust: invalid versioned key bundle")
	}
	trust.mu.Lock()
	defer trust.mu.Unlock()
	if bundle.Version <= trust.bundle.Version || bundle.RevocationEpoch < trust.bundle.RevocationEpoch {
		return errors.New("update host control trust: version or revocation epoch regressed")
	}
	for _, key := range trustKeys(bundle) {
		known, knownBefore := trust.knownKeys[key.ID]
		if _, retired := trust.retiredKeyIDs[key.ID]; retired {
			return errors.New("update host control trust: retired key cannot be reintroduced")
		}
		if knownBefore {
			if !sameSigningKey(known, key) {
				return errors.New("update host control trust: key identity mutation is forbidden")
			}
			continue
		}
		if key.Version <= trust.maximumKeyVersion {
			return errors.New("update host control trust: newly introduced key version regressed")
		}
	}
	for _, key := range trustKeys(trust.bundle) {
		if !containsTrustKey(bundle, key.ID) {
			trust.retiredKeyIDs[key.ID] = struct{}{}
		}
	}
	for _, key := range trustKeys(bundle) {
		if _, known := trust.knownKeys[key.ID]; !known {
			trust.knownKeys[key.ID] = copySigningKey(key)
		}
		if key.Version > trust.maximumKeyVersion {
			trust.maximumKeyVersion = key.Version
		}
	}
	trust.bundle = copyTrustBundle(bundle)
	return nil
}

// SignEnvelopeWithTrust binds a delivery to the current key version and
// revocation epoch of a validated trust snapshot.
func SignEnvelopeWithTrust(envelope Envelope, trust TrustBundle, privateKey ed25519.PrivateKey) ([]byte, error) {
	if !validTrustBundle(trust) || len(privateKey) != ed25519.PrivateKeySize || !bytes.Equal(privateKey.Public().(ed25519.PublicKey), trust.Current.PublicKey) || !keyCoversEnvelope(trust.Current, envelope) {
		return nil, errors.New("sign host envelope with trust: current key is invalid or outside validity")
	}
	envelope.ControlKeyID = trust.Current.ID
	envelope.ControlKeyVersion = trust.Current.Version
	envelope.ControlRevocationEpoch = trust.RevocationEpoch
	return SignEnvelope(envelope, trust.Current.ID, privateKey)
}

// VerifyEnvelopeWithTrust verifies an envelope only against the complete
// current/next snapshot and refuses keys, validity, or revocation epochs that
// are no longer trusted.
func VerifyEnvelopeWithTrust(wire []byte, hostID string, generation uint64, now time.Time, trust TrustBundle) (Envelope, error) {
	if !validTrustBundle(trust) {
		return Envelope{}, errors.New("verify host envelope with trust: invalid trust snapshot")
	}
	keys := map[string]ed25519.PublicKey{trust.Current.ID: trust.Current.PublicKey}
	if trust.Next != nil {
		keys[trust.Next.ID] = trust.Next.PublicKey
	}
	envelope, err := VerifyEnvelope(wire, hostID, generation, now, keys)
	if err != nil || envelope.ControlKeyVersion == 0 || envelope.ControlRevocationEpoch != trust.RevocationEpoch {
		return Envelope{}, errors.New("verify host envelope with trust: refused")
	}
	key, ok := trustedKey(trust, envelope.ControlKeyID, envelope.ControlKeyVersion)
	if !ok || !keyCoversEnvelope(key, envelope) {
		return Envelope{}, errors.New("verify host envelope with trust: refused")
	}
	return envelope, nil
}

func trustedKey(trust TrustBundle, id string, version uint64) (SigningKey, bool) {
	if trust.Current.ID == id && trust.Current.Version == version {
		return trust.Current, true
	}
	if trust.Next != nil && trust.Next.ID == id && trust.Next.Version == version {
		return *trust.Next, true
	}
	return SigningKey{}, false
}

func keyCoversEnvelope(key SigningKey, envelope Envelope) bool {
	return !envelope.IssuedAt.Before(key.NotBefore) && !envelope.ExpiresAt.After(key.NotAfter)
}

func validTrustBundle(bundle TrustBundle) bool {
	if bundle.Version == 0 || bundle.RevocationEpoch == 0 || !validSigningKey(bundle.Current) {
		return false
	}
	return bundle.Next == nil || (validSigningKey(*bundle.Next) && bundle.Current.ID != bundle.Next.ID)
}

func validSigningKey(key SigningKey) bool {
	return boundedID(key.ID, 128) && key.Version > 0 && len(key.PublicKey) == ed25519.PublicKeySize && !key.NotBefore.IsZero() && !key.NotAfter.IsZero() && key.NotBefore.Location() == time.UTC && key.NotAfter.Location() == time.UTC && key.NotAfter.After(key.NotBefore)
}

func copyTrustBundle(bundle TrustBundle) TrustBundle {
	bundle.Current = copySigningKey(bundle.Current)
	if bundle.Next != nil {
		next := copySigningKey(*bundle.Next)
		bundle.Next = &next
	}
	return bundle
}

func trustKeys(bundle TrustBundle) []SigningKey {
	keys := []SigningKey{bundle.Current}
	if bundle.Next != nil {
		keys = append(keys, *bundle.Next)
	}
	return keys
}

func maximumTrustKeyVersion(bundle TrustBundle) uint64 {
	maximum := bundle.Current.Version
	if bundle.Next != nil && bundle.Next.Version > maximum {
		maximum = bundle.Next.Version
	}
	return maximum
}

func containsTrustKey(bundle TrustBundle, id string) bool {
	return bundle.Current.ID == id || (bundle.Next != nil && bundle.Next.ID == id)
}

func sameSigningKey(left, right SigningKey) bool {
	return left.ID == right.ID && left.Version == right.Version && bytes.Equal(left.PublicKey, right.PublicKey) && left.NotBefore.Equal(right.NotBefore) && left.NotAfter.Equal(right.NotAfter)
}

func copySigningKey(key SigningKey) SigningKey {
	key.PublicKey = append(ed25519.PublicKey(nil), key.PublicKey...)
	return key
}
