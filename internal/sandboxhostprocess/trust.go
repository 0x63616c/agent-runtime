package sandboxhostprocess

import (
	"crypto/ed25519"
	"encoding/base64"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/cockroachdb/errors"
)

// LoadControlTrust resolves public verification keys from named secret
// references and constructs one immutable initial trust snapshot.
func LoadControlTrust(config controlTrustConfig, lookup SecretLookup) (*sandboxhostprotocol.AtomicTrust, error) {
	bundle, err := resolveControlTrust(config, lookup)
	if err != nil {
		return nil, err
	}
	trust, err := sandboxhostprotocol.NewAtomicTrust(bundle)
	if err != nil {
		return nil, errors.Wrap(err, "load sandbox host control trust")
	}
	return trust, nil
}

// ReloadControlTrust atomically applies a strictly newer current/next trust
// snapshot. A failed reload leaves the prior complete snapshot active.
func ReloadControlTrust(trust *sandboxhostprotocol.AtomicTrust, config controlTrustConfig, lookup SecretLookup) error {
	if trust == nil {
		return errors.New("reload sandbox host control trust: current trust is required")
	}
	bundle, err := resolveControlTrust(config, lookup)
	if err != nil {
		return err
	}
	return errors.Wrap(trust.Update(bundle), "reload sandbox host control trust")
}

func resolveControlTrust(config controlTrustConfig, lookup SecretLookup) (sandboxhostprotocol.TrustBundle, error) {
	if lookup == nil {
		return sandboxhostprotocol.TrustBundle{}, errors.New("resolve sandbox host control trust: secret lookup is required")
	}
	current, err := resolveControlTrustKey(config.current, lookup)
	if err != nil {
		return sandboxhostprotocol.TrustBundle{}, err
	}
	bundle := sandboxhostprotocol.TrustBundle{Version: config.version, RevocationEpoch: config.revocationEpoch, Current: current}
	if config.next != nil {
		next, nextErr := resolveControlTrustKey(*config.next, lookup)
		if nextErr != nil {
			return sandboxhostprotocol.TrustBundle{}, nextErr
		}
		bundle.Next = &next
	}
	return bundle, nil
}

func resolveControlTrustKey(config controlTrustKeyConfig, lookup SecretLookup) (sandboxhostprotocol.SigningKey, error) {
	encoded, ok := lookup(config.publicKeyEnvironment)
	if !ok || encoded == "" {
		return sandboxhostprotocol.SigningKey{}, errors.Newf("resolve sandbox host control trust: required secret environment %s is missing", config.publicKeyEnvironment)
	}
	publicKey, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return sandboxhostprotocol.SigningKey{}, errors.New("resolve sandbox host control trust: public key is invalid")
	}
	return sandboxhostprotocol.SigningKey{ID: config.id, Version: config.version, PublicKey: ed25519.PublicKey(publicKey), NotBefore: config.notBefore, NotAfter: config.notAfter}, nil
}
