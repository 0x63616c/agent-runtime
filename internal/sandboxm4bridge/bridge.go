// Package sandboxm4bridge is the private M3-to-M4 authority seam. It turns a
// current, signed host assignment into the one narrowly scoped Firecracker
// boot-probe capability; it never interprets a dispatch body or starts a VM.
package sandboxm4bridge

import (
	"crypto/ed25519"
	"time"

	"github.com/0x63616c/agent-runtime/internal/firecrackerlaunchgrant"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/0x63616c/agent-runtime/sandbox"
	"github.com/cockroachdb/errors"
)

// Capability is the immutable M3-verified authority M4 may consume for one
// fixed-purpose boot probe. Its grant is a copy, so callers cannot mutate this
// capability after successful M3 verification.
type Capability struct {
	grant firecrackerlaunchgrant.Grant
}

// Grant returns the validated, fixed-purpose M4 boot-probe grant.
func (capability Capability) Grant() firecrackerlaunchgrant.Grant {
	return capability.grant
}

// NewBootProbeCapability verifies the signed control envelope against the
// current host trust, exact host identity, current revocation epoch, and the
// host observation key enrolled into the assignment before creating M4 input.
func NewBootProbeCapability(wire []byte, hostID string, hostGeneration uint64, trust sandboxhostprotocol.TrustBundle, observationPrivateKey ed25519.PrivateKey, now time.Time, identity firecrackerlaunchgrant.TrustedM4Identity) (Capability, error) {
	if len(observationPrivateKey) != ed25519.PrivateKeySize {
		return Capability{}, errors.New("create M3/M4 boot-probe capability: host observation signing key is invalid")
	}
	envelope, err := sandboxhostprotocol.VerifyEnvelopeWithTrust(wire, hostID, hostGeneration, now, trust)
	if err != nil {
		return Capability{}, errors.New("create M3/M4 boot-probe capability: signed current host assignment is refused")
	}
	if envelope.HostObservationKeyDigest == "" || envelope.HostObservationKeyDigest != sandboxhostprotocol.Digest(observationPrivateKey.Public().(ed25519.PublicKey)) {
		return Capability{}, errors.New("create M3/M4 boot-probe capability: enrolled host observation key is refused")
	}
	grant, err := firecrackerlaunchgrant.New(firecrackerlaunchgrant.EnvelopeTuple{
		EnvelopeID:             envelope.EnvelopeID,
		DeliveryID:             envelope.DeliveryID,
		Nonce:                  envelope.Nonce,
		IssuedAt:               envelope.IssuedAt,
		ExpiresAt:              envelope.ExpiresAt,
		HostID:                 envelope.HostID,
		HostGeneration:         envelope.HostGeneration,
		AssignmentID:           envelope.AssignmentID,
		LeaseEpoch:             envelope.LeaseEpoch,
		FencingToken:           envelope.FencingToken,
		Tenant:                 envelope.Tenant,
		Principal:              envelope.Principal,
		SandboxID:              envelope.SandboxID,
		OperationID:            envelope.OperationID,
		OperationKind:          envelope.OperationKind,
		EffectiveSpecDigest:    sandbox.Digest(envelope.EffectiveSpecDigest),
		CapabilityDigest:       sandbox.Digest(envelope.CapabilityDigest),
		CanonicalRequestDigest: sandbox.Digest(envelope.CanonicalRequestDigest),
	}, identity)
	if err != nil {
		return Capability{}, errors.Wrap(err, "create M3/M4 boot-probe capability")
	}
	return Capability{grant: grant}, nil
}
