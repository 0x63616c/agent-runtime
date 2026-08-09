package sandboxcontrol

import (
	"context"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/cockroachdb/errors"
)

const maxAttestationEvidenceBytes = 64 << 10

// AttestationInput is raw, bounded enrollment evidence plus its explicit
// assurance profile. Evidence is verified transiently and never persisted.
type AttestationInput struct {
	Profile  AttestationProfile
	Evidence []byte
}

// AttestationProfile identifies the evidence assurance a host enrollment
// presents. Metadata-only local evidence is explicitly not a hardware or
// runtime integrity attestation.
type AttestationProfile string

const (
	// AttestationProfileLocalMetadata records only operator-supplied metadata
	// for the unsafe local development profile.
	AttestationProfileLocalMetadata AttestationProfile = "local-metadata-v1"
	// AttestationProfileVerified requires the configured predicate to accept
	// bounded evidence before a production-capable host is admitted.
	AttestationProfileVerified AttestationProfile = "verified-v1"
)

// AttestationState is the durable outcome of evaluating a host profile.
type AttestationState string

const (
	// AttestationMetadataOnly makes the deliberately limited local profile
	// visible rather than representing it as verification.
	AttestationMetadataOnly AttestationState = "metadata-only"
	// AttestationVerified records an explicit successful verifier predicate.
	AttestationVerified AttestationState = "verified"
	// AttestationFailed records an explicit failed or unavailable predicate.
	AttestationFailed AttestationState = "failed"
)

// AttestationEvidence is the bounded immutable input supplied transiently to
// a verifier. Only its digest and outcome may be persisted.
type AttestationEvidence struct {
	HostID            string
	Generation        uint64
	CertificateDigest string
	CapabilityDigest  string
	AttestationDigest string
	Evidence          []byte
}

// AttestationVerifier evaluates the selected profile's evidence predicate.
type AttestationVerifier interface {
	VerifyHostAttestation(context.Context, AttestationEvidence) error
}

// AttestationVerifierFunc adapts a function into an AttestationVerifier.
type AttestationVerifierFunc func(context.Context, AttestationEvidence) error

// VerifyHostAttestation calls the explicit profile predicate and returns a
// safe durable state. Verification failure is recorded as state, not exposed
// as unbounded verifier detail.
func VerifyHostAttestation(ctx context.Context, input AttestationInput, host HostEnrollment, verifier AttestationVerifier) HostAttestation {
	if input.Profile == AttestationProfileLocalMetadata && len(input.Evidence) == 0 {
		return HostAttestation{Profile: input.Profile, State: AttestationMetadataOnly}
	}
	raw := append([]byte(nil), input.Evidence...)
	digest := sandboxhostprotocol.Digest(raw)
	evidence := AttestationEvidence{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest, CapabilityDigest: host.CapabilityDigest, AttestationDigest: digest, Evidence: raw}
	if input.Profile != AttestationProfileVerified || verifier == nil || ctx.Err() != nil || !validAttestationEvidence(evidence) || verifier.VerifyHostAttestation(ctx, evidence) != nil {
		return HostAttestation{Profile: input.Profile, State: AttestationFailed, Digest: digest}
	}
	return HostAttestation{Profile: input.Profile, State: AttestationVerified, Digest: digest}
}

// VerifyHostAttestation implements AttestationVerifier.
func (verifier AttestationVerifierFunc) VerifyHostAttestation(ctx context.Context, evidence AttestationEvidence) error {
	if verifier == nil {
		return errors.New("verify host attestation: verifier is required")
	}
	return verifier(ctx, evidence)
}

// HostAttestation is the profile/state pair persisted with a host enrollment.
type HostAttestation struct {
	Profile AttestationProfile
	State   AttestationState
	Digest  string
}

func evaluateHostEnrollment(ctx context.Context, host HostEnrollment, input AttestationInput, verifier AttestationVerifier) (HostEnrollment, error) {
	if host.Status != HostActive || host.AttestationProfile != "" || host.AttestationState != "" || host.AttestationDigest != "" {
		return HostEnrollment{}, errors.New("provision sandbox host: caller-supplied attestation outcome is forbidden")
	}
	if len(input.Evidence) > maxAttestationEvidenceBytes {
		return HostEnrollment{}, errors.New("provision sandbox host: attestation evidence exceeds bounded input")
	}
	attestation := VerifyHostAttestation(ctx, input, host, verifier)
	host.AttestationProfile, host.AttestationState, host.AttestationDigest = attestation.Profile, attestation.State, attestation.Digest
	if attestation.State == AttestationFailed {
		host.Status = HostAttestationFailed
	}
	return host, nil
}

func validHostAttestation(host HostEnrollment) bool {
	switch host.Status {
	case HostActive:
		return (host.AttestationProfile == AttestationProfileLocalMetadata && host.AttestationState == AttestationMetadataOnly) || (host.AttestationProfile == AttestationProfileVerified && host.AttestationState == AttestationVerified && validBounded(host.AttestationDigest, maxDigestBytes))
	case HostAttestationFailed:
		return host.AttestationProfile == AttestationProfileVerified && host.AttestationState == AttestationFailed
	default:
		return false
	}
}

func validAttestationEvidence(evidence AttestationEvidence) bool {
	return validBounded(evidence.HostID, maxHostIDBytes) && evidence.Generation > 0 && validBounded(evidence.CertificateDigest, maxDigestBytes) && validBounded(evidence.CapabilityDigest, maxDigestBytes) && validBounded(evidence.AttestationDigest, maxDigestBytes) && len(evidence.Evidence) > 0 && len(evidence.Evidence) <= maxAttestationEvidenceBytes
}
