package sandboxcontrol

import (
	"context"

	"github.com/cockroachdb/errors"
)

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

// AttestationEvidence is the bounded metadata supplied to a verifier. It
// contains references only and never an attestation statement or secret.
type AttestationEvidence struct {
	HostID            string
	Generation        uint64
	CertificateDigest string
	CapabilityDigest  string
	AttestationDigest string
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
func VerifyHostAttestation(ctx context.Context, profile AttestationProfile, host HostEnrollment, verifier AttestationVerifier) HostAttestation {
	if profile == AttestationProfileLocalMetadata {
		return HostAttestation{Profile: profile, State: AttestationMetadataOnly}
	}
	evidence := AttestationEvidence{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest, CapabilityDigest: host.CapabilityDigest, AttestationDigest: host.AttestationDigest}
	if profile != AttestationProfileVerified || verifier == nil || ctx.Err() != nil || !validAttestationEvidence(evidence) || verifier.VerifyHostAttestation(ctx, evidence) != nil {
		return HostAttestation{Profile: profile, State: AttestationFailed}
	}
	return HostAttestation{Profile: profile, State: AttestationVerified}
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
}

func normalizeHostEnrollment(host HostEnrollment) HostEnrollment {
	if host.AttestationProfile == "" && host.AttestationState == "" {
		host.AttestationProfile = AttestationProfileLocalMetadata
		host.AttestationState = AttestationMetadataOnly
	}
	return host
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
	return validBounded(evidence.HostID, maxHostIDBytes) && evidence.Generation > 0 && validBounded(evidence.CertificateDigest, maxDigestBytes) && validBounded(evidence.CapabilityDigest, maxDigestBytes) && validBounded(evidence.AttestationDigest, maxDigestBytes)
}
