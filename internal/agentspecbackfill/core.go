// Package agentspecbackfill owns the pure immutable request, verification, and archive seam for Agent-spec backfill.
package agentspecbackfill

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
)

const (
	maxRequestBytes = 1024
	maxStatusBytes  = 2048
	requestVersion  = 1
	maximumCount    = uint64(^uint64(0) >> 1)
)

var (
	// ErrStaleSnapshot reports a request whose frozen legacy snapshot no longer matches.
	ErrStaleSnapshot = errors.New("agent spec backfill stale snapshot")
	// ErrWrongOwner reports a legacy revision outside the verified owner boundary.
	ErrWrongOwner = errors.New("agent spec backfill wrong owner")
	// ErrContentIntegrity reports immutable content that does not verify against its reference.
	ErrContentIntegrity = errors.New("agent spec backfill immutable content integrity")
	// ErrExpiredRequest reports a request outside its immutable admission window.
	ErrExpiredRequest = errors.New("agent spec backfill request expired")
	// ErrFutureRequest reports a request before its immutable creation time.
	ErrFutureRequest = errors.New("agent spec backfill request is not yet admitted")
)

// Request is the immutable, bounded controller request with no raw Agent specification or object key.
type Request struct {
	StackDigest              string
	MigrationVersion         uint32
	MigrationArtifactDigest  string
	ManifestDigest           string
	ControllerImageDigest    string
	SnapshotFingerprint      string
	SnapshotCount            uint64
	FenceNonce               string
	StaticReadinessDigest    string
	DatabaseAuthorityDigest  string
	BlobReadCapabilityDigest string
	CreatedAt                time.Time
	ExpiresAt                time.Time
}

// Digest returns the canonical request digest.
func (request Request) Digest() (string, error) {
	encoded, err := request.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Name returns the deterministic Kubernetes-safe request capability name.
func (request Request) Name() (string, error) {
	digest, err := request.Digest()
	if err != nil {
		return "", err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	if err != nil {
		return "", errors.Wrap(err, "decode request digest")
	}
	return "asb-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)), nil
}

// Canonical returns the deterministic CBOR request envelope.
func (request Request) Canonical() ([]byte, error) {
	if err := request.validate(); err != nil {
		return nil, err
	}
	var value bytes.Buffer
	writeHead(&value, 4, 14)
	writeUint(&value, requestVersion)
	writeText(&value, request.StackDigest)
	writeUint(&value, uint64(request.MigrationVersion))
	writeText(&value, request.MigrationArtifactDigest)
	writeText(&value, request.ManifestDigest)
	writeText(&value, request.ControllerImageDigest)
	writeText(&value, request.SnapshotFingerprint)
	writeUint(&value, request.SnapshotCount)
	nonce, _ := base64.RawURLEncoding.Strict().DecodeString(request.FenceNonce)
	writeBytes(&value, nonce)
	writeText(&value, request.StaticReadinessDigest)
	writeText(&value, request.DatabaseAuthorityDigest)
	writeText(&value, request.BlobReadCapabilityDigest)
	writeText(&value, request.CreatedAt.UTC().Format(time.RFC3339Nano))
	writeText(&value, request.ExpiresAt.UTC().Format(time.RFC3339Nano))
	if value.Len() > maxRequestBytes {
		return nil, errors.New("canonical backfill request exceeds bound")
	}
	return value.Bytes(), nil
}

func (request Request) validate() error {
	if request.MigrationVersion != 4 || request.SnapshotCount == 0 || request.SnapshotCount > maximumCount || request.CreatedAt.IsZero() || request.ExpiresAt.IsZero() || request.CreatedAt.Location() != time.UTC || request.ExpiresAt.Location() != time.UTC || !request.ExpiresAt.After(request.CreatedAt) || request.ExpiresAt.After(request.CreatedAt.Add(10*time.Minute)) {
		return errors.New("invalid backfill request fields")
	}
	for _, digest := range []string{request.StackDigest, request.MigrationArtifactDigest, request.ManifestDigest, request.ControllerImageDigest, request.SnapshotFingerprint, request.StaticReadinessDigest, request.DatabaseAuthorityDigest, request.BlobReadCapabilityDigest} {
		if !validDigest(digest) {
			return errors.New("invalid backfill digest")
		}
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(request.FenceNonce)
	if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != request.FenceNonce {
		return errors.New("invalid backfill fence nonce")
	}
	return nil
}

// ValidateAt verifies the immutable request admission window at an explicit UTC time.
func (request Request) ValidateAt(now time.Time) error {
	if err := request.validate(); err != nil {
		return err
	}
	if now.UTC().Before(request.CreatedAt) {
		return ErrFutureRequest
	}
	if !now.UTC().Before(request.ExpiresAt) {
		return ErrExpiredRequest
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	if value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

// Phase identifies one terminal or in-progress verification state.
type Phase string

const (
	// PhasePending identifies a request not yet examined by the controller.
	PhasePending Phase = "Pending"
	// PhaseVerifying identifies an in-progress verification.
	PhaseVerifying Phase = "Verifying"
	// PhaseVerified identifies a successfully verified immutable legacy set.
	PhaseVerified Phase = "Verified"
	// PhaseRefused identifies a terminal safe refusal.
	PhaseRefused Phase = "Refused"
)

// Reason is a bounded terminal refusal classification.
type Reason string

const (
	// RefusalSnapshot identifies a stale or malformed frozen snapshot.
	RefusalSnapshot Reason = "snapshot"
	// RefusalContent identifies content or owner integrity failure.
	RefusalContent Reason = "content"
	// RefusalExpired identifies an expired request.
	RefusalExpired Reason = "expired"
	// RefusalNotAdmitted identifies a request before its immutable creation time.
	RefusalNotAdmitted Reason = "not_admitted"
)

// Status is the bounded redacted result for one immutable request.
type Status struct {
	Phase               Phase
	RequestDigest       string
	SnapshotFingerprint string
	SnapshotCount       uint64
	Reason              Reason
	CompletedAt         time.Time
}

// Canonical returns the deterministic bounded CBOR terminal-status envelope.
func (status Status) Canonical() ([]byte, error) {
	if (status.Phase != PhaseVerified && status.Phase != PhaseRefused) || !validDigest(status.RequestDigest) || !validDigest(status.SnapshotFingerprint) || status.SnapshotCount == 0 || status.SnapshotCount > maximumCount || status.CompletedAt.IsZero() || status.CompletedAt.Location() != time.UTC {
		return nil, errors.New("invalid backfill status")
	}
	if (status.Phase == PhaseVerified && status.Reason != "") || (status.Phase == PhaseRefused && !validReason(status.Reason)) {
		return nil, errors.New("invalid backfill terminal status")
	}
	var value bytes.Buffer
	writeHead(&value, 4, 7)
	writeUint(&value, requestVersion)
	writeText(&value, string(status.Phase))
	writeText(&value, status.RequestDigest)
	writeText(&value, status.SnapshotFingerprint)
	writeUint(&value, status.SnapshotCount)
	writeText(&value, string(status.Reason))
	writeText(&value, status.CompletedAt.UTC().Format(time.RFC3339Nano))
	if value.Len() > maxStatusBytes {
		return nil, errors.New("canonical backfill status exceeds bound")
	}
	return value.Bytes(), nil
}

func validReason(reason Reason) bool {
	return reason == RefusalSnapshot || reason == RefusalContent || reason == RefusalExpired || reason == RefusalNotAdmitted
}

// ValidateFor proves the status matches one request at an explicit time.
func (status Status) ValidateFor(request Request, now time.Time) error {
	digest, err := request.Digest()
	if err != nil || status.RequestDigest != digest || status.SnapshotFingerprint != request.SnapshotFingerprint || status.SnapshotCount != request.SnapshotCount || status.CompletedAt.IsZero() || status.CompletedAt.Location() != time.UTC || status.CompletedAt.After(now.UTC()) {
		return errors.New("invalid backfill status")
	}
	if status.Phase == PhaseVerified && status.Reason != "" {
		return errors.New("verified backfill status has refusal reason")
	}
	if status.Phase == PhaseRefused && !validReason(status.Reason) {
		return errors.New("refused backfill status has no reason")
	}
	if status.Phase != PhaseVerified && status.Phase != PhaseRefused {
		return errors.New("backfill status is not terminal")
	}
	if status.Reason == RefusalNotAdmitted {
		if !status.CompletedAt.Before(request.CreatedAt) {
			return errors.New("not admitted backfill status is outside admission interval")
		}
		return nil
	}
	if status.CompletedAt.Before(request.CreatedAt) {
		return errors.New("backfill status precedes request creation")
	}
	if status.Reason == RefusalExpired {
		if status.CompletedAt.Before(request.ExpiresAt) {
			return errors.New("expired backfill status precedes expiry")
		}
		return nil
	}
	if !status.CompletedAt.Before(request.ExpiresAt) || !now.UTC().Before(request.ExpiresAt) {
		return errors.New("backfill status is outside request interval")
	}
	return nil
}

// ValidateTransitionFrom rejects any transition from a terminal status.
func (status Status) ValidateTransitionFrom(previous Status) error {
	if previous.Phase == PhaseVerified || previous.Phase == PhaseRefused {
		return errors.New("terminal backfill status is immutable")
	}
	return nil
}

// Snapshot describes the deterministic frozen legacy set.
type Snapshot struct {
	Fingerprint string
	Count       uint64
}

// LegacyRevision is one minimal immutable historical Agent revision reference.
type LegacyRevision struct {
	TenantID, AgentID, RevisionID, SpecificationDigest string
	SpecificationSizeBytes                             int64
}

// FrozenLegacySet is read under the migration fence.
type FrozenLegacySet struct {
	Snapshot  Snapshot
	Revisions []LegacyRevision
}

// FrozenLegacyReader reads the fenced historical revision set.
type FrozenLegacyReader interface {
	ReadFrozen(context.Context) (FrozenLegacySet, error)
}

// ImmutableContentVerifier validates one revision against its immutable content reference and manifest.
type ImmutableContentVerifier interface {
	VerifyImmutable(context.Context, LegacyRevision) error
}

// Verify reads and verifies a frozen set, returning only a bounded terminal status.
func Verify(ctx context.Context, request Request, reader FrozenLegacyReader, verifier ImmutableContentVerifier, now time.Time) (Status, error) {
	if err := request.validate(); err != nil {
		return Status{}, errors.Wrap(err, "validate backfill request")
	}
	digest, err := request.Digest()
	if err != nil {
		return Status{}, err
	}
	status := Status{RequestDigest: digest, SnapshotFingerprint: request.SnapshotFingerprint, SnapshotCount: request.SnapshotCount, CompletedAt: now.UTC()}
	if now.UTC().Before(request.CreatedAt) {
		status.Phase, status.Reason = PhaseRefused, RefusalNotAdmitted
		return status, nil
	}
	if !now.UTC().Before(request.ExpiresAt) {
		status.Phase, status.Reason = PhaseRefused, RefusalExpired
		return status, nil
	}
	if err := ctx.Err(); err != nil {
		return Status{}, errors.Wrap(err, "verify backfill request")
	}
	if reader == nil || verifier == nil {
		return Status{}, errors.New("backfill reader and verifier are required")
	}
	set, err := reader.ReadFrozen(ctx)
	if err != nil {
		return classifyVerificationError(status, err, "read frozen legacy set")
	}
	if err := ctx.Err(); err != nil {
		return Status{}, errors.Wrap(err, "read frozen legacy set")
	}
	if set.Snapshot.Fingerprint != request.SnapshotFingerprint || set.Snapshot.Count != request.SnapshotCount || uint64(len(set.Revisions)) != request.SnapshotCount {
		status.Phase, status.Reason = PhaseRefused, RefusalSnapshot
		return status, nil
	}
	for _, revision := range set.Revisions {
		if revision.TenantID == "" || revision.AgentID == "" || revision.RevisionID == "" || revision.SpecificationSizeBytes < 0 || !validDigest(revision.SpecificationDigest) {
			status.Phase, status.Reason = PhaseRefused, RefusalContent
			return status, nil
		}
		if err := verifier.VerifyImmutable(ctx, revision); err != nil {
			return classifyVerificationError(status, err, "verify immutable content")
		}
		if err := ctx.Err(); err != nil {
			return Status{}, errors.Wrap(err, "verify immutable content")
		}
	}
	status.Phase = PhaseVerified
	return status, nil
}

func classifyVerificationError(status Status, err error, action string) (Status, error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return Status{}, errors.Wrap(err, action)
	}
	if errors.Is(err, ErrStaleSnapshot) {
		status.Phase, status.Reason = PhaseRefused, RefusalSnapshot
		return status, nil
	}
	if errors.Is(err, ErrWrongOwner) || errors.Is(err, ErrContentIntegrity) {
		status.Phase, status.Reason = PhaseRefused, RefusalContent
		return status, nil
	}
	return Status{}, errors.Wrap(err, action)
}

// Audit is bounded redacted terminal evidence.
type Audit struct{ Code string }

// CertificateInput is the safe certificate projection when v4 committed.
type CertificateInput struct{ Digest string }

// TerminalArchiveEvidence is the redacted, immutable terminal evidence selected by the distinct archive-export authority.
// RequestUID is the observed CR UID, never a caller-supplied display name.
type TerminalArchiveEvidence struct {
	RequestUID    string
	RequestDigest string
	Request       Request
	Status        Status
	Audit         Audit
	Certificate   *CertificateInput
}

// ArchiveBundle is one immutable terminal request evidence bundle.
type ArchiveBundle struct {
	requestUID  string
	request     Request
	status      Status
	audit       Audit
	certificate *CertificateInput
}

// NewArchiveBundle constructs one CR-UID and request-digest-keyed terminal archive bundle.
func NewArchiveBundle(evidence TerminalArchiveEvidence) (ArchiveBundle, error) {
	if !validArchiveRequestUID(evidence.RequestUID) {
		return ArchiveBundle{}, errors.New("invalid archive request UID")
	}
	requestDigest, err := evidence.Request.Digest()
	if err != nil || evidence.RequestDigest != requestDigest {
		return ArchiveBundle{}, errors.New("archive evidence request digest does not match request")
	}
	if err := evidence.Status.ValidateFor(evidence.Request, evidence.Status.CompletedAt); err != nil {
		return ArchiveBundle{}, errors.Wrap(err, "validate archive status")
	}
	if !validAuditCode(evidence.Audit.Code) {
		return ArchiveBundle{}, errors.New("invalid archive audit code")
	}
	if evidence.Certificate != nil && !validDigest(evidence.Certificate.Digest) {
		return ArchiveBundle{}, errors.New("invalid archive certificate")
	}
	if evidence.Status.Phase != PhaseVerified && evidence.Certificate != nil {
		return ArchiveBundle{}, errors.New("refused archive has certificate")
	}
	return ArchiveBundle{requestUID: evidence.RequestUID, request: evidence.Request, status: evidence.Status, audit: evidence.Audit, certificate: evidence.Certificate}, nil
}

func validArchiveRequestUID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || (character == '-' && index > 0 && index < len(value)-1) {
			continue
		}
		return false
	}
	return true
}

func validAuditCode(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

// CertificatePresent reports whether the terminal request committed v4 certificate evidence.
func (bundle ArchiveBundle) CertificatePresent() bool { return bundle.certificate != nil }

// AuditCode reports the bounded redacted audit classification retained in this bundle.
func (bundle ArchiveBundle) AuditCode() string { return bundle.audit.Code }

// Key returns the deterministic archive object key under one declared prefix.
func (bundle ArchiveBundle) Key(prefix string) string {
	digest, _ := bundle.request.Digest()
	return strings.TrimSuffix(prefix, "/") + "/agentspecbackfill/v1/" + bundle.requestUID + "/" + strings.Replace(digest, ":", "-", 1) + ".cbor"
}

// Canonical returns bounded redacted immutable archive bytes.
func (bundle ArchiveBundle) Canonical() ([]byte, error) {
	request, err := bundle.request.Canonical()
	if err != nil {
		return nil, err
	}
	status, err := bundle.status.Canonical()
	if err != nil {
		return nil, err
	}
	var value bytes.Buffer
	writeHead(&value, 4, 6)
	writeUint(&value, 1)
	writeText(&value, bundle.requestUID)
	writeBytes(&value, request)
	writeBytes(&value, status)
	writeText(&value, bundle.audit.Code)
	if bundle.certificate == nil {
		value.WriteByte(0xf6)
	} else {
		writeText(&value, bundle.certificate.Digest)
	}
	if value.Len() > maxStatusBytes {
		return nil, errors.New("canonical archive exceeds bound")
	}
	return value.Bytes(), nil
}

// Digest returns the SHA-256 digest of one canonical immutable archive bundle.
func (bundle ArchiveBundle) Digest() (string, error) {
	canonical, err := bundle.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func writeUint(buffer *bytes.Buffer, value uint64) { writeHead(buffer, 0, value) }
func writeText(buffer *bytes.Buffer, value string) {
	writeHead(buffer, 3, uint64(len(value)))
	buffer.WriteString(value)
}
func writeBytes(buffer *bytes.Buffer, value []byte) {
	writeHead(buffer, 2, uint64(len(value)))
	buffer.Write(value)
}
func writeHead(buffer *bytes.Buffer, major byte, value uint64) {
	if value < 24 {
		buffer.WriteByte(major<<5 | byte(value))
		return
	}
	if value <= 0xff {
		buffer.WriteByte(major<<5 | 24)
		buffer.WriteByte(byte(value))
		return
	}
	if value <= 0xffff {
		buffer.WriteByte(major<<5 | 25)
		buffer.WriteByte(byte(value >> 8))
		buffer.WriteByte(byte(value))
		return
	}
	if value <= 0xffffffff {
		buffer.WriteByte(major<<5 | 26)
		for shift := uint(24); ; shift -= 8 {
			buffer.WriteByte(byte(value >> shift))
			if shift == 0 {
				return
			}
		}
	}
	buffer.WriteByte(major<<5 | 27)
	for shift := uint(56); ; shift -= 8 {
		buffer.WriteByte(byte(value >> shift))
		if shift == 0 {
			return
		}
	}
}
