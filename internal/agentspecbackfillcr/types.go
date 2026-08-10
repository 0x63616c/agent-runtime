// Package agentspecbackfillcr owns the structural, canonical AgentSpecBackfill request and status wires.
package agentspecbackfillcr

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"time"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfill"
	"github.com/cockroachdb/errors"
)

const (
	// APIVersion is the sole structural AgentSpecBackfill API version.
	APIVersion = "runtime.0x63616c.dev/v1alpha1"
	// Kind is the sole structural AgentSpecBackfill kind.
	Kind = "AgentSpecBackfill"

	maximumRequestWireBytes = 4096
	maximumStatusWireBytes  = 2048
)

var opaqueValue = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,127}$`)

// Metadata is the bounded structural metadata accepted for one AgentSpecBackfill resource.
type Metadata struct {
	Name       string
	UID        string
	Generation uint64
}

// Request is the immutable structural AgentSpecBackfill request. Its Spec reuses the canonical backfill request.
type Request struct {
	APIVersion string
	Kind       string
	Metadata   Metadata
	Spec       agentspecbackfill.Request
}

// Status is the bounded controller-owned structural AgentSpecBackfill result.
type Status struct {
	Phase                 agentspecbackfill.Phase
	RequestUID            string
	ObservedGeneration    uint64
	ControllerImageDigest string
	RequestDigest         string
	SnapshotFingerprint   string
	SnapshotCount         uint64
	ManifestDigest        string
	StaticReadinessDigest string
	VerifiedCount         uint64
	Reason                agentspecbackfill.Reason
	CompletedAt           time.Time
}

type requestWire struct {
	APIVersion string       `json:"apiVersion"`
	Kind       string       `json:"kind"`
	Metadata   metadataWire `json:"metadata"`
	Spec       specWire     `json:"spec"`
}

type metadataWire struct {
	Name       string `json:"name"`
	UID        string `json:"uid,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
}

type specWire struct {
	StackDigest              string    `json:"stackDigest"`
	MigrationVersion         uint32    `json:"migrationVersion"`
	MigrationArtifactDigest  string    `json:"migrationArtifactDigest"`
	ManifestDigest           string    `json:"manifestDigest"`
	ControllerImageDigest    string    `json:"controllerImageDigest"`
	SnapshotFingerprint      string    `json:"snapshotFingerprint"`
	SnapshotCount            uint64    `json:"snapshotCount"`
	FenceNonce               string    `json:"fenceNonce"`
	CreatedAt                time.Time `json:"createdAt"`
	StaticReadinessDigest    string    `json:"staticReadinessDigest"`
	DatabaseAuthorityDigest  string    `json:"databaseAuthorityDigest"`
	BlobReadCapabilityDigest string    `json:"blobReadCapabilityDigest"`
	RequestExpiresAt         time.Time `json:"requestExpiresAt"`
}

type statusWire struct {
	Phase                 agentspecbackfill.Phase  `json:"phase"`
	RequestUID            string                   `json:"requestUID"`
	ObservedGeneration    uint64                   `json:"observedGeneration"`
	ControllerImageDigest string                   `json:"controllerImageDigest"`
	RequestDigest         string                   `json:"requestDigest"`
	SnapshotFingerprint   string                   `json:"snapshotFingerprint"`
	SnapshotCount         uint64                   `json:"snapshotCount"`
	ManifestDigest        string                   `json:"manifestDigest"`
	StaticReadinessDigest string                   `json:"staticReadinessDigest"`
	VerifiedCount         uint64                   `json:"verifiedCount"`
	Reason                agentspecbackfill.Reason `json:"reason,omitempty"`
	CompletedAt           time.Time                `json:"completedAt"`
}

// NewRequest creates the sole canonical initial AgentSpecBackfill request for a validated immutable spec.
func NewRequest(spec agentspecbackfill.Request) (Request, error) {
	name, err := spec.Name()
	if err != nil {
		return Request{}, errors.Wrap(err, "name AgentSpecBackfill request")
	}
	request := Request{APIVersion: APIVersion, Kind: Kind, Metadata: Metadata{Name: name}, Spec: spec}
	if _, err := request.Canonical(); err != nil {
		return Request{}, err
	}
	return request, nil
}

// Canonical returns the bounded canonical JSON request wire.
func (request Request) Canonical() ([]byte, error) {
	if err := request.validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(request.wire())
	if err != nil || len(encoded) > maximumRequestWireBytes {
		return nil, errors.New("canonical AgentSpecBackfill request is invalid or oversized")
	}
	return encoded, nil
}

// ParseRequest decodes exactly one bounded canonical AgentSpecBackfill request wire.
func ParseRequest(input io.Reader) (Request, error) {
	if input == nil {
		return Request{}, errors.New("parse AgentSpecBackfill request: input is required")
	}
	encoded, err := io.ReadAll(io.LimitReader(input, maximumRequestWireBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maximumRequestWireBytes {
		return Request{}, errors.New("parse AgentSpecBackfill request: invalid bounded input")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire requestWire
	if err := decoder.Decode(&wire); err != nil {
		return Request{}, errors.Wrap(err, "parse AgentSpecBackfill request")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Request{}, errors.New("parse AgentSpecBackfill request: exactly one document is required")
	}
	request := requestFromWire(wire)
	canonical, err := request.Canonical()
	if err != nil || !bytes.Equal(encoded, canonical) {
		return Request{}, errors.New("parse AgentSpecBackfill request: canonical immutable wire is required")
	}
	return request, nil
}

// ValidateImmutableMutation refuses any changed request metadata or spec.
func (request Request) ValidateImmutableMutation(next Request) error {
	current, err := request.Canonical()
	if err != nil {
		return err
	}
	candidate, err := next.Canonical()
	if err != nil || !bytes.Equal(current, candidate) {
		return errors.New("AgentSpecBackfill request is immutable")
	}
	return nil
}

// CanonicalFor returns the bounded canonical JSON status wire after validating it against its immutable request.
func (status Status) CanonicalFor(request Request, now time.Time) ([]byte, error) {
	if err := status.ValidateFor(request, now); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(statusWire(status))
	if err != nil || len(encoded) > maximumStatusWireBytes {
		return nil, errors.New("canonical AgentSpecBackfill status is invalid or oversized")
	}
	return encoded, nil
}

// ParseStatus decodes exactly one bounded canonical AgentSpecBackfill status wire.
func ParseStatus(input io.Reader, request Request, now time.Time) (Status, error) {
	if input == nil {
		return Status{}, errors.New("parse AgentSpecBackfill status: input is required")
	}
	encoded, err := io.ReadAll(io.LimitReader(input, maximumStatusWireBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maximumStatusWireBytes {
		return Status{}, errors.New("parse AgentSpecBackfill status: invalid bounded input")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire statusWire
	if err := decoder.Decode(&wire); err != nil {
		return Status{}, errors.Wrap(err, "parse AgentSpecBackfill status")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Status{}, errors.New("parse AgentSpecBackfill status: exactly one document is required")
	}
	status := Status(wire)
	canonical, err := status.CanonicalFor(request, now)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return Status{}, errors.New("parse AgentSpecBackfill status: canonical bounded wire is required")
	}
	return status, nil
}

// ValidateFor proves a status is bounded and exactly bound to one observed immutable request.
func (status Status) ValidateFor(request Request, now time.Time) error {
	if err := request.validate(); err != nil {
		return err
	}
	digest, err := request.Spec.Digest()
	if err != nil || !opaqueValue.MatchString(request.Metadata.UID) || request.Metadata.Generation == 0 || status.RequestUID != request.Metadata.UID || status.ObservedGeneration != request.Metadata.Generation || status.ControllerImageDigest != request.Spec.ControllerImageDigest || status.RequestDigest != digest || status.SnapshotFingerprint != request.Spec.SnapshotFingerprint || status.SnapshotCount != request.Spec.SnapshotCount || status.ManifestDigest != request.Spec.ManifestDigest || status.StaticReadinessDigest != request.Spec.StaticReadinessDigest || status.VerifiedCount > request.Spec.SnapshotCount {
		return errors.New("AgentSpecBackfill status is not bound to the immutable request")
	}
	if status.Phase == agentspecbackfill.PhasePending || status.Phase == agentspecbackfill.PhaseVerifying {
		if status.Reason != "" || !status.CompletedAt.IsZero() {
			return errors.New("AgentSpecBackfill nonterminal status is invalid")
		}
		return nil
	}
	core := agentspecbackfill.Status{Phase: status.Phase, RequestDigest: status.RequestDigest, SnapshotFingerprint: status.SnapshotFingerprint, SnapshotCount: status.SnapshotCount, Reason: status.Reason, CompletedAt: status.CompletedAt}
	if err := core.ValidateFor(request.Spec, now); err != nil || status.Phase == agentspecbackfill.PhaseVerified && status.VerifiedCount != request.Spec.SnapshotCount {
		return errors.New("AgentSpecBackfill terminal status is invalid")
	}
	return nil
}

// ValidateTransitionFrom refuses every mutation from a terminal status.
func (status Status) ValidateTransitionFrom(previous Status, request Request, now time.Time) error {
	if err := status.ValidateFor(request, now); err != nil {
		return err
	}
	if previous.Phase == agentspecbackfill.PhaseVerified || previous.Phase == agentspecbackfill.PhaseRefused {
		return errors.New("AgentSpecBackfill terminal status is immutable")
	}
	return nil
}

func (request Request) validate() error {
	name, err := request.Spec.Name()
	if err != nil || request.APIVersion != APIVersion || request.Kind != Kind || request.Metadata.Name != name || request.Metadata.UID != "" && (!opaqueValue.MatchString(request.Metadata.UID) || request.Metadata.Generation == 0) || request.Metadata.UID == "" && request.Metadata.Generation != 0 {
		return errors.New("AgentSpecBackfill request is invalid")
	}
	return nil
}

func (request Request) wire() requestWire {
	spec := request.Spec
	return requestWire{APIVersion: request.APIVersion, Kind: request.Kind, Metadata: metadataWire{Name: request.Metadata.Name, UID: request.Metadata.UID, Generation: request.Metadata.Generation}, Spec: specWire{StackDigest: spec.StackDigest, MigrationVersion: spec.MigrationVersion, MigrationArtifactDigest: spec.MigrationArtifactDigest, ManifestDigest: spec.ManifestDigest, ControllerImageDigest: spec.ControllerImageDigest, SnapshotFingerprint: spec.SnapshotFingerprint, SnapshotCount: spec.SnapshotCount, FenceNonce: spec.FenceNonce, CreatedAt: spec.CreatedAt, StaticReadinessDigest: spec.StaticReadinessDigest, DatabaseAuthorityDigest: spec.DatabaseAuthorityDigest, BlobReadCapabilityDigest: spec.BlobReadCapabilityDigest, RequestExpiresAt: spec.ExpiresAt}}
}

func requestFromWire(wire requestWire) Request {
	return Request{APIVersion: wire.APIVersion, Kind: wire.Kind, Metadata: Metadata{Name: wire.Metadata.Name, UID: wire.Metadata.UID, Generation: wire.Metadata.Generation}, Spec: agentspecbackfill.Request{StackDigest: wire.Spec.StackDigest, MigrationVersion: wire.Spec.MigrationVersion, MigrationArtifactDigest: wire.Spec.MigrationArtifactDigest, ManifestDigest: wire.Spec.ManifestDigest, ControllerImageDigest: wire.Spec.ControllerImageDigest, SnapshotFingerprint: wire.Spec.SnapshotFingerprint, SnapshotCount: wire.Spec.SnapshotCount, FenceNonce: wire.Spec.FenceNonce, CreatedAt: wire.Spec.CreatedAt, StaticReadinessDigest: wire.Spec.StaticReadinessDigest, DatabaseAuthorityDigest: wire.Spec.DatabaseAuthorityDigest, BlobReadCapabilityDigest: wire.Spec.BlobReadCapabilityDigest, ExpiresAt: wire.Spec.RequestExpiresAt}}
}
