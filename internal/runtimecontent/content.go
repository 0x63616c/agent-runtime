// Package runtimecontent owns runtime-scoped immutable Agent specification and Input content.
package runtimecontent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/0x63616c/agent-runtime/internal/toolschema"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

const (
	// AgentSpecificationMediaTypeV1 identifies the canonical Agent specification envelope.
	AgentSpecificationMediaTypeV1 = "application/vnd.agent-runtime.agent-specification+cbor;version=1"
	// AgentSpecificationBodyMediaTypeV1 identifies an identity-free canonical Agent specification body.
	AgentSpecificationBodyMediaTypeV1 = "application/vnd.agent-runtime.agent-specification-body+cbor;version=1"
	// InputEnvelopeMediaTypeV1 identifies the canonical identity-free Input envelope.
	InputEnvelopeMediaTypeV1 = "application/vnd.agent-runtime.input+cbor;version=1"
	// ConversationEntryMediaTypeV1 identifies opaque immutable semantic context.
	ConversationEntryMediaTypeV1    = "application/vnd.agent-runtime.conversation-entry+octets;version=1"
	ToolActionDescriptorMediaTypeV1 = "application/vnd.agent-runtime.tool-action+octets;version=1"
	maximumSpecificationBytes       = 1 << 20
	maximumInputEnvelopeBytes       = 2<<20 + 4<<10
	maximumArtifactBytes            = 8 << 20
	maximumArtifactMediaTypeBytes   = 255
	maximumConversationEntryBytes   = 2 << 20
	maximumInstructionsBytes        = 256 * 1024
	maximumToolDescriptionBytes     = 4096
	maximumNameBytes                = 128
	maximumTools                    = 64
	maximumTenantIDBytes            = 128
	maximumContentRootBytes         = 128
)

var (
	// ErrNotFoundOrDenied prevents callers from enumerating runtime content.
	ErrNotFoundOrDenied = errors.New("runtime content not found or denied")
	// ErrUnavailable identifies a runtime-content object-store failure without exposing its details.
	ErrUnavailable = errors.New("runtime content unavailable")
	// ErrIntegrity identifies invalid, altered, or conflicting immutable runtime content.
	ErrIntegrity = errors.New("runtime content integrity failure")
)

// TenantID is the strict, canonical identity used to partition runtime content.
type TenantID string

// ParseTenantID validates one canonical runtime-content tenant identity.
func ParseTenantID(raw string) (TenantID, error) {
	if !validSegment(raw, maximumTenantIDBytes) {
		return "", errors.New("invalid runtime content tenant identity")
	}
	return TenantID(raw), nil
}

// PrincipalID is the strict, canonical identity used to authorize session-owned runtime content reads.
type PrincipalID string

// ParsePrincipalID validates one canonical runtime-content principal identity.
func ParsePrincipalID(raw string) (PrincipalID, error) {
	if !validSegment(raw, maximumTenantIDBytes) {
		return "", errors.New("invalid runtime content principal identity")
	}
	return PrincipalID(raw), nil
}

// Reference contains immutable content metadata without a storage key.
type Reference struct {
	Digest    string
	MediaType string
	SizeBytes int64
}

// AgentSpecificationBody is the immutable behavior content before a runtime state authority allocates an Agent revision identity.
type AgentSpecificationBody struct {
	Name         string
	ModelProfile string
	Instructions string
	Tools        []agentruntime.ToolDefinition
}

// Clone returns an independent Agent specification body.
func (body AgentSpecificationBody) Clone() AgentSpecificationBody {
	clone := body
	clone.Tools = cloneToolDefinitions(body.Tools)
	return clone
}

func cloneToolDefinitions(tools []agentruntime.ToolDefinition) []agentruntime.ToolDefinition {
	clone := append([]agentruntime.ToolDefinition(nil), tools...)
	for index := range clone {
		clone[index].InputSchema = append([]byte(nil), clone[index].InputSchema...)
	}
	return clone
}

// AgentSpecificationBodyCommitment is the bounded metadata a state command may persist after validating a staged body handoff.
type AgentSpecificationBodyCommitment struct {
	Tenant       TenantID
	Reference    Reference
	Name         string
	ModelProfile string
}

// InputEnvelopeCommitment is the bounded metadata a state command may persist after validating a staged Input handoff.
type InputEnvelopeCommitment struct {
	Tenant    TenantID
	Reference Reference
}

// ArtifactCommitment is the bounded immutable content metadata a runtime state
// command may persist.  It deliberately contains no storage locator or bytes.
type ArtifactCommitment struct {
	Tenant    TenantID
	Reference Reference
}

// ConversationEntryCommitment is the opaque immutable semantic-context
// reference a state transition may persist.
type ConversationEntryCommitment struct {
	Tenant    TenantID
	Reference Reference
}
type ToolActionDescriptorCommitment struct {
	Tenant    TenantID
	Reference Reference
}

// ContentHandoff is an opaque, in-process proof that Store wrote and read back one tenant-bound immutable content object.
//
// It is not a persistent record or a public capability. A state composition
// validates it through the issuing Store before accepting its metadata.
type ContentHandoff struct {
	issuer       *Store
	tenant       TenantID
	reference    Reference
	kind         contentKind
	name         string
	modelProfile string
}

type contentKind uint8

const (
	contentKindAgentSpecificationBody contentKind = iota + 1
	contentKindInputEnvelope
	contentKindArtifact
	contentKindConversationEntry
	contentKindToolActionDescriptor
)

// ContentHandoffValidator validates opaque staged-content commitments before a runtime state command persists their metadata.
type ContentHandoffValidator interface {
	ValidateAgentSpecificationBodyHandoff(ContentHandoff) (AgentSpecificationBodyCommitment, error)
	ValidateInputEnvelopeHandoff(ContentHandoff) (InputEnvelopeCommitment, error)
	ValidateArtifactHandoff(ContentHandoff) (ArtifactCommitment, error)
	ValidateConversationEntryHandoff(ContentHandoff) (ConversationEntryCommitment, error)
	ValidateToolActionDescriptorHandoff(ContentHandoff) (ToolActionDescriptorCommitment, error)
}

// ImmutableObjectStore conditionally stores and bounded-reads runtime-owned immutable bytes.
// A false created result requires Store to verify the existing object before success.
type ImmutableObjectStore interface {
	PutIfAbsent(context.Context, string, []byte) (created bool, err error)
	Get(context.Context, string, int) ([]byte, error)
}

// ImmutableObjectStreamer is an optional bounded streaming read capability.
// Buffered reads remain supported for legacy callers.
type ImmutableObjectStreamer interface {
	Open(context.Context, string, int) (io.ReadCloser, error)
}

// ArtifactStream contains state-authorized immutable metadata and a closable
// bounded byte stream. It never exposes an object-store key.
type ArtifactStream struct {
	Reference Reference
	Body      io.ReadCloser
}

// AgentSpecificationRecord is the exact durable metadata returned by a repository authorization check.
type AgentSpecificationRecord struct {
	Tenant     TenantID
	AgentID    agentruntime.AgentID
	RevisionID agentruntime.AgentRevisionID
	Revision   uint64
	Reference  Reference
}

// AgentSpecificationRepository authorizes one exact Agent revision content read.
type AgentSpecificationRepository interface {
	AuthorizeAgentSpecificationRead(context.Context, TenantID, agentruntime.AgentID, agentruntime.AgentRevisionID) (AgentSpecificationRecord, error)
}

// AgentSpecificationBodyRecord is the exact durable metadata required to authorize one identity-free Agent specification body read.
type AgentSpecificationBodyRecord struct {
	Tenant       TenantID
	AgentID      agentruntime.AgentID
	RevisionID   agentruntime.AgentRevisionID
	Revision     uint64
	Name         string
	ModelProfile string
	Reference    Reference
	CreatedAt    time.Time
}

// AgentSpecificationBodyRepository authorizes one exact metadata-bound Agent specification body read.
type AgentSpecificationBodyRepository interface {
	AuthorizeAgentSpecificationBodyRead(context.Context, TenantID, agentruntime.AgentID, agentruntime.AgentRevisionID) (AgentSpecificationBodyRecord, error)
}

// InputEnvelopeRecord is the exact durable metadata required to authorize one immutable Input envelope read.
type InputEnvelopeRecord struct {
	Tenant    TenantID
	Principal PrincipalID
	SessionID agentruntime.SessionID
	InputID   agentruntime.InputID
	Reference Reference
}

// InputEnvelopeRepository authorizes one exact metadata-bound Input envelope read.
type InputEnvelopeRepository interface {
	AuthorizeInputEnvelopeRead(context.Context, TenantID, PrincipalID, agentruntime.SessionID, agentruntime.InputID) (InputEnvelopeRecord, error)
}

// ArtifactRecord is the exact durable metadata required before immutable
// artifact bytes may be read.  The object-store key remains private to Store.
type ArtifactRecord struct {
	Tenant     TenantID
	Principal  PrincipalID
	ArtifactID agentruntime.ArtifactID
	Reference  Reference
}

// ArtifactRepository authorizes one exact artifact download under principal ownership.
type ArtifactRepository interface {
	AuthorizeArtifactRead(context.Context, TenantID, PrincipalID, agentruntime.ArtifactID) (ArtifactRecord, error)
}

// ToolActionDescriptorRepository authorizes one exact immutable tool action
// descriptor for a worker-owned operation.
type ToolActionDescriptorRepository interface {
	AuthorizeToolActionDescriptorRead(context.Context, TenantID, PrincipalID, agentruntime.SessionID, agentruntime.TurnID, string) (ToolActionDescriptorCommitment, error)
}

// AgentSpecificationReader reads Agent specification content only after repository authorization.
type AgentSpecificationReader struct {
	store      *Store
	repository AgentSpecificationRepository
}

// AgentSpecificationBodyReader synthesizes an Agent specification from authorized revision metadata and identity-free immutable content.
type AgentSpecificationBodyReader struct {
	store      *Store
	repository AgentSpecificationBodyRepository
}

// InputEnvelopeReader reads Input content only after runtime-state authorization.
type InputEnvelopeReader struct {
	store      *Store
	repository InputEnvelopeRepository
}

// ArtifactReader reads immutable bytes only after runtime-state authorization.
type ArtifactReader struct {
	store      *Store
	repository ArtifactRepository
}

// ToolActionDescriptorReader reads one immutable sandbox-control descriptor
// only after a worker-specific state authorization. The descriptor object key
// never crosses this boundary.
type ToolActionDescriptorReader struct {
	store      *Store
	repository ToolActionDescriptorRepository
}

// agentSpecificationLocator is a package-private capability created only after repository authorization.
type agentSpecificationLocator struct {
	tenant     TenantID
	agentID    agentruntime.AgentID
	revisionID agentruntime.AgentRevisionID
	revision   uint64
	reference  Reference
}

type agentSpecificationBodyLocator struct {
	record AgentSpecificationBodyRecord
}

type inputEnvelopeLocator struct {
	record InputEnvelopeRecord
}

type artifactLocator struct{ record ArtifactRecord }

type toolActionDescriptorLocator struct {
	commitment ToolActionDescriptorCommitment
}

// Store owns one explicit runtime content namespace.
type Store struct {
	contentRoot string
	objects     ImmutableObjectStore
}

// New constructs a Store from the explicitly declared content root and immutable object port.
func New(contentRoot string, objects ImmutableObjectStore) (*Store, error) {
	if objects == nil || !validContentRoot(contentRoot) {
		return nil, errors.New("runtime content root and immutable object store are required")
	}
	return &Store{contentRoot: contentRoot, objects: objects}, nil
}

// NewAgentSpecificationReader constructs the content-read boundary from an explicit Store and repository authority.
func NewAgentSpecificationReader(store *Store, repository AgentSpecificationRepository) (*AgentSpecificationReader, error) {
	if store == nil || repository == nil {
		return nil, errors.New("Agent specification reader requires content store and repository authority")
	}
	return &AgentSpecificationReader{store: store, repository: repository}, nil
}

// NewAgentSpecificationBodyReader constructs the metadata-bound Agent specification body read boundary.
func NewAgentSpecificationBodyReader(store *Store, repository AgentSpecificationBodyRepository) (*AgentSpecificationBodyReader, error) {
	if store == nil || repository == nil {
		return nil, errors.New("Agent specification body reader requires content store and repository authority")
	}
	return &AgentSpecificationBodyReader{store: store, repository: repository}, nil
}

// NewInputEnvelopeReader constructs the metadata-bound Input envelope read boundary.
func NewInputEnvelopeReader(store *Store, repository InputEnvelopeRepository) (*InputEnvelopeReader, error) {
	if store == nil || repository == nil {
		return nil, errors.New("Input envelope reader requires content store and repository authority")
	}
	return &InputEnvelopeReader{store: store, repository: repository}, nil
}

// NewArtifactReader constructs the authorization-before-content-read boundary.
func NewArtifactReader(store *Store, repository ArtifactRepository) (*ArtifactReader, error) {
	if store == nil || repository == nil {
		return nil, errors.New("Artifact reader requires content store and repository authority")
	}
	return &ArtifactReader{store: store, repository: repository}, nil
}

// NewToolActionDescriptorReader constructs the worker-only immutable action
// descriptor read boundary.
func NewToolActionDescriptorReader(store *Store, repository ToolActionDescriptorRepository) (*ToolActionDescriptorReader, error) {
	if store == nil || repository == nil {
		return nil, errors.New("tool action descriptor reader requires content store and repository authority")
	}
	return &ToolActionDescriptorReader{store: store, repository: repository}, nil
}

// ReadAgentSpecification authorizes and reads one exact tenant-owned Agent revision.
func (reader *AgentSpecificationReader) ReadAgentSpecification(ctx context.Context, tenant TenantID, agentID agentruntime.AgentID, revisionID agentruntime.AgentRevisionID) (agentruntime.AgentSpecification, error) {
	if !validTenantID(tenant) {
		return agentruntime.AgentSpecification{}, ErrNotFoundOrDenied
	}
	if _, err := agentruntime.ParseAgentID(agentID.String()); err != nil {
		return agentruntime.AgentSpecification{}, ErrNotFoundOrDenied
	}
	if _, err := agentruntime.ParseAgentRevisionID(revisionID.String()); err != nil {
		return agentruntime.AgentSpecification{}, ErrNotFoundOrDenied
	}
	if err := ctx.Err(); err != nil {
		return agentruntime.AgentSpecification{}, errors.Wrap(err, "authorize Agent specification read")
	}
	record, err := reader.repository.AuthorizeAgentSpecificationRead(ctx, tenant, agentID, revisionID)
	if err != nil {
		return agentruntime.AgentSpecification{}, classifyObjectError("authorize Agent specification read", err, ErrNotFoundOrDenied)
	}
	if err := ctx.Err(); err != nil {
		return agentruntime.AgentSpecification{}, errors.Wrap(err, "authorize Agent specification read")
	}
	if record.Tenant != tenant || record.AgentID != agentID || record.RevisionID != revisionID || !validAgentRevision(record.AgentID, record.RevisionID, record.Revision) || !validReference(record.Reference) {
		return agentruntime.AgentSpecification{}, ErrNotFoundOrDenied
	}
	locator := agentSpecificationLocator{tenant: record.Tenant, agentID: record.AgentID, revisionID: record.RevisionID, revision: record.Revision, reference: record.Reference}
	return reader.store.getAgentSpecification(ctx, locator)
}

// ReadAgentSpecification authorizes identity-free content and synthesizes one exact immutable Agent revision.
func (reader *AgentSpecificationBodyReader) ReadAgentSpecification(ctx context.Context, tenant TenantID, agentID agentruntime.AgentID, revisionID agentruntime.AgentRevisionID) (agentruntime.AgentSpecification, error) {
	if !validTenantID(tenant) {
		return agentruntime.AgentSpecification{}, ErrNotFoundOrDenied
	}
	if _, err := agentruntime.ParseAgentID(agentID.String()); err != nil {
		return agentruntime.AgentSpecification{}, ErrNotFoundOrDenied
	}
	if _, err := agentruntime.ParseAgentRevisionID(revisionID.String()); err != nil {
		return agentruntime.AgentSpecification{}, ErrNotFoundOrDenied
	}
	if err := ctx.Err(); err != nil {
		return agentruntime.AgentSpecification{}, errors.Wrap(err, "authorize Agent specification body read")
	}
	record, err := reader.repository.AuthorizeAgentSpecificationBodyRead(ctx, tenant, agentID, revisionID)
	if err != nil {
		return agentruntime.AgentSpecification{}, classifyObjectError("authorize Agent specification body read", err, ErrNotFoundOrDenied)
	}
	if err := ctx.Err(); err != nil {
		return agentruntime.AgentSpecification{}, errors.Wrap(err, "authorize Agent specification body read")
	}
	if record.Tenant != tenant || record.AgentID != agentID || record.RevisionID != revisionID || !validAgentRevision(record.AgentID, record.RevisionID, record.Revision) || !validName(record.Name) || !validName(record.ModelProfile) || !validAgentSpecificationBodyReference(record.Reference) || record.CreatedAt.IsZero() || record.CreatedAt.Location() != time.UTC {
		return agentruntime.AgentSpecification{}, ErrNotFoundOrDenied
	}
	return reader.store.getAgentSpecificationBody(ctx, agentSpecificationBodyLocator{record: record})
}

// ReadInputEnvelope authorizes and reads one exact tenant-owned Input envelope.
func (reader *InputEnvelopeReader) ReadInputEnvelope(ctx context.Context, tenant TenantID, principal PrincipalID, sessionID agentruntime.SessionID, inputID agentruntime.InputID) ([]agentruntime.ContentPart, error) {
	if !validTenantID(tenant) || !validPrincipalID(principal) {
		return nil, ErrNotFoundOrDenied
	}
	if _, err := agentruntime.ParseSessionID(sessionID.String()); err != nil {
		return nil, ErrNotFoundOrDenied
	}
	if _, err := agentruntime.ParseInputID(inputID.String()); err != nil {
		return nil, ErrNotFoundOrDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "authorize Input envelope read")
	}
	record, err := reader.repository.AuthorizeInputEnvelopeRead(ctx, tenant, principal, sessionID, inputID)
	if err != nil {
		return nil, classifyObjectError("authorize Input envelope read", err, ErrNotFoundOrDenied)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "authorize Input envelope read")
	}
	if record.Tenant != tenant || record.Principal != principal || record.SessionID != sessionID || record.InputID != inputID || !validInputEnvelopeRecord(record) {
		return nil, ErrNotFoundOrDenied
	}
	return reader.store.getInputEnvelope(ctx, inputEnvelopeLocator{record: record})
}

// ReadArtifact returns bounded immutable bytes after exact tenant/principal metadata authorization.
func (reader *ArtifactReader) ReadArtifact(ctx context.Context, tenant TenantID, principal PrincipalID, artifactID agentruntime.ArtifactID) ([]byte, error) {
	if !validTenantID(tenant) || !validPrincipalID(principal) {
		return nil, ErrNotFoundOrDenied
	}
	if _, err := agentruntime.ParseArtifactID(artifactID.String()); err != nil {
		return nil, ErrNotFoundOrDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "authorize Artifact read")
	}
	record, err := reader.repository.AuthorizeArtifactRead(ctx, tenant, principal, artifactID)
	if err != nil {
		return nil, classifyObjectError("authorize Artifact read", err, ErrNotFoundOrDenied)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "authorize Artifact read")
	}
	if record.Tenant != tenant || record.Principal != principal || record.ArtifactID != artifactID || !validArtifactRecord(record) {
		return nil, ErrNotFoundOrDenied
	}
	return reader.store.getArtifact(ctx, artifactLocator{record: record})
}

// OpenArtifact authorizes exact Artifact metadata before opening the object.
// It is intentionally additive to ReadArtifact for compatible callers.
func (reader *ArtifactReader) OpenArtifact(ctx context.Context, tenant TenantID, principal PrincipalID, artifactID agentruntime.ArtifactID) (ArtifactStream, error) {
	if reader == nil || reader.store == nil || !validTenantID(tenant) || !validPrincipalID(principal) {
		return ArtifactStream{}, ErrNotFoundOrDenied
	}
	if _, err := agentruntime.ParseArtifactID(artifactID.String()); err != nil {
		return ArtifactStream{}, ErrNotFoundOrDenied
	}
	record, err := reader.repository.AuthorizeArtifactRead(ctx, tenant, principal, artifactID)
	if err != nil {
		return ArtifactStream{}, classifyObjectError("authorize Artifact stream", err, ErrNotFoundOrDenied)
	}
	if record.Tenant != tenant || record.Principal != principal || record.ArtifactID != artifactID || !validArtifactRecord(record) {
		return ArtifactStream{}, ErrNotFoundOrDenied
	}
	streamer, ok := reader.store.objects.(ImmutableObjectStreamer)
	if !ok {
		return ArtifactStream{}, ErrUnavailable
	}
	body, err := streamer.Open(ctx, reader.store.key(record.Tenant, record.Reference.Digest), int(record.Reference.SizeBytes))
	if err != nil {
		return ArtifactStream{}, classifyObjectError("open immutable Artifact", err, ErrNotFoundOrDenied)
	}
	if body == nil {
		return ArtifactStream{}, ErrUnavailable
	}
	return ArtifactStream{Reference: record.Reference, Body: &limitedReadCloser{ReadCloser: body, reader: io.LimitReader(body, record.Reference.SizeBytes+1)}}, nil
}

type limitedReadCloser struct {
	io.ReadCloser
	reader io.Reader
}

func (stream *limitedReadCloser) Read(value []byte) (int, error) { return stream.reader.Read(value) }

// ReadToolActionDescriptor returns exact immutable sandbox-control bytes only
// after a state-backed runtime-worker authorization for the same operation.
func (reader *ToolActionDescriptorReader) ReadToolActionDescriptor(ctx context.Context, tenant TenantID, principal PrincipalID, sessionID agentruntime.SessionID, turnID agentruntime.TurnID, toolCallID string) ([]byte, error) {
	if !validTenantID(tenant) || !validPrincipalID(principal) {
		return nil, ErrNotFoundOrDenied
	}
	if _, err := agentruntime.ParseSessionID(sessionID.String()); err != nil {
		return nil, ErrNotFoundOrDenied
	}
	if _, err := agentruntime.ParseTurnID(turnID.String()); err != nil || !validToolCallID(toolCallID) {
		return nil, ErrNotFoundOrDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "authorize tool action descriptor read")
	}
	commitment, err := reader.repository.AuthorizeToolActionDescriptorRead(ctx, tenant, principal, sessionID, turnID, toolCallID)
	if err != nil {
		return nil, classifyObjectError("authorize tool action descriptor read", err, ErrNotFoundOrDenied)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "authorize tool action descriptor read")
	}
	if commitment.Tenant != tenant || !validToolActionDescriptorReference(commitment.Reference) {
		return nil, ErrNotFoundOrDenied
	}
	return reader.store.getToolActionDescriptor(ctx, toolActionDescriptorLocator{commitment: commitment})
}

// PutAgentSpecification canonically encodes and conditionally stores one immutable specification.
func (store *Store) PutAgentSpecification(ctx context.Context, tenant TenantID, specification agentruntime.AgentSpecification) (Reference, error) {
	if !validTenantID(tenant) {
		return Reference{}, errors.New("invalid runtime content owner")
	}
	if err := ctx.Err(); err != nil {
		return Reference{}, errors.Wrap(err, "store Agent specification")
	}
	encoded, err := encode(specification)
	if err != nil {
		return Reference{}, err
	}
	reference := referenceFor(encoded)
	created, err := store.objects.PutIfAbsent(ctx, store.key(tenant, reference.Digest), encoded)
	if err != nil {
		return Reference{}, classifyObjectError("store immutable Agent specification", err, ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return Reference{}, errors.Wrap(err, "store Agent specification")
	}
	if created {
		return reference, nil
	}
	existing, err := store.objects.Get(ctx, store.key(tenant, reference.Digest), int(reference.SizeBytes))
	if err != nil {
		return Reference{}, classifyObjectError("verify existing immutable Agent specification", err, ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return Reference{}, errors.Wrap(err, "verify existing immutable Agent specification")
	}
	if int64(len(existing)) != reference.SizeBytes || !bytes.Equal(existing, encoded) {
		return Reference{}, errors.Wrap(ErrIntegrity, "verify existing immutable Agent specification")
	}
	return reference, nil
}

// StageAgentSpecificationBody conditionally writes and reads back an identity-free Agent specification body before state admission.
func (store *Store) StageAgentSpecificationBody(ctx context.Context, tenant TenantID, body AgentSpecificationBody) (ContentHandoff, error) {
	if !validTenantID(tenant) {
		return ContentHandoff{}, errors.New("stage Agent specification body: invalid runtime content owner")
	}
	if err := ctx.Err(); err != nil {
		return ContentHandoff{}, errors.Wrap(err, "stage Agent specification body")
	}
	encoded, err := encodeAgentSpecificationBody(body)
	if err != nil {
		return ContentHandoff{}, err
	}
	reference := referenceForMediaType(encoded, AgentSpecificationBodyMediaTypeV1)
	if err := store.putVerified(ctx, tenant, reference, encoded, "stage Agent specification body"); err != nil {
		return ContentHandoff{}, err
	}
	return ContentHandoff{issuer: store, tenant: tenant, reference: reference, kind: contentKindAgentSpecificationBody, name: body.Name, modelProfile: body.ModelProfile}, nil
}

// ValidateAgentSpecificationBodyHandoff returns metadata only when this Store issued an intact tenant-bound body handoff.
func (store *Store) ValidateAgentSpecificationBodyHandoff(handoff ContentHandoff) (AgentSpecificationBodyCommitment, error) {
	if store == nil || handoff.issuer != store || handoff.kind != contentKindAgentSpecificationBody || !validTenantID(handoff.tenant) || !validAgentSpecificationBodyReference(handoff.reference) || !validName(handoff.name) || !validName(handoff.modelProfile) {
		return AgentSpecificationBodyCommitment{}, ErrNotFoundOrDenied
	}
	return AgentSpecificationBodyCommitment{Tenant: handoff.tenant, Reference: handoff.reference, Name: handoff.name, ModelProfile: handoff.modelProfile}, nil
}

// StageInputEnvelope conditionally writes and reads back a canonical Input envelope before state admission.
func (store *Store) StageInputEnvelope(ctx context.Context, tenant TenantID, parts []agentruntime.ContentPart) (ContentHandoff, error) {
	if !validTenantID(tenant) {
		return ContentHandoff{}, errors.New("stage Input envelope: invalid runtime content owner")
	}
	if err := ctx.Err(); err != nil {
		return ContentHandoff{}, errors.Wrap(err, "stage Input envelope")
	}
	encoded, err := encodeInputEnvelope(parts)
	if err != nil {
		return ContentHandoff{}, err
	}
	reference := referenceForMediaType(encoded, InputEnvelopeMediaTypeV1)
	if err := store.putVerified(ctx, tenant, reference, encoded, "stage Input envelope"); err != nil {
		return ContentHandoff{}, err
	}
	return ContentHandoff{issuer: store, tenant: tenant, reference: reference, kind: contentKindInputEnvelope}, nil
}

// ValidateInputEnvelopeHandoff returns metadata only when this Store issued an intact tenant-bound Input handoff.
func (store *Store) ValidateInputEnvelopeHandoff(handoff ContentHandoff) (InputEnvelopeCommitment, error) {
	if store == nil || handoff.issuer != store || handoff.kind != contentKindInputEnvelope || !validTenantID(handoff.tenant) || !validInputEnvelopeReference(handoff.reference) || handoff.name != "" || handoff.modelProfile != "" {
		return InputEnvelopeCommitment{}, ErrNotFoundOrDenied
	}
	return InputEnvelopeCommitment{Tenant: handoff.tenant, Reference: handoff.reference}, nil
}

// StageArtifact conditionally stores bounded immutable artifact bytes before
// state admission.  The caller receives only an opaque handoff, never a key.
func (store *Store) StageArtifact(ctx context.Context, tenant TenantID, mediaType string, data []byte) (ContentHandoff, error) {
	if !validTenantID(tenant) || !validArtifactMediaType(mediaType) || len(data) == 0 || len(data) > maximumArtifactBytes {
		return ContentHandoff{}, errors.New("stage Artifact: invalid immutable content")
	}
	if err := ctx.Err(); err != nil {
		return ContentHandoff{}, errors.Wrap(err, "stage Artifact")
	}
	copyData := append([]byte(nil), data...)
	reference := referenceForMediaType(copyData, mediaType)
	if err := store.putVerified(ctx, tenant, reference, copyData, "stage Artifact"); err != nil {
		return ContentHandoff{}, err
	}
	return ContentHandoff{issuer: store, tenant: tenant, reference: reference, kind: contentKindArtifact}, nil
}

// ValidateArtifactHandoff returns digest metadata only for an intact handoff
// issued by this exact Store.
func (store *Store) ValidateArtifactHandoff(handoff ContentHandoff) (ArtifactCommitment, error) {
	if store == nil || handoff.issuer != store || handoff.kind != contentKindArtifact || !validTenantID(handoff.tenant) || !validArtifactReference(handoff.reference) || handoff.name != "" || handoff.modelProfile != "" {
		return ArtifactCommitment{}, ErrNotFoundOrDenied
	}
	return ArtifactCommitment{Tenant: handoff.tenant, Reference: handoff.reference}, nil
}

// StageConversationEntry stores one bounded opaque semantic-context entry.
// State admission supplies identity and optimistic versioning separately.
func (store *Store) StageConversationEntry(ctx context.Context, tenant TenantID, body []byte) (ContentHandoff, error) {
	if !validTenantID(tenant) || len(body) == 0 || len(body) > maximumConversationEntryBytes {
		return ContentHandoff{}, errors.New("stage conversation entry: invalid immutable content")
	}
	if err := ctx.Err(); err != nil {
		return ContentHandoff{}, errors.Wrap(err, "stage conversation entry")
	}
	copyBody := append([]byte(nil), body...)
	reference := referenceForMediaType(copyBody, ConversationEntryMediaTypeV1)
	if err := store.putVerified(ctx, tenant, reference, copyBody, "stage conversation entry"); err != nil {
		return ContentHandoff{}, err
	}
	return ContentHandoff{issuer: store, tenant: tenant, reference: reference, kind: contentKindConversationEntry}, nil
}

// StageToolActionDescriptor stores one opaque immutable, adapter-authorized tool action descriptor.
func (store *Store) StageToolActionDescriptor(ctx context.Context, tenant TenantID, body []byte) (ContentHandoff, error) {
	if store == nil || !validTenantID(tenant) || len(body) == 0 || len(body) > maximumConversationEntryBytes {
		return ContentHandoff{}, ErrNotFoundOrDenied
	}
	copyBody := append([]byte(nil), body...)
	reference := referenceForMediaType(copyBody, ToolActionDescriptorMediaTypeV1)
	if err := store.putVerified(ctx, tenant, reference, copyBody, "stage tool action descriptor"); err != nil {
		return ContentHandoff{}, err
	}
	return ContentHandoff{issuer: store, tenant: tenant, reference: reference, kind: contentKindToolActionDescriptor}, nil
}
func (store *Store) ValidateToolActionDescriptorHandoff(h ContentHandoff) (ToolActionDescriptorCommitment, error) {
	if store == nil || h.issuer != store || h.kind != contentKindToolActionDescriptor || !validTenantID(h.tenant) || h.reference.MediaType != ToolActionDescriptorMediaTypeV1 || h.reference.SizeBytes <= 0 || h.reference.SizeBytes > maximumConversationEntryBytes || !validDigest(h.reference.Digest) {
		return ToolActionDescriptorCommitment{}, ErrNotFoundOrDenied
	}
	return ToolActionDescriptorCommitment{Tenant: h.tenant, Reference: h.reference}, nil
}

// ValidateConversationEntryHandoff returns only a tenant-bound immutable
// reference issued by this exact Store.
func (store *Store) ValidateConversationEntryHandoff(handoff ContentHandoff) (ConversationEntryCommitment, error) {
	if store == nil || handoff.issuer != store || handoff.kind != contentKindConversationEntry || !validTenantID(handoff.tenant) || !validConversationEntryReference(handoff.reference) || handoff.name != "" || handoff.modelProfile != "" {
		return ConversationEntryCommitment{}, ErrNotFoundOrDenied
	}
	return ConversationEntryCommitment{Tenant: handoff.tenant, Reference: handoff.reference}, nil
}

func (store *Store) getAgentSpecification(ctx context.Context, locator agentSpecificationLocator) (agentruntime.AgentSpecification, error) {
	if !validLocator(locator) {
		return agentruntime.AgentSpecification{}, ErrNotFoundOrDenied
	}
	if err := ctx.Err(); err != nil {
		return agentruntime.AgentSpecification{}, errors.Wrap(err, "read Agent specification")
	}
	raw, err := store.objects.Get(ctx, store.key(locator.tenant, locator.reference.Digest), int(locator.reference.SizeBytes))
	if err != nil {
		return agentruntime.AgentSpecification{}, classifyObjectError("read immutable Agent specification", err, ErrNotFoundOrDenied)
	}
	if err := ctx.Err(); err != nil {
		return agentruntime.AgentSpecification{}, errors.Wrap(err, "read Agent specification")
	}
	if int64(len(raw)) != locator.reference.SizeBytes || referenceFor(raw).Digest != locator.reference.Digest {
		return agentruntime.AgentSpecification{}, ErrIntegrity
	}
	specification, err := decode(raw)
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.Wrap(ErrIntegrity, "decode immutable Agent specification")
	}
	if specification.ID != locator.agentID || specification.RevisionID != locator.revisionID || specification.Revision != locator.revision {
		return agentruntime.AgentSpecification{}, ErrNotFoundOrDenied
	}
	return specification, nil
}

func (store *Store) getAgentSpecificationBody(ctx context.Context, locator agentSpecificationBodyLocator) (agentruntime.AgentSpecification, error) {
	record := locator.record
	if !validTenantID(record.Tenant) || !validAgentRevision(record.AgentID, record.RevisionID, record.Revision) || !validName(record.Name) || !validName(record.ModelProfile) || !validAgentSpecificationBodyReference(record.Reference) || record.CreatedAt.IsZero() || record.CreatedAt.Location() != time.UTC {
		return agentruntime.AgentSpecification{}, ErrNotFoundOrDenied
	}
	if err := ctx.Err(); err != nil {
		return agentruntime.AgentSpecification{}, errors.Wrap(err, "read Agent specification body")
	}
	raw, err := store.objects.Get(ctx, store.key(record.Tenant, record.Reference.Digest), int(record.Reference.SizeBytes))
	if err != nil {
		return agentruntime.AgentSpecification{}, classifyObjectError("read immutable Agent specification body", err, ErrNotFoundOrDenied)
	}
	if err := ctx.Err(); err != nil {
		return agentruntime.AgentSpecification{}, errors.Wrap(err, "read Agent specification body")
	}
	if int64(len(raw)) != record.Reference.SizeBytes || referenceForMediaType(raw, AgentSpecificationBodyMediaTypeV1).Digest != record.Reference.Digest {
		return agentruntime.AgentSpecification{}, ErrIntegrity
	}
	body, err := decodeAgentSpecificationBody(raw)
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.Wrap(ErrIntegrity, "decode immutable Agent specification body")
	}
	if body.Name != record.Name || body.ModelProfile != record.ModelProfile {
		return agentruntime.AgentSpecification{}, ErrNotFoundOrDenied
	}
	return agentruntime.AgentSpecification{ID: record.AgentID, RevisionID: record.RevisionID, Revision: record.Revision, Name: record.Name, ModelProfile: record.ModelProfile, Instructions: body.Instructions, Tools: append([]agentruntime.ToolDefinition(nil), body.Tools...), CreatedAt: record.CreatedAt.UTC()}, nil
}

func (store *Store) getInputEnvelope(ctx context.Context, locator inputEnvelopeLocator) ([]agentruntime.ContentPart, error) {
	record := locator.record
	if !validInputEnvelopeRecord(record) {
		return nil, ErrNotFoundOrDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "read Input envelope")
	}
	raw, err := store.objects.Get(ctx, store.key(record.Tenant, record.Reference.Digest), int(record.Reference.SizeBytes))
	if err != nil {
		return nil, classifyObjectError("read immutable Input envelope", err, ErrNotFoundOrDenied)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "read Input envelope")
	}
	if int64(len(raw)) != record.Reference.SizeBytes || referenceForMediaType(raw, InputEnvelopeMediaTypeV1).Digest != record.Reference.Digest {
		return nil, ErrIntegrity
	}
	parts, err := decodeInputEnvelope(raw)
	if err != nil {
		return nil, errors.Wrap(ErrIntegrity, "decode immutable Input envelope")
	}
	return parts, nil
}

func (store *Store) getArtifact(ctx context.Context, locator artifactLocator) ([]byte, error) {
	record := locator.record
	if !validArtifactRecord(record) {
		return nil, ErrNotFoundOrDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "read Artifact")
	}
	raw, err := store.objects.Get(ctx, store.key(record.Tenant, record.Reference.Digest), int(record.Reference.SizeBytes))
	if err != nil {
		return nil, classifyObjectError("read immutable Artifact", err, ErrNotFoundOrDenied)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "read Artifact")
	}
	if int64(len(raw)) != record.Reference.SizeBytes || referenceForMediaType(raw, record.Reference.MediaType).Digest != record.Reference.Digest {
		return nil, ErrIntegrity
	}
	return append([]byte(nil), raw...), nil
}

func (store *Store) getToolActionDescriptor(ctx context.Context, locator toolActionDescriptorLocator) ([]byte, error) {
	commitment := locator.commitment
	if !validTenantID(commitment.Tenant) || !validToolActionDescriptorReference(commitment.Reference) {
		return nil, ErrNotFoundOrDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "read tool action descriptor")
	}
	raw, err := store.objects.Get(ctx, store.key(commitment.Tenant, commitment.Reference.Digest), int(commitment.Reference.SizeBytes))
	if err != nil {
		return nil, classifyObjectError("read immutable tool action descriptor", err, ErrNotFoundOrDenied)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "read tool action descriptor")
	}
	if int64(len(raw)) != commitment.Reference.SizeBytes || referenceForMediaType(raw, ToolActionDescriptorMediaTypeV1).Digest != commitment.Reference.Digest {
		return nil, ErrIntegrity
	}
	return append([]byte(nil), raw...), nil
}

func (store *Store) key(tenant TenantID, digest string) string {
	return string(tenant) + "/" + store.contentRoot + "/v1/sha256/" + strings.TrimPrefix(digest, "sha256:")
}

func referenceFor(encoded []byte) Reference {
	return referenceForMediaType(encoded, AgentSpecificationMediaTypeV1)
}

func referenceForMediaType(encoded []byte, mediaType string) Reference {
	sum := sha256.Sum256(encoded)
	return Reference{Digest: "sha256:" + hex.EncodeToString(sum[:]), MediaType: mediaType, SizeBytes: int64(len(encoded))}
}

func (store *Store) putVerified(ctx context.Context, tenant TenantID, reference Reference, encoded []byte, action string) error {
	_, err := store.objects.PutIfAbsent(ctx, store.key(tenant, reference.Digest), encoded)
	if err != nil {
		return classifyObjectError("store immutable "+action, err, ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, action)
	}
	existing, err := store.objects.Get(ctx, store.key(tenant, reference.Digest), int(reference.SizeBytes))
	if err != nil {
		return classifyObjectError("verify immutable "+action, err, ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, action)
	}
	if int64(len(existing)) != reference.SizeBytes || referenceForMediaType(existing, reference.MediaType).Digest != reference.Digest || !bytes.Equal(existing, encoded) {
		return errors.Wrap(ErrIntegrity, "verify immutable "+action)
	}
	return nil
}

func validLocator(locator agentSpecificationLocator) bool {
	return validTenantID(locator.tenant) && validAgentRevision(locator.agentID, locator.revisionID, locator.revision) && validReference(locator.reference)
}

func validTenantID(value TenantID) bool {
	return validSegment(string(value), maximumTenantIDBytes)
}

func validPrincipalID(value PrincipalID) bool {
	return validSegment(string(value), maximumTenantIDBytes)
}

func validContentRoot(value string) bool {
	if len(value) == 0 || len(value) > maximumContentRootBytes || strings.ContainsAny(value, "\\\x00\n\r") || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if !validSegment(segment, maximumContentRootBytes) || segment == "temporal-payload" {
			return false
		}
	}
	return true
}

func validSegment(value string, maximumBytes int) bool {
	if value == "" || value == "." || value == ".." || len(value) > maximumBytes || !utf8.ValidString(value) {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || (index > 0 && (character == '-' || character == '_')) {
			continue
		}
		return false
	}
	return true
}

func validAgentRevision(agentID agentruntime.AgentID, revisionID agentruntime.AgentRevisionID, revision uint64) bool {
	if revision == 0 {
		return false
	}
	if _, err := agentruntime.ParseAgentID(agentID.String()); err != nil {
		return false
	}
	_, err := agentruntime.ParseAgentRevisionID(revisionID.String())
	return err == nil
}

func validReference(reference Reference) bool {
	return reference.MediaType == AgentSpecificationMediaTypeV1 && reference.SizeBytes > 0 && reference.SizeBytes <= maximumSpecificationBytes && validDigest(reference.Digest)
}

func validAgentSpecificationBodyReference(reference Reference) bool {
	return reference.MediaType == AgentSpecificationBodyMediaTypeV1 && reference.SizeBytes > 0 && reference.SizeBytes <= maximumSpecificationBytes && validDigest(reference.Digest)
}

func validInputEnvelopeReference(reference Reference) bool {
	return reference.MediaType == InputEnvelopeMediaTypeV1 && reference.SizeBytes > 0 && reference.SizeBytes <= maximumInputEnvelopeBytes && validDigest(reference.Digest)
}

func validArtifactReference(reference Reference) bool {
	return validArtifactMediaType(reference.MediaType) && reference.SizeBytes > 0 && reference.SizeBytes <= maximumArtifactBytes && validDigest(reference.Digest)
}

func validConversationEntryReference(reference Reference) bool {
	return reference.MediaType == ConversationEntryMediaTypeV1 && reference.SizeBytes > 0 && reference.SizeBytes <= maximumConversationEntryBytes && validDigest(reference.Digest)
}

func validToolActionDescriptorReference(reference Reference) bool {
	return reference.MediaType == ToolActionDescriptorMediaTypeV1 && reference.SizeBytes > 0 && reference.SizeBytes <= maximumConversationEntryBytes && validDigest(reference.Digest)
}

func validToolCallID(value string) bool {
	return value != "" && len(value) <= 128 && utf8.ValidString(value) && !strings.ContainsAny(value, "\\\x00\r\n")
}

func validArtifactMediaType(value string) bool {
	return value != "" && len(value) <= maximumArtifactMediaTypeBytes && utf8.ValidString(value) && !strings.ContainsAny(value, "\\\x00\r\n")
}

func validInputEnvelopeRecord(record InputEnvelopeRecord) bool {
	if !validTenantID(record.Tenant) || !validPrincipalID(record.Principal) || !validInputEnvelopeReference(record.Reference) {
		return false
	}
	if _, err := agentruntime.ParseSessionID(record.SessionID.String()); err != nil {
		return false
	}
	_, err := agentruntime.ParseInputID(record.InputID.String())
	return err == nil
}

func validArtifactRecord(record ArtifactRecord) bool {
	if !validTenantID(record.Tenant) || !validPrincipalID(record.Principal) || !validArtifactReference(record.Reference) {
		return false
	}
	_, err := agentruntime.ParseArtifactID(record.ArtifactID.String())
	return err == nil
}

func validDigest(value string) bool {
	return len(value) == 71 && strings.HasPrefix(value, "sha256:") && strings.Trim(value[7:], "0123456789abcdef") == ""
}

func classifyObjectError(action string, err error, fallback error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Wrap(err, action)
	}
	if errors.Is(err, ErrIntegrity) {
		return errors.Wrap(ErrIntegrity, action)
	}
	if errors.Is(err, ErrNotFoundOrDenied) {
		return errors.Wrap(fallback, action)
	}
	return errors.Wrap(ErrUnavailable, action)
}

func encode(specification agentruntime.AgentSpecification) ([]byte, error) {
	if err := validate(specification); err != nil {
		return nil, err
	}
	var encoded bytes.Buffer
	hasSchemas := hasToolSchemas(specification.Tools)
	head(&encoded, 4, 9)
	if hasSchemas {
		uintv(&encoded, 2)
	} else {
		uintv(&encoded, 1)
	}
	text(&encoded, specification.ID.String())
	text(&encoded, specification.RevisionID.String())
	uintv(&encoded, specification.Revision)
	text(&encoded, specification.Name)
	text(&encoded, specification.ModelProfile)
	text(&encoded, specification.Instructions)
	head(&encoded, 4, uint64(len(specification.Tools)))
	for _, tool := range specification.Tools {
		if hasSchemas {
			version, schema, err := toolschema.CanonicalSchema(tool.InputSchemaVersion, tool.InputSchema)
			if err != nil {
				return nil, err
			}
			head(&encoded, 4, 4)
			text(&encoded, tool.Name)
			text(&encoded, tool.Description)
			text(&encoded, version)
			text(&encoded, string(schema))
		} else {
			head(&encoded, 4, 2)
			text(&encoded, tool.Name)
			text(&encoded, tool.Description)
		}
	}
	text(&encoded, specification.CreatedAt.UTC().Format(time.RFC3339Nano))
	if encoded.Len() > maximumSpecificationBytes {
		return nil, errors.New("canonical Agent specification exceeds bound")
	}
	return encoded.Bytes(), nil
}

func encodeAgentSpecificationBody(body AgentSpecificationBody) ([]byte, error) {
	if err := validateAgentSpecificationBody(body); err != nil {
		return nil, err
	}
	var encoded bytes.Buffer
	hasSchemas := hasToolSchemas(body.Tools)
	head(&encoded, 4, 5)
	if hasSchemas {
		uintv(&encoded, 2)
	} else {
		uintv(&encoded, 1)
	}
	text(&encoded, body.Name)
	text(&encoded, body.ModelProfile)
	text(&encoded, body.Instructions)
	head(&encoded, 4, uint64(len(body.Tools)))
	for _, tool := range body.Tools {
		if hasSchemas {
			version, schema, err := toolschema.CanonicalSchema(tool.InputSchemaVersion, tool.InputSchema)
			if err != nil {
				return nil, err
			}
			head(&encoded, 4, 4)
			text(&encoded, tool.Name)
			text(&encoded, tool.Description)
			text(&encoded, version)
			text(&encoded, string(schema))
		} else {
			head(&encoded, 4, 2)
			text(&encoded, tool.Name)
			text(&encoded, tool.Description)
		}
	}
	if encoded.Len() > maximumSpecificationBytes {
		return nil, errors.New("canonical Agent specification body exceeds bound")
	}
	return encoded.Bytes(), nil
}

func hasToolSchemas(tools []agentruntime.ToolDefinition) bool {
	for _, tool := range tools {
		if tool.InputSchemaVersion != "" || len(tool.InputSchema) != 0 {
			return true
		}
	}
	return false
}

func encodeInputEnvelope(parts []agentruntime.ContentPart) ([]byte, error) {
	if err := validateInputEnvelope(parts); err != nil {
		return nil, err
	}
	var encoded bytes.Buffer
	head(&encoded, 4, 2)
	uintv(&encoded, 1)
	head(&encoded, 4, uint64(len(parts)))
	for _, part := range parts {
		head(&encoded, 4, 2)
		switch part.Kind {
		case agentruntime.ContentText:
			uintv(&encoded, 1)
			text(&encoded, part.Text)
		case agentruntime.ContentArtifact:
			uintv(&encoded, 2)
			head(&encoded, 4, 4)
			text(&encoded, part.Artifact.ID.String())
			text(&encoded, part.Artifact.MediaType)
			uintv(&encoded, uint64(part.Artifact.SizeBytes))
			text(&encoded, part.Artifact.SHA256)
		default:
			return nil, errors.New("unsupported Input envelope part")
		}
	}
	if encoded.Len() > maximumInputEnvelopeBytes {
		return nil, errors.New("canonical Input envelope exceeds bound")
	}
	return encoded.Bytes(), nil
}

func decodeInputEnvelope(raw []byte) ([]agentruntime.ContentPart, error) {
	if len(raw) == 0 || len(raw) > maximumInputEnvelopeBytes {
		return nil, errors.New("invalid Input envelope")
	}
	decoder := decoder{raw: raw}
	major, count, err := decoder.head()
	if err != nil || major != 4 || count != 2 {
		return nil, errors.New("invalid Input envelope")
	}
	if version, err := decoder.uint(); err != nil || version != 1 {
		return nil, errors.New("unsupported Input envelope version")
	}
	major, count, err = decoder.head()
	if err != nil || major != 4 || count == 0 || count > agentruntime.MaxInputParts {
		return nil, errors.New("invalid Input envelope parts")
	}
	parts := make([]agentruntime.ContentPart, 0, count)
	for index := uint64(0); index < count; index++ {
		major, fields, err := decoder.head()
		if err != nil || major != 4 || fields != 2 {
			return nil, errors.New("invalid Input envelope part")
		}
		kind, err := decoder.uint()
		if err != nil {
			return nil, errors.New("invalid Input envelope part kind")
		}
		switch kind {
		case 1:
			value, err := decoder.text()
			if err != nil {
				return nil, errors.New("invalid Input envelope text part")
			}
			parts = append(parts, agentruntime.ContentPart{Kind: agentruntime.ContentText, Text: value})
		case 2:
			major, fields, err := decoder.head()
			if err != nil || major != 4 || fields != 4 {
				return nil, errors.New("invalid Input envelope artifact part")
			}
			id, err := decoder.text()
			if err != nil {
				return nil, errors.New("invalid Input envelope artifact part")
			}
			mediaType, err := decoder.text()
			if err != nil {
				return nil, errors.New("invalid Input envelope artifact part")
			}
			sizeBytes, err := decoder.uint()
			if err != nil || sizeBytes > uint64(^uint64(0)>>1) {
				return nil, errors.New("invalid Input envelope artifact size")
			}
			digest, err := decoder.text()
			if err != nil {
				return nil, errors.New("invalid Input envelope artifact part")
			}
			parts = append(parts, agentruntime.ContentPart{Kind: agentruntime.ContentArtifact, Artifact: &agentruntime.ArtifactReference{ID: agentruntime.ArtifactID(id), MediaType: mediaType, SizeBytes: int64(sizeBytes), SHA256: digest}})
		default:
			return nil, errors.New("unsupported Input envelope part")
		}
	}
	if decoder.at != len(raw) {
		return nil, errors.New("invalid Input envelope")
	}
	if err := validateInputEnvelope(parts); err != nil {
		return nil, err
	}
	canonical, err := encodeInputEnvelope(parts)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, errors.New("noncanonical Input envelope")
	}
	return parts, nil
}

func decodeAgentSpecificationBody(raw []byte) (AgentSpecificationBody, error) {
	if len(raw) == 0 || len(raw) > maximumSpecificationBytes {
		return AgentSpecificationBody{}, errors.New("invalid Agent specification body")
	}
	decoder := decoder{raw: raw}
	major, count, err := decoder.head()
	if err != nil || major != 4 || count != 5 {
		return AgentSpecificationBody{}, errors.New("invalid Agent specification body envelope")
	}
	version, err := decoder.uint()
	if err != nil || (version != 1 && version != 2) {
		return AgentSpecificationBody{}, errors.New("unsupported Agent specification body version")
	}
	name, err := decoder.text()
	if err != nil {
		return AgentSpecificationBody{}, errors.New("invalid Agent specification body")
	}
	modelProfile, err := decoder.text()
	if err != nil {
		return AgentSpecificationBody{}, errors.New("invalid Agent specification body")
	}
	instructions, err := decoder.text()
	if err != nil {
		return AgentSpecificationBody{}, errors.New("invalid Agent specification body")
	}
	major, count, err = decoder.head()
	if err != nil || major != 4 || count > maximumTools {
		return AgentSpecificationBody{}, errors.New("invalid Agent specification body tools")
	}
	tools := make([]agentruntime.ToolDefinition, 0, count)
	for index := uint64(0); index < count; index++ {
		major, fields, err := decoder.head()
		if err != nil || major != 4 || (fields != 2 && (version != 2 || fields != 4)) {
			return AgentSpecificationBody{}, errors.New("invalid Agent specification body tool")
		}
		toolName, err := decoder.text()
		if err != nil {
			return AgentSpecificationBody{}, errors.New("invalid Agent specification body tool")
		}
		description, err := decoder.text()
		if err != nil {
			return AgentSpecificationBody{}, errors.New("invalid Agent specification body tool")
		}
		tool := agentruntime.ToolDefinition{Name: toolName, Description: description}
		if version == 2 {
			tool.InputSchemaVersion, err = decoder.text()
			if err != nil {
				return AgentSpecificationBody{}, errors.New("invalid Agent specification body tool")
			}
			schema, readErr := decoder.text()
			if readErr != nil {
				return AgentSpecificationBody{}, errors.New("invalid Agent specification body tool")
			}
			tool.InputSchema = []byte(schema)
		}
		tools = append(tools, tool)
	}
	if decoder.at != len(raw) {
		return AgentSpecificationBody{}, errors.New("invalid Agent specification body")
	}
	body := AgentSpecificationBody{Name: name, ModelProfile: modelProfile, Instructions: instructions, Tools: tools}
	canonical, err := encodeAgentSpecificationBody(body)
	if err != nil || (version == 2 && !bytes.Equal(canonical, raw)) {
		return AgentSpecificationBody{}, errors.New("noncanonical Agent specification body")
	}
	return body, nil
}

func decode(raw []byte) (agentruntime.AgentSpecification, error) {
	if len(raw) == 0 || len(raw) > maximumSpecificationBytes {
		return agentruntime.AgentSpecification{}, errors.New("invalid canonical Agent specification")
	}
	decoder := decoder{raw: raw}
	major, count, err := decoder.head()
	if err != nil || major != 4 || count != 9 {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification envelope")
	}
	version, err := decoder.uint()
	if err != nil || (version != 1 && version != 2) {
		return agentruntime.AgentSpecification{}, errors.New("unsupported Agent specification version")
	}
	id, err := decoder.text()
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	revisionID, err := decoder.text()
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	revision, err := decoder.uint()
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	name, err := decoder.text()
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	model, err := decoder.text()
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	instructions, err := decoder.text()
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	major, count, err = decoder.head()
	if err != nil || major != 4 || count > maximumTools {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification tools")
	}
	tools := make([]agentruntime.ToolDefinition, 0, count)
	for index := uint64(0); index < count; index++ {
		major, fields, err := decoder.head()
		if err != nil || major != 4 || (fields != 2 && (version != 2 || fields != 4)) {
			return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification tool")
		}
		name, err := decoder.text()
		if err != nil {
			return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification tool")
		}
		description, err := decoder.text()
		if err != nil {
			return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification tool")
		}
		tool := agentruntime.ToolDefinition{Name: name, Description: description}
		if version == 2 {
			tool.InputSchemaVersion, err = decoder.text()
			if err != nil {
				return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification tool")
			}
			schema, readErr := decoder.text()
			if readErr != nil {
				return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification tool")
			}
			tool.InputSchema = []byte(schema)
		}
		tools = append(tools, tool)
	}
	createdAt, err := decoder.text()
	if err != nil || decoder.at != len(raw) {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	agentID, err := agentruntime.ParseAgentID(id)
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	agentRevisionID, err := agentruntime.ParseAgentRevisionID(revisionID)
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	parsedCreatedAt, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil || parsedCreatedAt.Location() != time.UTC {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	specification := agentruntime.AgentSpecification{ID: agentID, RevisionID: agentRevisionID, Revision: revision, Name: name, ModelProfile: model, Instructions: instructions, Tools: tools, CreatedAt: parsedCreatedAt}
	canonical, err := encode(specification)
	if err != nil || (version == 2 && !bytes.Equal(canonical, raw)) {
		return agentruntime.AgentSpecification{}, errors.New("noncanonical Agent specification")
	}
	return specification, nil
}

func validate(specification agentruntime.AgentSpecification) error {
	if !validAgentRevision(specification.ID, specification.RevisionID, specification.Revision) || !validName(specification.Name) || !validName(specification.ModelProfile) || !validText(specification.Instructions, maximumInstructionsBytes) || specification.CreatedAt.IsZero() || specification.CreatedAt.Location() != time.UTC || len(specification.Tools) > maximumTools {
		return errors.New("invalid Agent specification")
	}
	seenTools := make(map[string]struct{}, len(specification.Tools))
	for _, tool := range specification.Tools {
		if !validName(tool.Name) || !validText(tool.Description, maximumToolDescriptionBytes) {
			return errors.New("invalid Agent specification")
		}
		if _, _, err := toolschema.CanonicalSchema(tool.InputSchemaVersion, tool.InputSchema); err != nil {
			return errors.New("invalid Agent specification")
		}
		if _, found := seenTools[tool.Name]; found {
			return errors.New("invalid Agent specification")
		}
		seenTools[tool.Name] = struct{}{}
	}
	return nil
}

func validateAgentSpecificationBody(body AgentSpecificationBody) error {
	if !validName(body.Name) || !validName(body.ModelProfile) || !validText(body.Instructions, maximumInstructionsBytes) || len(body.Tools) > maximumTools {
		return errors.New("invalid Agent specification body")
	}
	seenTools := make(map[string]struct{}, len(body.Tools))
	for _, tool := range body.Tools {
		if !validName(tool.Name) || !validText(tool.Description, maximumToolDescriptionBytes) {
			return errors.New("invalid Agent specification body")
		}
		if _, _, err := toolschema.CanonicalSchema(tool.InputSchemaVersion, tool.InputSchema); err != nil {
			return errors.New("invalid Agent specification body")
		}
		if _, found := seenTools[tool.Name]; found {
			return errors.New("invalid Agent specification body")
		}
		seenTools[tool.Name] = struct{}{}
	}
	return nil
}

func validateInputEnvelope(parts []agentruntime.ContentPart) error {
	if len(parts) == 0 || len(parts) > agentruntime.MaxInputParts {
		return errors.New("invalid Input envelope part count")
	}
	for _, part := range parts {
		switch part.Kind {
		case agentruntime.ContentText:
			if !validText(part.Text, agentruntime.MaxTextPartBytes) || part.Artifact != nil {
				return errors.New("invalid Input envelope text part")
			}
		case agentruntime.ContentArtifact:
			if part.Text != "" || part.Artifact == nil || part.Artifact.SizeBytes < 0 || !validText(part.Artifact.MediaType, 255) || len(part.Artifact.SHA256) != 64 || strings.Trim(part.Artifact.SHA256, "0123456789abcdef") != "" {
				return errors.New("invalid Input envelope artifact part")
			}
			if _, err := agentruntime.ParseArtifactID(part.Artifact.ID.String()); err != nil {
				return errors.New("invalid Input envelope artifact part")
			}
		default:
			return errors.New("unsupported Input envelope part")
		}
	}
	return nil
}

func validName(value string) bool {
	if len(value) == 0 || len(value) > maximumNameBytes {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func validText(value string, maximumBytes int) bool {
	return len(value) > 0 && len(value) <= maximumBytes && utf8.ValidString(value)
}

type decoder struct {
	raw []byte
	at  int
}

func (decoder *decoder) head() (byte, uint64, error) {
	if decoder.at >= len(decoder.raw) {
		return 0, 0, errors.New("truncated CBOR")
	}
	first := decoder.raw[decoder.at]
	decoder.at++
	major := first >> 5
	value := uint64(first & 31)
	if value < 24 {
		return major, value, nil
	}
	width := 0
	switch value {
	case 24:
		width = 1
	case 25:
		width = 2
	case 26:
		width = 4
	case 27:
		width = 8
	default:
		return 0, 0, errors.New("indefinite CBOR")
	}
	if decoder.at+width > len(decoder.raw) {
		return 0, 0, errors.New("truncated CBOR")
	}
	value = 0
	for index := 0; index < width; index++ {
		value = value<<8 | uint64(decoder.raw[decoder.at])
		decoder.at++
	}
	if (width == 1 && value < 24) || (width == 2 && value <= 255) || (width == 4 && value <= 65535) || (width == 8 && value <= 0xffffffff) {
		return 0, 0, errors.New("noncanonical CBOR")
	}
	return major, value, nil
}

func (decoder *decoder) uint() (uint64, error) {
	major, value, err := decoder.head()
	if err != nil || major != 0 {
		return 0, errors.New("invalid CBOR uint")
	}
	return value, nil
}

func (decoder *decoder) text() (string, error) {
	major, count, err := decoder.head()
	if err != nil || major != 3 || count > uint64(len(decoder.raw)-decoder.at) {
		return "", errors.New("invalid CBOR text")
	}
	value := string(decoder.raw[decoder.at : decoder.at+int(count)])
	decoder.at += int(count)
	if !utf8.ValidString(value) {
		return "", errors.New("invalid UTF-8 CBOR text")
	}
	return value, nil
}

func head(buffer *bytes.Buffer, major byte, value uint64) {
	if value < 24 {
		buffer.WriteByte(major<<5 | byte(value))
		return
	}
	if value <= 255 {
		buffer.WriteByte(major<<5 | 24)
		buffer.WriteByte(byte(value))
		return
	}
	if value <= 65535 {
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

func uintv(buffer *bytes.Buffer, value uint64) {
	head(buffer, 0, value)
}

func text(buffer *bytes.Buffer, value string) {
	head(buffer, 3, uint64(len(value)))
	buffer.WriteString(value)
}
