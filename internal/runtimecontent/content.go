// Package runtimecontent owns runtime-scoped immutable Agent specification content.
package runtimecontent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf8"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

const (
	// AgentSpecificationMediaTypeV1 identifies the canonical Agent specification envelope.
	AgentSpecificationMediaTypeV1 = "application/vnd.agent-runtime.agent-specification+cbor;version=1"
	maximumSpecificationBytes     = 1 << 20
	maximumInstructionsBytes      = 256 * 1024
	maximumToolDescriptionBytes   = 4096
	maximumNameBytes              = 128
	maximumTools                  = 64
	maximumTenantIDBytes          = 128
	maximumContentRootBytes       = 128
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

// Reference contains immutable content metadata without a storage key.
type Reference struct {
	Digest    string
	MediaType string
	SizeBytes int64
}

// ImmutableObjectStore conditionally stores and bounded-reads runtime-owned immutable bytes.
// A false created result requires Store to verify the existing object before success.
type ImmutableObjectStore interface {
	PutIfAbsent(context.Context, string, []byte) (created bool, err error)
	Get(context.Context, string, int) ([]byte, error)
}

// AgentSpecificationLocatorIssuer issues opaque repository capabilities for Agent specifications.
type AgentSpecificationLocatorIssuer interface {
	IssueAgentSpecificationLocator(TenantID, agentruntime.AgentID, agentruntime.AgentRevisionID, uint64, Reference) (AgentSpecificationLocator, error)
}

// AgentSpecificationLocator is an opaque repository-issued capability for one immutable Agent revision.
type AgentSpecificationLocator struct {
	tenant     TenantID
	agentID    agentruntime.AgentID
	revisionID agentruntime.AgentRevisionID
	revision   uint64
	reference  Reference
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

// IssueAgentSpecificationLocator binds a repository capability to one tenant, Agent, and Agent revision.
func (store *Store) IssueAgentSpecificationLocator(tenant TenantID, agentID agentruntime.AgentID, revisionID agentruntime.AgentRevisionID, revision uint64, reference Reference) (AgentSpecificationLocator, error) {
	if !validTenantID(tenant) || !validAgentRevision(agentID, revisionID, revision) || !validReference(reference) {
		return AgentSpecificationLocator{}, errors.New("invalid Agent specification repository capability")
	}
	return AgentSpecificationLocator{tenant: tenant, agentID: agentID, revisionID: revisionID, revision: revision, reference: reference}, nil
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

// GetAgentSpecification reads only a repository-issued capability after integrity validation.
func (store *Store) GetAgentSpecification(ctx context.Context, locator AgentSpecificationLocator) (agentruntime.AgentSpecification, error) {
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

func (store *Store) key(tenant TenantID, digest string) string {
	return string(tenant) + "/" + store.contentRoot + "/v1/sha256/" + strings.TrimPrefix(digest, "sha256:")
}

func referenceFor(encoded []byte) Reference {
	sum := sha256.Sum256(encoded)
	return Reference{Digest: "sha256:" + hex.EncodeToString(sum[:]), MediaType: AgentSpecificationMediaTypeV1, SizeBytes: int64(len(encoded))}
}

func validLocator(locator AgentSpecificationLocator) bool {
	return validTenantID(locator.tenant) && validAgentRevision(locator.agentID, locator.revisionID, locator.revision) && validReference(locator.reference)
}

func validTenantID(value TenantID) bool {
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
	head(&encoded, 4, 9)
	uintv(&encoded, 1)
	text(&encoded, specification.ID.String())
	text(&encoded, specification.RevisionID.String())
	uintv(&encoded, specification.Revision)
	text(&encoded, specification.Name)
	text(&encoded, specification.ModelProfile)
	text(&encoded, specification.Instructions)
	head(&encoded, 4, uint64(len(specification.Tools)))
	for _, tool := range specification.Tools {
		head(&encoded, 4, 2)
		text(&encoded, tool.Name)
		text(&encoded, tool.Description)
	}
	text(&encoded, specification.CreatedAt.UTC().Format(time.RFC3339Nano))
	if encoded.Len() > maximumSpecificationBytes {
		return nil, errors.New("canonical Agent specification exceeds bound")
	}
	return encoded.Bytes(), nil
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
	if version, err := decoder.uint(); err != nil || version != 1 {
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
		if err != nil || major != 4 || fields != 2 {
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
		tools = append(tools, agentruntime.ToolDefinition{Name: name, Description: description})
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
	if err != nil || !bytes.Equal(canonical, raw) {
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
		if _, found := seenTools[tool.Name]; found {
			return errors.New("invalid Agent specification")
		}
		seenTools[tool.Name] = struct{}{}
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
