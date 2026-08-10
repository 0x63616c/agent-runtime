// Package runtimecontent owns runtime-scoped immutable Agent specification content.
package runtimecontent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

const (
	// AgentSpecificationMediaTypeV1 identifies the canonical Agent specification envelope.
	AgentSpecificationMediaTypeV1 = "application/vnd.agent-runtime.agent-specification+cbor;version=1"
	maximumSpecificationBytes     = 1 << 20
	maximumTools                  = 128
)

// Reference contains immutable content metadata without a storage key.
type Reference struct {
	Digest, MediaType string
	SizeBytes         int64
}

// ImmutableObjectStore conditionally stores and bounded-reads runtime-owned immutable bytes.
type ImmutableObjectStore interface {
	PutIfAbsent(context.Context, string, []byte) error
	Get(context.Context, string, int) ([]byte, error)
}

// Store owns one explicit runtime content namespace.
type Store struct {
	namespace string
	objects   ImmutableObjectStore
}
type locator struct {
	tenant    string
	reference Reference
}

// New constructs a Store from the declared runtime-content namespace and immutable object port.
func New(namespace string, objects ImmutableObjectStore) (*Store, error) {
	namespace = strings.Trim(namespace, "/")
	if objects == nil || namespace != "runtime-content" {
		return nil, errors.New("runtime content namespace and immutable object store are required")
	}
	return &Store{namespace: namespace, objects: objects}, nil
}

func (store *Store) locator(tenant string, reference Reference) locator {
	return locator{tenant: tenant, reference: reference}
}

// PutAgentSpecification canonically encodes and conditionally stores one immutable specification.
func (store *Store) PutAgentSpecification(ctx context.Context, tenant string, specification agentruntime.AgentSpecification) (Reference, error) {
	if !validTenant(tenant) {
		return Reference{}, errors.New("invalid runtime content owner")
	}
	if err := ctx.Err(); err != nil {
		return Reference{}, errors.Wrap(err, "store Agent specification")
	}
	encoded, err := encode(specification)
	if err != nil {
		return Reference{}, err
	}
	sum := sha256.Sum256(encoded)
	reference := Reference{Digest: "sha256:" + hex.EncodeToString(sum[:]), MediaType: AgentSpecificationMediaTypeV1, SizeBytes: int64(len(encoded))}
	if err := store.objects.PutIfAbsent(ctx, store.key(tenant, reference.Digest), encoded); err != nil {
		return Reference{}, errors.Wrap(err, "store immutable Agent specification")
	}
	return reference, nil
}

// GetAgentSpecification reads only a repository-issued locator after integrity validation.
func (store *Store) GetAgentSpecification(ctx context.Context, entry locator) (agentruntime.AgentSpecification, error) {
	if !validTenant(entry.tenant) || entry.reference.MediaType != AgentSpecificationMediaTypeV1 || entry.reference.SizeBytes <= 0 || entry.reference.SizeBytes > maximumSpecificationBytes || !validDigest(entry.reference.Digest) {
		return agentruntime.AgentSpecification{}, errors.New("runtime content not found or denied")
	}
	if err := ctx.Err(); err != nil {
		return agentruntime.AgentSpecification{}, errors.Wrap(err, "read Agent specification")
	}
	raw, err := store.objects.Get(ctx, store.key(entry.tenant, entry.reference.Digest), int(entry.reference.SizeBytes))
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("runtime content not found or denied")
	}
	if int64(len(raw)) != entry.reference.SizeBytes {
		return agentruntime.AgentSpecification{}, errors.New("runtime content integrity failure")
	}
	sum := sha256.Sum256(raw)
	if entry.reference.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		return agentruntime.AgentSpecification{}, errors.New("runtime content integrity failure")
	}
	return decode(raw)
}
func (store *Store) key(tenant, digest string) string {
	return tenant + "/" + store.namespace + "/v1/sha256/" + strings.TrimPrefix(digest, "sha256:")
}
func validTenant(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, "/\\\x00\n\r")
}
func validDigest(value string) bool {
	return len(value) == 71 && strings.HasPrefix(value, "sha256:") && strings.Trim(value[7:], "0123456789abcdef") == ""
}

func encode(s agentruntime.AgentSpecification) ([]byte, error) {
	if err := validate(s); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	head(&b, 4, 9)
	uintv(&b, 1)
	text(&b, s.ID.String())
	text(&b, s.RevisionID.String())
	uintv(&b, s.Revision)
	text(&b, s.Name)
	text(&b, s.ModelProfile)
	text(&b, s.Instructions)
	head(&b, 4, uint64(len(s.Tools)))
	for _, tool := range s.Tools {
		head(&b, 4, 2)
		text(&b, tool.Name)
		text(&b, tool.Description)
	}
	text(&b, s.CreatedAt.UTC().Format(time.RFC3339Nano))
	if b.Len() > maximumSpecificationBytes {
		return nil, errors.New("canonical Agent specification exceeds bound")
	}
	return b.Bytes(), nil
}
func decode(raw []byte) (agentruntime.AgentSpecification, error) {
	if len(raw) == 0 || len(raw) > maximumSpecificationBytes {
		return agentruntime.AgentSpecification{}, errors.New("invalid canonical Agent specification")
	}
	d := decoder{raw: raw}
	major, n, err := d.head()
	if err != nil || major != 4 || n != 9 {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification envelope")
	}
	if v, err := d.uint(); err != nil || v != 1 {
		return agentruntime.AgentSpecification{}, errors.New("unsupported Agent specification version")
	}
	id, err := d.text()
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	rid, err := d.text()
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	revision, err := d.uint()
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	name, err := d.text()
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	model, err := d.text()
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	instructions, err := d.text()
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	major, n, err = d.head()
	if err != nil || major != 4 || n > maximumTools {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification tools")
	}
	tools := make([]agentruntime.ToolDefinition, 0, n)
	for i := uint64(0); i < n; i++ {
		major, count, err := d.head()
		if err != nil || major != 4 || count != 2 {
			return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification tool")
		}
		tn, err := d.text()
		if err != nil {
			return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification tool")
		}
		td, err := d.text()
		if err != nil {
			return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification tool")
		}
		tools = append(tools, agentruntime.ToolDefinition{Name: tn, Description: td})
	}
	created, err := d.text()
	if err != nil || d.at != len(raw) {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	aid, err := agentruntime.ParseAgentID(id)
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	arid, err := agentruntime.ParseAgentRevisionID(rid)
	if err != nil {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	at, err := time.Parse(time.RFC3339Nano, created)
	if err != nil || at.Location() != time.UTC {
		return agentruntime.AgentSpecification{}, errors.New("invalid Agent specification")
	}
	result := agentruntime.AgentSpecification{ID: aid, RevisionID: arid, Revision: revision, Name: name, ModelProfile: model, Instructions: instructions, Tools: tools, CreatedAt: at}
	canonical, err := encode(result)
	if err != nil || !bytes.Equal(canonical, raw) {
		return agentruntime.AgentSpecification{}, errors.New("noncanonical Agent specification")
	}
	return result, nil
}
func validate(s agentruntime.AgentSpecification) error {
	if _, err := agentruntime.ParseAgentID(s.ID.String()); err != nil {
		return errors.New("invalid Agent specification")
	}
	if _, err := agentruntime.ParseAgentRevisionID(s.RevisionID.String()); err != nil || s.Revision == 0 || s.Name == "" || s.ModelProfile == "" || s.Instructions == "" || s.CreatedAt.IsZero() || s.CreatedAt.Location() != time.UTC || len(s.Tools) > maximumTools {
		return errors.New("invalid Agent specification")
	}
	for _, t := range s.Tools {
		if t.Name == "" || t.Description == "" || strings.ContainsAny(t.Name+t.Description, "\x00\n\r") {
			return errors.New("invalid Agent specification")
		}
	}
	return nil
}

type decoder struct {
	raw []byte
	at  int
}

func (d *decoder) head() (byte, uint64, error) {
	if d.at >= len(d.raw) {
		return 0, 0, errors.New("truncated CBOR")
	}
	first := d.raw[d.at]
	d.at++
	major := first >> 5
	v := uint64(first & 31)
	if v < 24 {
		return major, v, nil
	}
	size := 0
	switch v {
	case 24:
		size = 1
	case 25:
		size = 2
	case 26:
		size = 4
	case 27:
		size = 8
	default:
		return 0, 0, errors.New("indefinite CBOR")
	}
	if d.at+size > len(d.raw) {
		return 0, 0, errors.New("truncated CBOR")
	}
	value := uint64(0)
	for i := 0; i < size; i++ {
		value = value<<8 | uint64(d.raw[d.at])
		d.at++
	}
	if (size == 1 && value < 24) || (size == 2 && value <= 255) || (size == 4 && value <= 65535) || (size == 8 && value <= 0xffffffff) {
		return 0, 0, errors.New("noncanonical CBOR")
	}
	return major, value, nil
}
func (d *decoder) uint() (uint64, error) {
	m, v, e := d.head()
	if e != nil || m != 0 {
		return 0, errors.New("invalid CBOR uint")
	}
	return v, nil
}
func (d *decoder) text() (string, error) {
	m, n, e := d.head()
	if e != nil || m != 3 || n > uint64(len(d.raw)-d.at) {
		return "", errors.New("invalid CBOR text")
	}
	value := string(d.raw[d.at : d.at+int(n)])
	d.at += int(n)
	return value, nil
}
func head(b *bytes.Buffer, m byte, v uint64) {
	if v < 24 {
		b.WriteByte(m<<5 | byte(v))
		return
	}
	if v <= 255 {
		b.WriteByte(m<<5 | 24)
		b.WriteByte(byte(v))
		return
	}
	if v <= 65535 {
		b.WriteByte(m<<5 | 25)
		b.WriteByte(byte(v >> 8))
		b.WriteByte(byte(v))
		return
	}
	if v <= 0xffffffff {
		b.WriteByte(m<<5 | 26)
		for s := uint(24); ; s -= 8 {
			b.WriteByte(byte(v >> s))
			if s == 0 {
				return
			}
		}
	}
	b.WriteByte(m<<5 | 27)
	for s := uint(56); ; s -= 8 {
		b.WriteByte(byte(v >> s))
		if s == 0 {
			return
		}
	}
}
func uintv(b *bytes.Buffer, v uint64) { head(b, 0, v) }
func text(b *bytes.Buffer, v string)  { head(b, 3, uint64(len(v))); b.WriteString(v) }
