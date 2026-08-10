package runtimecontent_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestStoreWritesAndReadsCanonicalAgentSpecificationThroughRepositoryCapability(t *testing.T) {
	store, objects, tenant, repository := testStore(t)
	specification := specification(t)
	reference, err := store.PutAgentSpecification(context.Background(), tenant, specification)
	if err != nil {
		t.Fatal(err)
	}
	const wantCanonicalHex = "8901766167656e745f3132333435363738393041424344454675617265765f31323334353637383930414243444546016a726573656172636865726862616c616e63656467626520736166658182667365617263686673656172636874323032362d30382d30395430303a30303a30305a"
	if got := hex.EncodeToString(objects.values[objects.keys[0]]); got != wantCanonicalHex {
		t.Fatalf("canonical Agent specification changed: got %s", got)
	}
	if reference.MediaType != runtimecontent.AgentSpecificationMediaTypeV1 || reference.Digest == "" || reference.SizeBytes <= 0 || len(objects.keys) != 1 {
		t.Fatalf("expected immutable canonical reference, got %+v keys=%v", reference, objects.keys)
	}
	if objects.keys[0] != "tenant-a/runtime-content/v1/sha256/"+reference.Digest[len("sha256:"):] {
		t.Fatalf("unexpected runtime content key %q", objects.keys[0])
	}
	reader := readerFor(t, store, repository, tenant, specification, reference)
	got, err := reader.ReadAgentSpecification(context.Background(), tenant, specification.ID, specification.RevisionID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, specification) {
		t.Fatalf("unexpected Agent specification: got %+v want %+v", got, specification)
	}
}

func TestStoreVerifiesExistingObjectBeforeReturningReference(t *testing.T) {
	store, objects, tenant, _ := testStore(t)
	objects.alwaysExisting = true
	objects.existing = []byte("different object")
	if _, err := store.PutAgentSpecification(context.Background(), tenant, specification(t)); !errors.Is(err, runtimecontent.ErrIntegrity) {
		t.Fatalf("expected integrity refusal for conflicting existing object, got %v", err)
	}
	if objects.gets != 1 {
		t.Fatalf("expected exact existing-object verification, got %d reads", objects.gets)
	}
}

func TestStoreAcceptsOnlyAnExactlyMatchingExistingObject(t *testing.T) {
	store, objects, tenant, _ := testStore(t)
	first, err := store.PutAgentSpecification(context.Background(), tenant, specification(t))
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.PutAgentSpecification(context.Background(), tenant, specification(t))
	if err != nil {
		t.Fatal(err)
	}
	if second != first || objects.gets != 1 {
		t.Fatalf("expected one exact read-back for matching existing content, got ref=%+v reads=%d", second, objects.gets)
	}
}

func TestStoreRejectsInvalidTenantAndContentRootPaths(t *testing.T) {
	objects := newRecordingObjects()
	for _, root := range []string{"", ".", "..", "/runtime-content", "runtime-content/../other", "temporal-payload", "runtime-content\\other"} {
		if _, err := runtimecontent.New(root, objects); err == nil {
			t.Fatalf("expected root %q to be refused", root)
		}
	}
	for _, raw := range []string{"", ".", "..", "tenant/a", "tenant\\a", "Tenant-A", "tenant\x00a"} {
		if _, err := runtimecontent.ParseTenantID(raw); err == nil {
			t.Fatalf("expected tenant %q to be refused", raw)
		}
	}
}

func TestStoreKeepsConfiguredContentRootsDisjoint(t *testing.T) {
	objects := newRecordingObjects()
	primary, err := runtimecontent.New("runtime-content", objects)
	if err != nil {
		t.Fatal(err)
	}
	secondary, err := runtimecontent.New("runtime-content-v2", objects)
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := runtimecontent.ParseTenantID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := primary.PutAgentSpecification(context.Background(), tenant, specification(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := secondary.PutAgentSpecification(context.Background(), tenant, specification(t)); err != nil {
		t.Fatal(err)
	}
	if len(objects.keys) != 2 || objects.keys[0] == objects.keys[1] {
		t.Fatalf("expected configured roots to remain disjoint, got %v", objects.keys)
	}
}

func TestStoreRejectsForeignAndMismatchedRepositoryCapabilities(t *testing.T) {
	store, objects, tenant, repository := testStore(t)
	specification := specification(t)
	reference, err := store.PutAgentSpecification(context.Background(), tenant, specification)
	if err != nil {
		t.Fatal(err)
	}
	otherTenant, err := runtimecontent.ParseTenantID("tenant-b")
	if err != nil {
		t.Fatal(err)
	}
	reader := readerFor(t, store, repository, tenant, specification, reference)
	if _, err := reader.ReadAgentSpecification(context.Background(), otherTenant, specification.ID, specification.RevisionID); !errors.Is(err, runtimecontent.ErrNotFoundOrDenied) {
		t.Fatalf("expected non-enumerating foreign capability refusal, got %v", err)
	}
	wrongID, err := agentruntime.ParseAgentID("agent_ABCDEFGHIJ123456")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadAgentSpecification(context.Background(), tenant, wrongID, specification.RevisionID); !errors.Is(err, runtimecontent.ErrNotFoundOrDenied) {
		t.Fatalf("expected mismatched capability refusal, got %v", err)
	}
	if len(objects.keys) != 1 {
		t.Fatalf("expected no new writes, got keys %v", objects.keys)
	}
}

func TestStoreClassifiesCancellationAbsenceUnavailableAndIntegrity(t *testing.T) {
	store, objects, tenant, repository := testStore(t)
	specification := specification(t)
	reference, err := store.PutAgentSpecification(context.Background(), tenant, specification)
	if err != nil {
		t.Fatal(err)
	}
	reader := readerFor(t, store, repository, tenant, specification, reference)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reader.ReadAgentSpecification(ctx, tenant, specification.ID, specification.RevisionID); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation preservation, got %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	repository.hook = cancel
	if _, err := reader.ReadAgentSpecification(ctx, tenant, specification.ID, specification.RevisionID); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected post-authorization cancellation preservation, got %v", err)
	}
	repository.hook = nil
	ctx, cancel = context.WithCancel(context.Background())
	objects.getHook = cancel
	if _, err := reader.ReadAgentSpecification(ctx, tenant, specification.ID, specification.RevisionID); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected post-I/O cancellation preservation, got %v", err)
	}
	objects.getHook = nil
	repository.err = runtimecontent.ErrNotFoundOrDenied
	if _, err := reader.ReadAgentSpecification(context.Background(), tenant, specification.ID, specification.RevisionID); !errors.Is(err, runtimecontent.ErrNotFoundOrDenied) {
		t.Fatalf("expected repository non-enumerating absence, got %v", err)
	}
	repository.err = errors.New("repository unavailable")
	if _, err := reader.ReadAgentSpecification(context.Background(), tenant, specification.ID, specification.RevisionID); !errors.Is(err, runtimecontent.ErrUnavailable) {
		t.Fatalf("expected repository unavailable classification, got %v", err)
	}
	repository.err = nil
	objects.getErr = runtimecontent.ErrNotFoundOrDenied
	if _, err := reader.ReadAgentSpecification(context.Background(), tenant, specification.ID, specification.RevisionID); !errors.Is(err, runtimecontent.ErrNotFoundOrDenied) {
		t.Fatalf("expected non-enumerating absence, got %v", err)
	}
	objects.getErr = errors.New("object storage unavailable")
	if _, err := reader.ReadAgentSpecification(context.Background(), tenant, specification.ID, specification.RevisionID); !errors.Is(err, runtimecontent.ErrUnavailable) {
		t.Fatalf("expected unavailable classification, got %v", err)
	}
	objects.getErr = nil
	objects.values[objects.keys[0]] = append(objects.values[objects.keys[0]], 0)
	if _, err := reader.ReadAgentSpecification(context.Background(), tenant, specification.ID, specification.RevisionID); !errors.Is(err, runtimecontent.ErrIntegrity) {
		t.Fatalf("expected tampered content integrity refusal, got %v", err)
	}
}

func TestStoreRejectsNoncanonicalAndInvalidUTF8Content(t *testing.T) {
	store, objects, tenant, repository := testStore(t)
	specification := specification(t)
	_, err := store.PutAgentSpecification(context.Background(), tenant, specification)
	if err != nil {
		t.Fatal(err)
	}
	noncanonical := append([]byte(nil), objects.values[objects.keys[0]]...)
	noncanonical[1] = 0x18 // Encode version 1 non-minimally; CBOR needs a second byte.
	noncanonical = append(noncanonical[:2], append([]byte{0x01}, noncanonical[2:]...)...)
	noncanonicalReference := referenceFor(noncanonical)
	reader := readerFor(t, store, repository, tenant, specification, noncanonicalReference)
	objects.forcedValue = noncanonical
	if _, err := reader.ReadAgentSpecification(context.Background(), tenant, specification.ID, specification.RevisionID); !errors.Is(err, runtimecontent.ErrIntegrity) {
		t.Fatalf("expected noncanonical content refusal, got %v", err)
	}
	invalidUTF8Encoded := append([]byte(nil), objects.values[objects.keys[0]]...)
	nameOffset := bytes.Index(invalidUTF8Encoded, []byte(specification.Name))
	if nameOffset < 0 {
		t.Fatal("test vector does not contain Agent name")
	}
	invalidUTF8Encoded[nameOffset] = 0xff
	invalidUTF8Reference := referenceFor(invalidUTF8Encoded)
	reader = readerFor(t, store, repository, tenant, specification, invalidUTF8Reference)
	objects.forcedValue = invalidUTF8Encoded
	if _, err := reader.ReadAgentSpecification(context.Background(), tenant, specification.ID, specification.RevisionID); !errors.Is(err, runtimecontent.ErrIntegrity) {
		t.Fatalf("expected invalid UTF-8 decode refusal, got %v", err)
	}
	objects.forcedValue = nil
	invalidUTF8 := specification
	invalidUTF8.Name = string([]byte{0xff})
	if _, err := store.PutAgentSpecification(context.Background(), tenant, invalidUTF8); err == nil {
		t.Fatal("expected invalid UTF-8 encode refusal")
	}
	oversized := specification
	oversized.Instructions = strings.Repeat("x", 256*1024+1)
	if _, err := store.PutAgentSpecification(context.Background(), tenant, oversized); err == nil {
		t.Fatal("expected oversized specification refusal")
	}
}

type recordingObjects struct {
	keys           []string
	values         map[string][]byte
	alwaysExisting bool
	existing       []byte
	getErr         error
	getHook        func()
	forcedValue    []byte
	gets           int
}

func newRecordingObjects() *recordingObjects {
	return &recordingObjects{values: make(map[string][]byte)}
}

func (objects *recordingObjects) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	objects.keys = append(objects.keys, key)
	if objects.alwaysExisting {
		objects.values[key] = append([]byte(nil), objects.existing...)
		return false, nil
	}
	if _, exists := objects.values[key]; exists {
		return false, nil
	}
	objects.values[key] = append([]byte(nil), value...)
	return true, nil
}

func (objects *recordingObjects) Get(_ context.Context, key string, _ int) ([]byte, error) {
	objects.gets++
	if objects.getHook != nil {
		objects.getHook()
	}
	if objects.getErr != nil {
		return nil, objects.getErr
	}
	if objects.forcedValue != nil {
		return append([]byte(nil), objects.forcedValue...), nil
	}
	value, exists := objects.values[key]
	if !exists {
		return nil, runtimecontent.ErrNotFoundOrDenied
	}
	return append([]byte(nil), value...), nil
}

func testStore(t *testing.T) (*runtimecontent.Store, *recordingObjects, runtimecontent.TenantID, *recordingRepository) {
	t.Helper()
	objects := newRecordingObjects()
	store, err := runtimecontent.New("runtime-content", objects)
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := runtimecontent.ParseTenantID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	return store, objects, tenant, &recordingRepository{}
}

func readerFor(t *testing.T, store *runtimecontent.Store, repository *recordingRepository, tenant runtimecontent.TenantID, specification agentruntime.AgentSpecification, reference runtimecontent.Reference) *runtimecontent.AgentSpecificationReader {
	t.Helper()
	repository.record = runtimecontent.AgentSpecificationRecord{Tenant: tenant, AgentID: specification.ID, RevisionID: specification.RevisionID, Revision: specification.Revision, Reference: reference}
	reader, err := runtimecontent.NewAgentSpecificationReader(store, repository)
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

type recordingRepository struct {
	record runtimecontent.AgentSpecificationRecord
	err    error
	hook   func()
}

func (repository *recordingRepository) AuthorizeAgentSpecificationRead(_ context.Context, _ runtimecontent.TenantID, _ agentruntime.AgentID, _ agentruntime.AgentRevisionID) (runtimecontent.AgentSpecificationRecord, error) {
	if repository.hook != nil {
		repository.hook()
	}
	if repository.err != nil {
		return runtimecontent.AgentSpecificationRecord{}, repository.err
	}
	return repository.record, nil
}

func specification(t *testing.T) agentruntime.AgentSpecification {
	t.Helper()
	id, _ := agentruntime.ParseAgentID("agent_1234567890ABCDEF")
	revision, _ := agentruntime.ParseAgentRevisionID("arev_1234567890ABCDEF")
	return agentruntime.AgentSpecification{ID: id, RevisionID: revision, Revision: 1, Name: "researcher", ModelProfile: "balanced", Instructions: "be safe", Tools: []agentruntime.ToolDefinition{{Name: "search", Description: "search"}}, CreatedAt: time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)}
}

func referenceFor(raw []byte) runtimecontent.Reference {
	sum := sha256.Sum256(raw)
	return runtimecontent.Reference{Digest: "sha256:" + hex.EncodeToString(sum[:]), MediaType: runtimecontent.AgentSpecificationMediaTypeV1, SizeBytes: int64(len(raw))}
}
