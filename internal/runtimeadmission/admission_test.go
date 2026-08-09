package runtimeadmission

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestContentStoreKeepsTenantObjectsDistinctAndHydratesAuthorizedInput(t *testing.T) {
	t.Parallel()

	store := NewMemoryContentStore()
	alice := Owner{TenantID: "tenant_a", PrincipalID: "alice"}
	otherTenant := Owner{TenantID: "tenant_b", PrincipalID: "alice"}
	parts := []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "hello"}}

	reference, err := store.PutInput(context.Background(), alice, parts)
	if err != nil {
		t.Fatalf("put input: %v", err)
	}
	if reference.MediaType != InputMediaTypeV1 || reference.SizeBytes <= 0 || reference.Digest[:7] != "sha256:" {
		t.Fatalf("reference = %#v, want bounded v1 digest reference", reference)
	}
	locator := authorizedInputLocator{owner: alice, sessionID: "sess_0000000000000001", inputID: "inpt_0000000000000001", reference: reference}
	got, err := store.GetInput(context.Background(), locator)
	if err != nil {
		t.Fatalf("get authorized input: %v", err)
	}
	if len(got) != 1 || got[0].Text != "hello" {
		t.Fatalf("hydrated parts = %#v, want hello", got)
	}
	otherLocator := authorizedInputLocator{owner: otherTenant, sessionID: "sess_0000000000000001", inputID: "inpt_0000000000000001", reference: reference}
	if _, err := store.GetInput(context.Background(), otherLocator); !errors.Is(err, ErrNotFoundOrDenied) {
		t.Fatalf("cross-tenant get error = %v, want ErrNotFoundOrDenied", err)
	}
}

func TestInputCanonicalEncodingUsesDeterministicCBORWithoutTextEscapingGrowth(t *testing.T) {
	t.Parallel()

	encoded, err := encodeInput([]agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "hello"}})
	if err != nil {
		t.Fatalf("encode input: %v", err)
	}
	want := []byte{0x82, 0x01, 0x81, 0x82, 0x01, 0x65, 'h', 'e', 'l', 'l', 'o'}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("canonical CBOR = %x, want %x", encoded, want)
	}
	parts, err := decodeInput(append(encoded, 0x00))
	if err == nil || parts != nil {
		t.Fatalf("decode trailing CBOR = %#v, %v; want integrity failure", parts, err)
	}
	maximum := make([]agentruntime.ContentPart, agentruntime.MaxInputParts)
	for index := range maximum {
		maximum[index] = agentruntime.ContentPart{Kind: agentruntime.ContentText, Text: strings.Repeat("<", agentruntime.MaxTextPartBytes)}
	}
	encoded, err = encodeInput(maximum)
	if err != nil || len(encoded) > maximumInputBytes {
		t.Fatalf("maximum public input bytes = %d, %v; want <= %d", len(encoded), err, maximumInputBytes)
	}
}

func TestContentStoreRejectsPartCountsOutsidePublicContract(t *testing.T) {
	t.Parallel()
	store := NewMemoryContentStore()
	owner := Owner{TenantID: "tenant_a", PrincipalID: "alice"}
	if _, err := store.PutInput(context.Background(), owner, nil); err == nil {
		t.Fatal("empty parts staged content, want public-contract refusal")
	}
	parts := make([]agentruntime.ContentPart, agentruntime.MaxInputParts+1)
	for index := range parts {
		parts[index] = agentruntime.ContentPart{Kind: agentruntime.ContentText, Text: "x"}
	}
	if _, err := store.PutInput(context.Background(), owner, parts); err == nil {
		t.Fatal("too many parts staged content, want public-contract refusal")
	}
}

func TestGeneratedTypedIDsUseSDKCanonicalParsers(t *testing.T) {
	t.Parallel()
	if _, err := newID[agentruntime.InputID](literalIDs{value: "0000000000000001"}, "wrong_"); err == nil {
		t.Fatal("generated input ID accepted wrong canonical prefix")
	}
}

func TestServiceRefusesUnauthorizedArtifactBeforeStaging(t *testing.T) {
	t.Parallel()

	store := NewMemoryContentStore()
	catalog := NewMemoryArtifactCatalog()
	owner := Owner{TenantID: "tenant_a", PrincipalID: "alice"}
	catalog.Seed(Owner{TenantID: "tenant_a", PrincipalID: "bob"}, agentruntime.ArtifactReference{
		ID: "art_0000000000000001", MediaType: "text/plain", SizeBytes: 5,
		SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	service, err := NewService(store, catalog, rejectingRepository{}, fixedClock{now: time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)}, sequenceIDs{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	_, err = service.SendInput(context.Background(), owner, agentruntime.SendInputRequest{
		SessionID: "sess_0000000000000001", IdempotencyKey: "artifact-send",
		Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentArtifact, Artifact: &agentruntime.ArtifactReference{
			ID: "art_0000000000000001", MediaType: "text/plain", SizeBytes: 5,
			SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}}},
	})
	if !errors.Is(err, ErrNotFoundOrDenied) {
		t.Fatalf("send unauthorized artifact error = %v, want ErrNotFoundOrDenied", err)
	}
	if store.Count() != 0 {
		t.Fatalf("stored objects = %d, want no staging before artifact refusal", store.Count())
	}
}

type rejectingRepository struct{}

type literalIDs struct{ value string }

func (source literalIDs) Next() (string, error) { return source.value, nil }

func (rejectingRepository) Admit(context.Context, Owner, PreparedInput, IDSource) (AdmissionResult, error) {
	return AdmissionResult{}, errors.New("repository should not be called")
}

func (rejectingRepository) AuthorizeInputRead(context.Context, Owner, agentruntime.SessionID, agentruntime.InputID) (authorizedInputLocator, error) {
	return authorizedInputLocator{}, errors.New("repository should not be called")
}
