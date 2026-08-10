package runtimecontent_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestStoreStagesAnIdentityFreeAgentSpecificationBodyAsTenantBoundHandoff(t *testing.T) {
	store, objects, tenant, _ := testStore(t)
	body := runtimecontent.AgentSpecificationBody{
		Name: "researcher", ModelProfile: "balanced", Instructions: "be safe",
		Tools: []agentruntime.ToolDefinition{{Name: "search", Description: "search"}},
	}

	handoff, err := store.StageAgentSpecificationBody(context.Background(), tenant, body)
	if err != nil {
		t.Fatalf("stage Agent specification body: %v", err)
	}
	commitment, err := store.ValidateAgentSpecificationBodyHandoff(handoff)
	if err != nil {
		t.Fatalf("validate Agent specification body handoff: %v", err)
	}
	if commitment.Tenant != tenant || commitment.Name != body.Name || commitment.ModelProfile != body.ModelProfile || commitment.Reference.MediaType != runtimecontent.AgentSpecificationBodyMediaTypeV1 {
		t.Fatalf("handoff commitment = %#v, want tenant-bound body reference", commitment)
	}
	if len(objects.keys) != 1 || bytes.Contains(objects.values[objects.keys[0]], []byte("agent_")) || bytes.Contains(objects.values[objects.keys[0]], []byte("arev_")) {
		t.Fatalf("staged Agent body must be identity-free, keys=%v bytes=%x", objects.keys, objects.values[objects.keys[0]])
	}
}

func TestAgentSpecificationBodyReaderAuthorizesAndSynthesizesRevisionMetadata(t *testing.T) {
	store, _, tenant, _ := testStore(t)
	body := runtimecontent.AgentSpecificationBody{
		Name: "researcher", ModelProfile: "balanced", Instructions: "be safe",
		Tools: []agentruntime.ToolDefinition{{Name: "search", Description: "search"}},
	}
	handoff, err := store.StageAgentSpecificationBody(context.Background(), tenant, body)
	if err != nil {
		t.Fatalf("stage Agent specification body: %v", err)
	}
	commitment, err := store.ValidateAgentSpecificationBodyHandoff(handoff)
	if err != nil {
		t.Fatalf("validate Agent specification body handoff: %v", err)
	}
	agentID, _ := agentruntime.ParseAgentID("agent_1234567890ABCDEF")
	revisionID, _ := agentruntime.ParseAgentRevisionID("arev_1234567890ABCDEF")
	createdAt := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	repository := bodyReaderRepository{record: runtimecontent.AgentSpecificationBodyRecord{
		Tenant: tenant, AgentID: agentID, RevisionID: revisionID, Revision: 1,
		Name: body.Name, ModelProfile: body.ModelProfile, Reference: commitment.Reference, CreatedAt: createdAt,
	}}
	reader, err := runtimecontent.NewAgentSpecificationBodyReader(store, repository)
	if err != nil {
		t.Fatalf("new Agent specification body reader: %v", err)
	}

	got, err := reader.ReadAgentSpecification(context.Background(), tenant, agentID, revisionID)
	if err != nil {
		t.Fatalf("read Agent specification body: %v", err)
	}
	want := agentruntime.AgentSpecification{ID: agentID, RevisionID: revisionID, Revision: 1, Name: body.Name, ModelProfile: body.ModelProfile, Instructions: body.Instructions, Tools: body.Tools, CreatedAt: createdAt}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("synthesized Agent specification = %#v, want %#v", got, want)
	}
}

func TestStoreRejectsAgentSpecificationBodyHandoffFromAnotherContentAuthority(t *testing.T) {
	store, objects, tenant, _ := testStore(t)
	handoff, err := store.StageAgentSpecificationBody(context.Background(), tenant, runtimecontent.AgentSpecificationBody{Name: "researcher", ModelProfile: "balanced", Instructions: "be safe"})
	if err != nil {
		t.Fatalf("stage Agent specification body: %v", err)
	}
	other, err := runtimecontent.New("runtime-content", objects)
	if err != nil {
		t.Fatalf("new other content authority: %v", err)
	}
	if _, err := other.ValidateAgentSpecificationBodyHandoff(handoff); !errors.Is(err, runtimecontent.ErrNotFoundOrDenied) {
		t.Fatalf("foreign handoff error = %v, want ErrNotFoundOrDenied", err)
	}
}

var _ runtimecontent.ContentHandoffValidator = (*runtimecontent.Store)(nil)

type bodyReaderRepository struct {
	record runtimecontent.AgentSpecificationBodyRecord
}

func (repository bodyReaderRepository) AuthorizeAgentSpecificationBodyRead(context.Context, runtimecontent.TenantID, agentruntime.AgentID, agentruntime.AgentRevisionID) (runtimecontent.AgentSpecificationBodyRecord, error) {
	return repository.record, nil
}
