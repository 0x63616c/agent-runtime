package runtimecontent

import (
	"context"
	"testing"
	"time"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestStoreWritesCanonicalKeyFreeAgentSpecification(t *testing.T) {
	store, objects := testStore(t)
	reference, err := store.PutAgentSpecification(context.Background(), "tenant-a", specification(t))
	if err != nil || reference.MediaType != AgentSpecificationMediaTypeV1 || reference.Digest == "" || reference.SizeBytes <= 0 || len(objects.keys) != 1 {
		t.Fatalf("expected immutable canonical reference, got %+v %v keys=%v", reference, err, objects.keys)
	}
	if objects.keys[0] != "tenant-a/runtime-content/v1/sha256/"+reference.Digest[len("sha256:"):] {
		t.Fatalf("unexpected runtime content key %q", objects.keys[0])
	}
}

func TestStoreRefusesForeignLocatorAndCodecNamespace(t *testing.T) {
	if _, err := New("tenant-a/temporal-payload", nil); err == nil {
		t.Fatal("expected temporal payload namespace collision to be refused")
	}
	store, _ := testStore(t)
	reference, err := store.PutAgentSpecification(context.Background(), "tenant-a", specification(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAgentSpecification(context.Background(), store.locator("tenant-b", reference)); err == nil {
		t.Fatal("expected foreign tenant locator refusal")
	}
}

func TestStoreRejectsNoncanonicalAndCancelledReads(t *testing.T) {
	store, objects := testStore(t)
	reference, err := store.PutAgentSpecification(context.Background(), "tenant-a", specification(t))
	if err != nil {
		t.Fatal(err)
	}
	objects.values[objects.keys[0]] = append(objects.values[objects.keys[0]], 0)
	if _, err := store.GetAgentSpecification(context.Background(), store.locator("tenant-a", reference)); err == nil {
		t.Fatal("expected tampered canonical content refusal")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.PutAgentSpecification(ctx, "tenant-a", specification(t)); err == nil {
		t.Fatal("expected cancellation")
	}
}

type recordingObjects struct {
	keys   []string
	values map[string][]byte
}

func (objects *recordingObjects) PutIfAbsent(_ context.Context, key string, value []byte) error {
	objects.keys = append(objects.keys, key)
	objects.values[key] = append([]byte(nil), value...)
	return nil
}
func (objects *recordingObjects) Get(_ context.Context, key string, _ int) ([]byte, error) {
	return append([]byte(nil), objects.values[key]...), nil
}
func testStore(t *testing.T) (*Store, *recordingObjects) {
	t.Helper()
	objects := &recordingObjects{values: map[string][]byte{}}
	store, err := New("runtime-content", objects)
	if err != nil {
		t.Fatal(err)
	}
	return store, objects
}
func specification(t *testing.T) agentruntime.AgentSpecification {
	t.Helper()
	id, _ := agentruntime.ParseAgentID("agent_1234567890ABCDEF")
	revision, _ := agentruntime.ParseAgentRevisionID("arev_1234567890ABCDEF")
	return agentruntime.AgentSpecification{ID: id, RevisionID: revision, Revision: 1, Name: "researcher", ModelProfile: "balanced", Instructions: "be safe", Tools: []agentruntime.ToolDefinition{{Name: "search", Description: "search"}}, CreatedAt: time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)}
}
