package sandboxcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestOperationLedgerDoesNotImplyAResourceReadModel(t *testing.T) {
	// A target in an operation ledger is not enough evidence to construct a
	// public resource response. This guards sandbox.control/v1 from adding a
	// route that derives desired/actual resource state from operation metadata.
	var store DurableStore = NewMemoryLedger()
	if _, ok := store.(ResourceReadModel); ok {
		t.Fatal("memory operation ledger unexpectedly implements resource read model")
	}
}

func TestResourceProjectionBindingPinsOnlyItsAdmittedSnapshot(t *testing.T) {
	initial := sandbox.SandboxInfo{ID: "sbx_01", Desired: sandbox.SandboxActive, Actual: sandbox.SandboxPending}
	body, err := json.Marshal(initial)
	if err != nil {
		t.Fatalf("marshal initial snapshot: %v", err)
	}
	binding := ResourceProjectionBinding{
		Kind:                   ResourceProjectionSandbox,
		ResourceID:             string(initial.ID),
		AdmittedSnapshotDigest: projectionSnapshotDigest(body),
		Transition:             ResourceProjectionReplaceSnapshot,
	}
	if !matchesAdmittedResourceProjection(&binding, ResourceProjectionSandbox, string(initial.ID), body) {
		t.Fatal("admitted snapshot did not match its binding")
	}
	changed := initial
	changed.Actual = sandbox.SandboxProvisioning
	changedBody, err := json.Marshal(changed)
	if err != nil {
		t.Fatalf("marshal changed snapshot: %v", err)
	}
	if matchesAdmittedResourceProjection(&binding, ResourceProjectionSandbox, string(initial.ID), changedBody) {
		t.Fatal("changed snapshot matched an immutable admitted digest")
	}
	if matchesAdmittedResourceProjection(&binding, ResourceProjectionProcess, string(initial.ID), body) {
		t.Fatal("different resource kind matched the binding")
	}
}

func TestMemoryResourceReadModelScopesAndDefensivelyCopiesResources(t *testing.T) {
	t.Parallel()
	model := NewMemoryResourceReadModel()
	const owner = "tenant-a:principal-a"
	info := sandbox.SandboxInfo{
		ID:     "sbx_01",
		Actual: sandbox.SandboxReady,
		Image:  sandbox.ImageInfo{Identity: sandbox.NumericIdentity{Groups: []uint32{100, 101}}},
		Capabilities: sandbox.CapabilitySnapshot{
			Signals:   []sandbox.Signal{"TERM"},
			Isolation: sandbox.CapabilityDescriptor{LimitPrecision: []string{"memory"}},
		},
	}
	if err := model.ProjectSandbox(context.Background(), owner, info); err != nil {
		t.Fatalf("ProjectSandbox() error = %v", err)
	}
	info.Image.Identity.Groups[0] = 999
	info.Capabilities.Signals[0] = "KILL"

	got, err := model.GetSandbox(context.Background(), owner, "sbx_01")
	if err != nil || got.Image.Identity.Groups[0] != 100 || got.Capabilities.Signals[0] != "TERM" {
		t.Fatalf("GetSandbox() = %#v, %v; want independent projected metadata", got, err)
	}
	got.Image.Identity.Groups[0] = 1
	got.Capabilities.Isolation.LimitPrecision[0] = "changed"
	again, err := model.GetSandbox(context.Background(), owner, "sbx_01")
	if err != nil || again.Image.Identity.Groups[0] != 100 || again.Capabilities.Isolation.LimitPrecision[0] != "memory" {
		t.Fatalf("second GetSandbox() = %#v, %v; want defensive copy", again, err)
	}
	if _, err := model.GetSandbox(context.Background(), "tenant-b:principal-b", "sbx_01"); !errors.Is(err, ErrNotFoundOrDenied) {
		t.Fatalf("cross-principal GetSandbox() error = %v; want ErrNotFoundOrDenied", err)
	}
}

func TestMemoryResourceReadModelPaginatesWithinPrincipal(t *testing.T) {
	t.Parallel()
	model := NewMemoryResourceReadModel()
	const owner = "tenant-a:principal-a"
	for _, id := range []sandbox.VolumeID{"vol_03", "vol_01", "vol_02"} {
		if err := model.ProjectVolume(context.Background(), owner, sandbox.VolumeInfo{ID: id}); err != nil {
			t.Fatalf("ProjectVolume(%q) error = %v", id, err)
		}
	}
	if err := model.ProjectVolume(context.Background(), "tenant-b:principal-b", sandbox.VolumeInfo{ID: "vol_00"}); err != nil {
		t.Fatalf("ProjectVolume(other) error = %v", err)
	}
	first, err := model.ListVolumes(context.Background(), owner, sandbox.Page{Limit: 2})
	if err != nil || len(first.Items) != 2 || first.Items[0].ID != "vol_01" || first.Items[1].ID != "vol_02" || first.Next != "vol_02" {
		t.Fatalf("first ListVolumes() = %#v, %v", first, err)
	}
	second, err := model.ListVolumes(context.Background(), owner, sandbox.Page{Cursor: first.Next, Limit: 2})
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != "vol_03" || second.Next != "" {
		t.Fatalf("second ListVolumes() = %#v, %v", second, err)
	}
	if _, err := model.ListVolumes(context.Background(), owner, sandbox.Page{}); err == nil {
		t.Fatal("ListVolumes() with zero limit unexpectedly succeeded")
	}
}

func TestMemoryResourceReadModelPropagatesCancelledContext(t *testing.T) {
	t.Parallel()
	model := NewMemoryResourceReadModel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := model.GetSnapshot(ctx, "tenant-a:principal-a", "snp_01"); !errors.Is(err, context.Canceled) {
		t.Fatalf("GetSnapshot(cancelled) error = %v; want context.Canceled", err)
	}
}
