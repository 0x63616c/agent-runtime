package sandbox

import (
	"context"
	"testing"
	"time"
)

func TestClientCapabilitySnapshotIsStructuredFrozenAndBoundToCreate(t *testing.T) {
	policy := testLimitPolicy()
	policy.capabilities.Isolation = CapabilityDescriptor{State: CapabilityEnforced, ContractVersion: "test/isolation/v1", ConformanceVersion: "test", DataPlane: "deterministic"}
	client, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC), policy)
	if err != nil {
		t.Fatalf("newCoreClientWithPolicy() error = %v", err)
	}

	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities() error = %v", err)
	}
	if !validDigest(capabilities.Digest) || capabilities.Isolation.State != CapabilityEnforced || capabilities.Isolation.DataPlane != "deterministic" {
		t.Fatalf("Capabilities() = %#v, want structured enforced isolation profile", capabilities)
	}
	capabilities.Isolation.LimitPrecision = []string{"mutated"}
	again, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities() second call error = %v", err)
	}
	if len(again.Isolation.LimitPrecision) != 0 {
		t.Fatalf("Capabilities() returned caller-owned mutable state: %#v", again.Isolation.LimitPrecision)
	}

	request := validCreateRequest("op_capability_bound")
	request.CreateSandbox.Spec.Capabilities = CapabilityRequirements{Required: []CapabilityRequirement{{Feature: CapabilityIsolation, Minimum: CapabilityEnforced}}}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	operation, err := client.GetOperation(context.Background(), request.ID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if got, want := operation.CapabilityDigest, again.Digest; got != want {
		t.Fatalf("create capability digest = %q, want negotiated %q", got, want)
	}
}

func TestCapabilityDigestChangesWhenAnyAdvertisedProfileFactChanges(t *testing.T) {
	first := testLimitPolicy()
	first.capabilities.Egress = CapabilityDescriptor{State: CapabilityUnavailable, ContractVersion: "profile/v1", ConformanceVersion: "none", DataPlane: "deny-all"}
	second := first
	second.capabilities.Egress = CapabilityDescriptor{State: CapabilityDeclared, ContractVersion: "profile/v1", ConformanceVersion: "test", DataPlane: "proxy"}

	firstClient, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC), first)
	if err != nil {
		t.Fatalf("new first client: %v", err)
	}
	secondClient, err := newCoreClientWithPolicy("principal-b", time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC), second)
	if err != nil {
		t.Fatalf("new second client: %v", err)
	}
	firstCapabilities, err := firstClient.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("first Capabilities(): %v", err)
	}
	secondCapabilities, err := secondClient.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("second Capabilities(): %v", err)
	}
	if firstCapabilities.Digest == secondCapabilities.Digest {
		t.Fatalf("capability digests are equal (%q) after profile changed", firstCapabilities.Digest)
	}
}

func TestRetryFailsClosedWhenPersistedCapabilityProfileRegresses(t *testing.T) {
	ledger := newCoreLedger()
	firstPolicy := testLimitPolicy()
	firstPolicy.capabilities.Isolation = CapabilityDescriptor{State: CapabilityEnforced, ContractVersion: "profile/v1", ConformanceVersion: "certified", DataPlane: "isolated"}
	first, err := newCoreClientWithLedger("principal-a", time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC), firstPolicy, ledger)
	if err != nil {
		t.Fatalf("new first client: %v", err)
	}
	request := validCreateRequest("op_capability_regression")
	request.CreateSandbox.Spec.Capabilities.Required = []CapabilityRequirement{{Feature: CapabilityIsolation, Minimum: CapabilityEnforced}}
	if _, err := first.Submit(context.Background(), request); err != nil {
		t.Fatalf("first Submit() error = %v", err)
	}

	regressed, err := newCoreClientWithLedger("principal-a", time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC), testLimitPolicy(), ledger)
	if err != nil {
		t.Fatalf("new regressed client: %v", err)
	}
	if _, err := regressed.Submit(context.Background(), request); err == nil {
		t.Fatal("Submit() error = nil after capability regression")
	} else {
		failureCode(t, err, FailureIncompatiblePersistedPolicy)
	}
}

func TestRestoreBindsTheNegotiatedCapabilitySnapshot(t *testing.T) {
	policy := testLimitPolicy()
	policy.capabilities.Snapshots = CapabilityDescriptor{State: CapabilityEnforced, ContractVersion: "snapshot/v1", ConformanceVersion: "test", DataPlane: "deterministic"}
	client, err := newCoreClientWithPolicy("principal-a", time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC), policy)
	if err != nil {
		t.Fatalf("newCoreClientWithPolicy() error = %v", err)
	}
	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities() error = %v", err)
	}
	request := OperationRequest{ID: "op_restore_capability", Kind: OperationRestoreSandbox, RestoreSandbox: &RestoreSandboxRequest{SnapshotID: "snap_01", Overrides: SandboxOverrides{Capabilities: &CapabilityRequirements{Required: []CapabilityRequirement{{Feature: CapabilitySnapshots, Minimum: CapabilityEnforced}}}}}}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatalf("Submit(restore) error = %v", err)
	}
	operation, err := client.GetOperation(context.Background(), request.ID)
	if err != nil {
		t.Fatalf("GetOperation() error = %v", err)
	}
	if got, want := operation.CapabilityDigest, capabilities.Digest; got != want {
		t.Fatalf("restore capability digest = %q, want negotiated %q", got, want)
	}
}
