package firecracker

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestDirectLaunchOwnershipPersistsVerifiedCreateAndBindsExactExecAfterRestart(t *testing.T) {
	plan := directOwnershipPlan(t)
	path := filepath.Join(t.TempDir(), "launch-ownership.json")
	owner, err := OpenDirectLaunchOwnership(path, plan)
	if err != nil {
		t.Fatal(err)
	}
	create, createWire := directOwnershipCreateEnvelope(t, plan)
	if err := owner.ClaimCreate(create, createWire); err != nil {
		t.Fatalf("ClaimCreate() error = %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}

	owner, err = OpenDirectLaunchOwnership(path, plan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	exec, execWire := directOwnershipExecEnvelope(t, create, create.Tenant)
	if err := owner.BindExec(exec, execWire); err != nil {
		t.Fatalf("BindExec() after restart error = %v", err)
	}
	wrong := exec
	wrong.CapabilityDigest = sandboxhostprotocol.Digest([]byte("substituted-capability"))
	if err := owner.BindExec(wrong, execWire); !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("BindExec(substituted capability) = %v, want refusal", err)
	}
	crossTenant := exec
	crossTenant.Tenant = "tenant_02"
	if owner.matchesExecOwnership(crossTenant) {
		t.Fatal("matchesExecOwnership() accepted a tenant-only mismatch")
	}
}

func TestHostProcessExecutorDirectOwnershipRefusesExecUntilVerifiedCreate(t *testing.T) {
	plan := directOwnershipPlan(t)
	owner, err := OpenDirectLaunchOwnership(filepath.Join(t.TempDir(), "launch-ownership.json"), plan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	executor := HostProcessExecutor{Host: &LinuxJailerHost{}, Ownership: owner}
	create, createWire := directOwnershipCreateEnvelope(t, plan)
	exec, execWire := directOwnershipExecEnvelope(t, create, create.Tenant)
	if err := executor.ExecuteAuthenticated(context.Background(), exec, execWire); !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("ExecuteAuthenticated(exec before create) = %v, want refusal", err)
	}
	if err := executor.ExecuteAuthenticated(context.Background(), create, createWire); !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("ExecuteAuthenticated(create) = %v, want unavailable after durable ownership", err)
	}
	if err := executor.ReapAuthenticated(context.Background(), exec, execWire); !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("ReapAuthenticated(exact exec) = %v, want unavailable host cleanup", err)
	}
}

func directOwnershipPlan(t *testing.T) Plan {
	t.Helper()
	return mustCompile(t, validProfile())
}

func directOwnershipCreateEnvelope(t *testing.T, plan Plan) (sandboxhostprotocol.Envelope, []byte) {
	t.Helper()
	now := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	request := sandbox.OperationRequest{ID: "op_owned-001", Kind: sandbox.OperationCreateSandbox, CreateSandbox: &sandbox.CreateSandboxRequest{Spec: sandbox.SandboxSpec{Image: sandbox.ImageRef{Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}}}
	payload, err := sandbox.EncodeControlOperationRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, decodeErr := sandbox.DecodeControlOperationRequest(payload); decodeErr != nil || decoded.ID != request.ID || decoded.Kind != request.Kind {
		t.Fatalf("create request decode = %#v, %v", decoded, decodeErr)
	}
	envelope := sandboxhostprotocol.Envelope{ProtocolVersion: sandboxhostprotocol.Version, EnvelopeID: "envelope-create", DeliveryID: "delivery-create", Nonce: "nonce-create", IssuedAt: now, ExpiresAt: now.Add(time.Minute), ControlKeyID: "control_01", HostID: "host_01", HostGeneration: 1, AssignmentID: "assignment-create", LeaseEpoch: 1, FencingToken: 1, Tenant: "tenant_01", Principal: "tenant_01:principal_01", OperationID: string(request.ID), OperationKind: string(request.Kind), EffectiveSpecDigest: sandboxhostprotocol.Digest([]byte("effective-spec")), CapabilityDigest: sandboxhostprotocol.Digest([]byte("capability-profile")), CanonicalRequestDigest: sandboxhostprotocol.Digest([]byte("canonical-create-request")), SequenceContract: "host-proposed/control-owned-v1", Payload: payload}
	envelope.PayloadDigest = sandboxhostprotocol.Digest(payload)
	wire, err := sandboxhostprotocol.SignEnvelope(envelope, "control_01", ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope, wire
}

func directOwnershipExecEnvelope(t *testing.T, create sandboxhostprotocol.Envelope, tenant string) (sandboxhostprotocol.Envelope, []byte) {
	t.Helper()
	now := create.IssuedAt
	sandboxID := sandbox.SandboxIDForCreateOperation(sandbox.OperationID(create.OperationID))
	request := sandbox.OperationRequest{ID: "op_exec-001", Kind: sandbox.OperationExecProcess, ExecProcess: &sandbox.ExecProcessRequest{SandboxID: sandboxID, Command: sandbox.Command{Executable: "/bin/echo", Argv: []string{"echo"}, WorkDir: "/work"}}}
	payload, err := sandbox.EncodeControlOperationRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	envelope := sandboxhostprotocol.Envelope{ProtocolVersion: sandboxhostprotocol.Version, EnvelopeID: "envelope-exec-" + tenant, DeliveryID: "delivery-exec-" + tenant, Nonce: "nonce-exec-" + tenant, IssuedAt: now, ExpiresAt: now.Add(time.Minute), ControlKeyID: create.ControlKeyID, HostID: create.HostID, HostGeneration: create.HostGeneration, AssignmentID: "assignment-exec-" + tenant, LeaseEpoch: 2, FencingToken: 2, Tenant: tenant, Principal: tenant + ":principal_01", SandboxID: string(sandboxID), ProcessID: "prc_exec-001", OperationID: string(request.ID), OperationKind: string(request.Kind), EffectiveSpecDigest: create.EffectiveSpecDigest, CapabilityDigest: create.CapabilityDigest, CanonicalRequestDigest: sandboxhostprotocol.Digest([]byte("canonical-exec-request")), SequenceContract: "host-proposed/control-owned-v1", Payload: payload}
	envelope.PayloadDigest = sandboxhostprotocol.Digest(payload)
	wire, err := sandboxhostprotocol.SignEnvelope(envelope, "control_01", ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope, wire
}
