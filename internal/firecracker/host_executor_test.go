package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxauthority"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

func TestHostProcessExecutorCanOnlyReachTheFencedGuestDispatchGate(t *testing.T) {
	plan := mustCompile(t, validProfile())
	executor := HostProcessExecutor{Host: newLinuxJailerHost(plan, verifiedPlanFixtures(plan), &recordingJailerStarter{}, &recordingFirecrackerHTTP{}, &recordingGuestChannel{})}
	err := executor.Execute(context.Background(), sandboxhostprotocol.Envelope{HostID: "host_01", AssignmentID: "assignment_01", FencingToken: 1, CapabilityDigest: string(plan.Capabilities().Digest)})
	if !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("Execute() = %v, want certified profile refusal", err)
	}
}

func TestHostProcessExecutorRefusesSecretCommandWithoutAComposedCertifiedLifecycle(t *testing.T) {
	plan := mustCompile(t, validProfile())
	executor := HostProcessExecutor{Host: newLinuxJailerHost(plan, verifiedPlanFixtures(plan), &recordingJailerStarter{}, &recordingFirecrackerHTTP{}, &recordingGuestChannel{})}
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	payload, err := json.Marshal(GuestSecretCommand{Version: GuestSecretCommandOperationKind, Command: json.RawMessage(`{"version":"agent-runtime.guest-command/v1"}`), Secret: sandboxauthority.SecretRequest{Principal: "principal-001", SandboxID: plan.VMID(), ProcessID: "process-001", OperationID: "operation-001", Binding: "binding-001", Purpose: "command", ExpiresAt: now.Add(time.Minute)}})
	if err != nil {
		t.Fatal(err)
	}
	err = executor.ExecuteAuthenticatedWithOutput(context.Background(), sandboxhostprotocol.Envelope{HostID: "host_01", AssignmentID: "assignment_01", FencingToken: 1, CapabilityDigest: string(plan.Capabilities().Digest), SandboxID: plan.VMID(), ProcessID: "process-001", OperationID: "operation-001", OperationKind: GuestSecretCommandOperationKind, ExpiresAt: now.Add(time.Minute), Payload: payload}, []byte("not-a-verified-envelope"), func(context.Context, sandboxhostprotocol.GuestOutput) error { return nil })
	if !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("ExecuteAuthenticatedWithOutput() = %v, want secret profile refusal", err)
	}
}
