package firecracker

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
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

func TestHostProcessExecutorRefusesAReboundAuthenticatedEnvelopeBeforeGuestDispatch(t *testing.T) {
	plan := mustCompile(t, validProfile())
	executor := HostProcessExecutor{Host: newLinuxJailerHost(plan, verifiedPlanFixtures(plan), &recordingJailerStarter{}, &recordingFirecrackerHTTP{}, &recordingGuestChannel{})}
	envelope, wire := authenticatedHostExecutorEnvelope(t, plan)
	rebound := envelope
	rebound.FencingToken++
	err := executor.ExecuteAuthenticated(context.Background(), rebound, wire)
	if !errors.Is(err, ErrCapabilityUnavailable) || !strings.Contains(err.Error(), "exact canonical envelope") {
		t.Fatalf("ExecuteAuthenticated(rebound envelope) = %v, want exact-wire refusal", err)
	}
}

func authenticatedHostExecutorEnvelope(t *testing.T, plan Plan) (sandboxhostprotocol.Envelope, []byte) {
	t.Helper()
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	envelope := sandboxhostprotocol.Envelope{
		ProtocolVersion:        sandboxhostprotocol.Version,
		EnvelopeID:             "envelope_01",
		DeliveryID:             "delivery_01",
		Nonce:                  "nonce_01",
		IssuedAt:               now,
		ExpiresAt:              now.Add(time.Minute),
		HostID:                 "host_01",
		HostGeneration:         1,
		AssignmentID:           "assignment_01",
		LeaseEpoch:             1,
		FencingToken:           1,
		Tenant:                 "tenant_01",
		Principal:              "tenant_01:principal_01",
		SandboxID:              plan.VMID(),
		ProcessID:              "process_01",
		OperationID:            "operation_01",
		OperationKind:          "generic-command",
		EffectiveSpecDigest:    sandboxhostprotocol.Digest([]byte("effective-spec")),
		CapabilityDigest:       sandboxhostprotocol.Digest([]byte("unavailable-capability-profile")),
		CanonicalRequestDigest: sandboxhostprotocol.Digest([]byte("canonical-request")),
		SequenceContract:       "host-proposed/control-owned-v1",
		Payload:                []byte(`{"command":"bounded"}`),
	}
	envelope.PayloadDigest = sandboxhostprotocol.Digest(envelope.Payload)
	wire, err := sandboxhostprotocol.SignEnvelope(envelope, "control_01", ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return envelope, wire
}
