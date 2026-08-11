package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/sandboxauthority"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

func TestProxyExecutionAuthorityBindsTheLeaseToOneExactFencedEnvelope(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	source, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	lease := sandboxauthority.EgressLease{Principal: "principal-001", SandboxID: "sandbox-001", ProcessID: "process-001", OperationID: "operation-001", ExpiresAt: now.Add(time.Minute), Rules: []sandboxauthority.EgressRule{{Domain: "api.example.invalid", Protocol: "tcp", Ports: []sandboxauthority.PortRange{{First: 443, Last: 443}}}}}
	authority, err := NewProxyExecutionAuthority(lease, source, guestChannelResolver("8.8.8.8"), guestChannelDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial must not run while binding authority")
	}))
	if err != nil {
		t.Fatal(err)
	}
	envelope := proxyAuthorityEnvelope(t, lease, 9)
	if _, err := authority.Begin(envelope); err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	for name, mutate := range map[string]func(*sandboxhostprotocol.Envelope){
		"principal": func(envelope *sandboxhostprotocol.Envelope) { envelope.Principal = "other" },
		"fence":     func(envelope *sandboxhostprotocol.Envelope) { envelope.FencingToken++ },
		"expiry":    func(envelope *sandboxhostprotocol.Envelope) { envelope.ExpiresAt = envelope.ExpiresAt.Add(time.Second) },
		"request": func(envelope *sandboxhostprotocol.Envelope) {
			payload, _ := DecodeGuestProxyPayload(envelope.Payload)
			payload.Request.ProcessID = "other-process"
			envelope.Payload, _ = json.Marshal(payload)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := envelope
			mutate(&candidate)
			if _, err := authority.Begin(candidate); !errors.Is(err, ErrCapabilityUnavailable) {
				t.Fatalf("Begin() error = %v, want unavailable", err)
			}
		})
	}
}

func TestHostProcessExecutorRefusesProxyWithoutAComposedCertifiedAuthority(t *testing.T) {
	plan := mustCompile(t, validProfile())
	executor := HostProcessExecutor{Host: newLinuxJailerHost(plan, verifiedPlanFixtures(plan), &recordingJailerStarter{}, &recordingFirecrackerHTTP{}, &recordingGuestChannel{})}
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	lease := sandboxauthority.EgressLease{Principal: "principal-001", SandboxID: plan.VMID(), ProcessID: "process-001", OperationID: "operation-001", ExpiresAt: now.Add(time.Minute), Rules: []sandboxauthority.EgressRule{{Domain: "api.example.invalid", Protocol: "tcp", Ports: []sandboxauthority.PortRange{{First: 443, Last: 443}}}}}
	err := executor.ExecuteAuthenticatedWithOutput(context.Background(), proxyAuthorityEnvelope(t, lease, 1), []byte("not-a-verified-envelope"), func(context.Context, sandboxhostprotocol.GuestOutput) error { return nil })
	if !errors.Is(err, ErrCapabilityUnavailable) {
		t.Fatalf("ExecuteAuthenticatedWithOutput() error = %v, want proxy profile refusal", err)
	}
}

func proxyAuthorityEnvelope(t *testing.T, lease sandboxauthority.EgressLease, fence uint64) sandboxhostprotocol.Envelope {
	t.Helper()
	payload, err := json.Marshal(GuestProxyPayload{Version: GuestProxyOperationKind, Request: sandboxauthority.ProxySessionRequest{SandboxID: lease.SandboxID, ProcessID: lease.ProcessID, OperationID: lease.OperationID, VMID: lease.SandboxID, FencingToken: fence, Destination: sandboxauthority.EgressDestination{Domain: "api.example.invalid", Protocol: "tcp", Port: 443}}, Input: []byte("request")})
	if err != nil {
		t.Fatal(err)
	}
	envelope := sandboxhostprotocol.Envelope{EnvelopeID: "envelope-001", DeliveryID: "delivery-001", HostID: "host_01", AssignmentID: "assignment_01", FencingToken: fence, Principal: lease.Principal, SandboxID: lease.SandboxID, ProcessID: lease.ProcessID, OperationID: lease.OperationID, OperationKind: GuestProxyOperationKind, ExpiresAt: lease.ExpiresAt, Payload: payload}
	envelope.PayloadDigest = sandboxhostprotocol.Digest(payload)
	return envelope
}
