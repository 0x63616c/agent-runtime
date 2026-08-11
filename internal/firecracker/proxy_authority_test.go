package firecracker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
		"ungranted DNS request": func(envelope *sandboxhostprotocol.Envelope) {
			payload, _ := DecodeGuestProxyPayload(envelope.Payload)
			payload.Request.Destination.Domain = "other.example.invalid"
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

func TestProxyAuthorityIssuerBindsTheAuthenticatedWireToOneNoRouteLease(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	source, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	plan := mustCompile(t, validProfile())
	jailer := mustCompileJailerExecutionAuthority(t, plan)
	topology, err := CompileNoRouteProxyTopologyManifest(plan, jailer)
	if err != nil {
		t.Fatal(err)
	}
	lease := sandboxauthority.EgressLease{Principal: "tenant-001:principal-001", SandboxID: plan.VMID(), ProcessID: "process-001", OperationID: "operation-001", ExpiresAt: now.Add(time.Minute), Rules: []sandboxauthority.EgressRule{{Domain: "api.example.invalid", Protocol: "tcp", Ports: []sandboxauthority.PortRange{{First: 443, Last: 443}}}}}
	issuer, err := NewProxyAuthorityIssuer(plan, jailer, topology, lease, source, guestChannelResolver("8.8.8.8"), guestChannelDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial must not run while issuing authority")
	}))
	if err != nil {
		t.Fatal(err)
	}
	envelope, wire := signedProxyAuthorityEnvelope(t, lease, 9, now)
	authority, err := issuer.Issue(envelope, wire)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if _, err := authority.Begin(envelope); err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	for name, mutate := range map[string]func(*sandboxhostprotocol.Envelope, *[]byte){
		"wrong wire": func(_ *sandboxhostprotocol.Envelope, wire *[]byte) {
			*wire = append([]byte(nil), (*wire)[:len(*wire)-1]...)
		},
		"wrong VM":    func(envelope *sandboxhostprotocol.Envelope, _ *[]byte) { envelope.SandboxID = "other-sandbox" },
		"wrong fence": func(envelope *sandboxhostprotocol.Envelope, _ *[]byte) { envelope.FencingToken++ },
		"wrong DNS request": func(envelope *sandboxhostprotocol.Envelope, _ *[]byte) {
			payload, _ := DecodeGuestProxyPayload(envelope.Payload)
			payload.Request.Destination.Domain = "other.example.invalid"
			envelope.Payload, _ = json.Marshal(payload)
			envelope.PayloadDigest = sandboxhostprotocol.Digest(envelope.Payload)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, candidateWire := envelope, append([]byte(nil), wire...)
			mutate(&candidate, &candidateWire)
			if _, err := issuer.Issue(candidate, candidateWire); !errors.Is(err, ErrCapabilityUnavailable) {
				t.Fatalf("Issue() error = %v, want unavailable", err)
			}
		})
	}
	if !issuer.BoundTo(plan, jailer, topology) {
		t.Fatal("BoundTo() rejected exact issuer binding")
	}
	topology.GuestNICCount = 1
	if issuer.BoundTo(plan, jailer, topology) {
		t.Fatal("BoundTo() accepted a widened topology")
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

func signedProxyAuthorityEnvelope(t *testing.T, lease sandboxauthority.EgressLease, fence uint64, now time.Time) (sandboxhostprotocol.Envelope, []byte) {
	t.Helper()
	envelope := proxyAuthorityEnvelope(t, lease, fence)
	envelope.ProtocolVersion = sandboxhostprotocol.Version
	envelope.Nonce = "nonce-001"
	envelope.IssuedAt = now
	envelope.HostGeneration = 1
	envelope.LeaseEpoch = 1
	envelope.Tenant = "tenant-001"
	envelope.Principal = lease.Principal
	envelope.EffectiveSpecDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	envelope.CapabilityDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	envelope.CanonicalRequestDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	envelope.SequenceContract = "host-proposed/control-owned-v1"
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sandboxhostprotocol.SignEnvelope(envelope, "control-key-001", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	var signed sandboxhostprotocol.Envelope
	if err := json.Unmarshal(wire, &signed); err != nil {
		t.Fatal(err)
	}
	return signed, wire
}
