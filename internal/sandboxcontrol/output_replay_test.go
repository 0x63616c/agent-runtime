package sandboxcontrol

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestMemoryLedgerReplaysOnlyDurableRedactedOutputForItsProcessPrincipal(t *testing.T) {
	now := time.Date(2030, 8, 7, 1, 2, 3, 0, time.UTC)
	ledger := NewMemoryLedger()
	host := HostEnrollment{HostID: "host_output_replay", Tenant: "tenant_01", Pool: "pool_01", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("a"), SigningPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), CapabilityDigest: digest("b"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	if err := ledger.ProvisionHost(context.Background(), host, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	operation := Operation{Principal: "tenant_01:subject_01", Tenant: host.Tenant, ID: "op_output_replay", Kind: "exec-process", TargetKind: "process", TargetID: "prc_output_replay", InputDigest: digest("1"), CanonicalDigest: digest("2"), EffectiveSpecDigest: digest("3"), CapabilityDigest: host.CapabilityDigest, DispatchBody: `{"version":"sandbox.control/v1"}`, AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour), CleanupRequired: true}
	if _, _, err := ledger.Accept(context.Background(), operation); err != nil {
		t.Fatal(err)
	}
	identity := HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}
	dispatch, err := ledger.PullHostAssignment(context.Background(), identity, now, now.Add(time.Minute), DeliverySeed{AssignmentID: "assignment_replay", EnvelopeID: "envelope_replay", DeliveryID: "delivery_replay", Nonce: "nonce_replay"}, testEnvelopeSigner)
	if err != nil {
		t.Fatal(err)
	}
	first := replayOutput(dispatch.Operation, host, "output_replay_01", "stdout", 1, []byte("safe [REDACTED]"), true, now.Add(time.Second))
	second := replayOutput(dispatch.Operation, host, "output_replay_02", "stderr", 1, []byte("diagnostic"), false, now.Add(2*time.Second))
	for _, output := range []sandboxhostprotocol.Output{first, second} {
		if duplicate, err := ledger.RecordAuthenticatedHostOutput(context.Background(), identity, output, now.Add(3*time.Second)); err != nil || duplicate {
			t.Fatalf("RecordAuthenticatedHostOutput() = %t, %v", duplicate, err)
		}
	}
	events, err := ledger.ReplayOutput(context.Background(), operation.Principal, sandbox.ProcessID(operation.TargetID), "")
	if err != nil || len(events) != 2 || string(events[0].Chunk.Bytes) != "safe [REDACTED]" || !events[0].Chunk.Redacted || string(events[1].Chunk.Bytes) != "diagnostic" || events[1].Chunk.Redacted {
		t.Fatalf("ReplayOutput() = %#v, %v", events, err)
	}
	resumed, err := ledger.ReplayOutput(context.Background(), operation.Principal, sandbox.ProcessID(operation.TargetID), events[0].Cursor)
	if err != nil || len(resumed) != 1 || resumed[0].Cursor != events[1].Cursor {
		t.Fatalf("ReplayOutput(resume) = %#v, %v", resumed, err)
	}
	if _, err := ledger.ReplayOutput(context.Background(), "tenant_01:other", sandbox.ProcessID(operation.TargetID), ""); err != nil {
		t.Fatalf("cross-principal ReplayOutput() = %v, want empty not failure", err)
	}
	if _, err := ledger.ReplayOutput(context.Background(), operation.Principal, sandbox.ProcessID(operation.TargetID), "output:missing"); err == nil {
		t.Fatal("ReplayOutput(missing cursor) = nil, want gap")
	}
}

func TestMemoryLedgerTrimsDurableOutputToTheAdmittedPerStreamRetentionLimit(t *testing.T) {
	now := time.Date(2030, 8, 7, 1, 2, 3, 0, time.UTC)
	ledger := NewMemoryLedger()
	host := HostEnrollment{HostID: "host_output_trim", Tenant: "tenant_01", Pool: "pool_01", Generation: 1, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: digest("a"), SigningPublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), CapabilityDigest: digest("b"), Status: HostActive, ExpiresAt: now.Add(time.Hour)}
	if err := ledger.ProvisionHost(context.Background(), host, AttestationInput{Profile: AttestationProfileLocalMetadata}, nil); err != nil {
		t.Fatal(err)
	}
	operation := Operation{Principal: "tenant_01:subject_01", Tenant: host.Tenant, ID: "op_output_trim", Kind: "exec-process", TargetKind: "process", TargetID: "prc_output_trim", InputDigest: digest("1"), CanonicalDigest: digest("2"), EffectiveSpecDigest: digest("3"), CapabilityDigest: host.CapabilityDigest, DispatchBody: `{"version":"sandbox.control/v1"}`, AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour), CleanupRequired: true, RetainedOutputBytes: 10}
	if _, _, err := ledger.Accept(context.Background(), operation); err != nil {
		t.Fatal(err)
	}
	identity := HostIdentity{HostID: host.HostID, Generation: host.Generation, CertificateDigest: host.CertificateDigest}
	dispatch, err := ledger.PullHostAssignment(context.Background(), identity, now, now.Add(time.Minute), DeliverySeed{AssignmentID: "assignment_trim", EnvelopeID: "envelope_trim", DeliveryID: "delivery_trim", Nonce: "nonce_trim"}, testEnvelopeSigner)
	if err != nil {
		t.Fatal(err)
	}
	first := replayOutput(dispatch.Operation, host, "output_trim_01", "stdout", 1, []byte("12345678"), false, now.Add(time.Second))
	second := replayOutput(dispatch.Operation, host, "output_trim_02", "stdout", 2, []byte("abcdefgh"), false, now.Add(2*time.Second))
	for _, output := range []sandboxhostprotocol.Output{first, second} {
		if _, err := ledger.RecordAuthenticatedHostOutput(context.Background(), identity, output, now.Add(3*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	events, err := ledger.ReplayOutput(context.Background(), operation.Principal, sandbox.ProcessID(operation.TargetID), "")
	if err != nil || len(events) != 1 || string(events[0].Chunk.Bytes) != "abcdefgh" {
		t.Fatalf("ReplayOutput() = %#v, %v", events, err)
	}
	if _, err := ledger.ReplayOutput(context.Background(), operation.Principal, sandbox.ProcessID(operation.TargetID), "output:assignment_trim:stdout:1"); err == nil {
		t.Fatal("ReplayOutput(evicted cursor) = nil, want gap")
	}
}

func replayOutput(operation Operation, host HostEnrollment, id, stream string, sequence uint64, chunk []byte, redacted bool, observedAt time.Time) sandboxhostprotocol.Output {
	return sandboxhostprotocol.Output{ProtocolVersion: sandboxhostprotocol.Version, OutputID: id, HostID: host.HostID, HostGeneration: host.Generation, AssignmentID: operation.Assignment.AssignmentID, LeaseEpoch: operation.Assignment.LeaseEpoch, FencingToken: operation.Assignment.FencingToken, Principal: operation.Principal, OperationID: operation.ID, Stream: stream, Sequence: sequence, ChunkDigest: sandboxhostprotocol.Digest(chunk), SizeBytes: uint32(len(chunk)), Chunk: append([]byte(nil), chunk...), Redacted: redacted, ObservedAt: observedAt}
}
