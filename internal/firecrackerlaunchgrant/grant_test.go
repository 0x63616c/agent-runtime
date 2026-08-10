package firecrackerlaunchgrant

import (
	"bytes"
	"encoding/json"
	stderrors "errors"
	"reflect"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/sandbox"
)

// The private host-execution seam accepts a grant, never a DispatchBody. This
// test fixes the one operator-only boot-probe binding that a later M3/M4
// executor may consume; it does not expose a sandbox operation.
func TestGrantCanonicalCodecBindsOneOperatorBootProbeToOneM3EnvelopeAndM4Identity(t *testing.T) {
	issuedAt := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	grant, err := New(
		EnvelopeTuple{
			EnvelopeID:             "envelope_01",
			DeliveryID:             "delivery_01",
			HostID:                 "host_01",
			HostGeneration:         7,
			AssignmentID:           "assignment_01",
			LeaseEpoch:             4,
			FencingToken:           4,
			Tenant:                 "tenant_01",
			Principal:              "tenant_01:operator_01",
			SandboxID:              "sbx_01",
			OperationID:            "operation_01",
			OperationKind:          OperatorBootProbeOperation,
			EffectiveSpecDigest:    testDigest('a'),
			CapabilityDigest:       testDigest('b'),
			CanonicalRequestDigest: testDigest('c'),
		},
		TrustedM4Identity{
			VMID:            "sandbox-001",
			FixtureVersion:  "fixture-v1",
			PlanDigest:      testDigest('d'),
			FixtureDigest:   testDigest('e'),
			StageDigest:     testDigest('f'),
			AuthorityDigest: testDigest('0'),
		},
		"MDEyMzQ1Njc4OWFiY2RlZg",
		issuedAt,
		issuedAt.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got, want := grant.SerialMarker, "AGENT_RUNTIME_FC_SMOKE sandbox-001 fixture-v1 agent-runtime-firecracker-guest/v1"; got != want {
		t.Fatalf("SerialMarker = %q, want %q", got, want)
	}
	if grant.GuestProtocol != GuestProtocolV1 {
		t.Fatalf("GuestProtocol = %q, want %q", grant.GuestProtocol, GuestProtocolV1)
	}

	wire, err := Encode(grant)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(wire)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if !reflect.DeepEqual(decoded, grant) {
		t.Fatalf("Decode(Encode()) = %#v, want %#v", decoded, grant)
	}
	if got, want := string(wire), `{"version":"firecracker-launch-grant/v1","envelope":{"envelope_id":"envelope_01","delivery_id":"delivery_01","host_id":"host_01","host_generation":7,"assignment_id":"assignment_01","lease_epoch":4,"fencing_token":4,"tenant":"tenant_01","principal":"tenant_01:operator_01","sandbox_id":"sbx_01","operation_id":"operation_01","operation_kind":"firecracker-boot-probe","effective_spec_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","capability_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","canonical_request_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"m4":{"vm_id":"sandbox-001","fixture_version":"fixture-v1","plan_digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","fixture_digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","stage_digest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","authority_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"nonce":"MDEyMzQ1Njc4OWFiY2RlZg","issued_at":"2026-08-10T12:00:00Z","deadline":"2026-08-10T12:02:00Z","guest_protocol":"agent-runtime-firecracker-guest/v1","serial_marker":"AGENT_RUNTIME_FC_SMOKE sandbox-001 fixture-v1 agent-runtime-firecracker-guest/v1"}`; got != want {
		t.Fatalf("Encode() = %s, want %s", got, want)
	}
}

func TestDecodeRefusesAnInjectedRawDispatchBody(t *testing.T) {
	grant := validGrant(t)
	wire, err := Encode(grant)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	withBody := append(append([]byte(nil), wire[:len(wire)-1]...), []byte(`,"dispatch_body":{"untrusted":"request"}}`)...)
	if _, err := Decode(withBody); err == nil {
		t.Fatal("Decode() accepted an injected raw DispatchBody")
	}
}

func TestDecodeRefusesNonCanonicalGrantBytes(t *testing.T) {
	wire, err := Encode(validGrant(t))
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if _, err := Decode(append([]byte(" "), wire...)); err == nil {
		t.Fatal("Decode() accepted non-canonical whitespace")
	}
}

func TestNewRefusesAValueOutsideTheFixedBootProbeBinding(t *testing.T) {
	base := validGrant(t)
	for name, mutate := range map[string]func(*EnvelopeTuple, *TrustedM4Identity, *string, *time.Time){
		"different operation": func(envelope *EnvelopeTuple, _ *TrustedM4Identity, _ *string, _ *time.Time) {
			envelope.OperationKind = "close-sandbox"
		},
		"untrusted M4 stage digest": func(_ *EnvelopeTuple, identity *TrustedM4Identity, _ *string, _ *time.Time) {
			identity.StageDigest = "sha256:not-a-digest"
		},
		"short nonce": func(_ *EnvelopeTuple, _ *TrustedM4Identity, nonce *string, _ *time.Time) {
			*nonce = "short"
		},
		"unbounded deadline": func(_ *EnvelopeTuple, _ *TrustedM4Identity, _ *string, deadline *time.Time) {
			*deadline = base.IssuedAt.Add(6 * time.Minute)
		},
	} {
		t.Run(name, func(t *testing.T) {
			envelope, identity, nonce, deadline := base.Envelope, base.M4, base.Nonce, base.Deadline
			mutate(&envelope, &identity, &nonce, &deadline)
			if _, err := New(envelope, identity, nonce, base.IssuedAt, deadline); err == nil {
				t.Fatal("New() accepted a widened boot-probe binding")
			}
		})
	}
}

func TestValidateBindingRefusesACanonicalGrantWhoseM4AuthorityDigestDrifts(t *testing.T) {
	grant := validGrant(t)
	wire, err := Encode(grant)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(wire)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	expected := decoded.M4
	expected.AuthorityDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := ValidateBinding(decoded, decoded.Envelope, expected, decoded.IssuedAt.Add(time.Minute)); err == nil {
		t.Fatal("ValidateBinding() accepted a grant whose M4 authority binding drifted")
	}
}

func TestDecodeRefusesACanonicalButSemanticallyWidenedGrant(t *testing.T) {
	grant := validGrant(t)
	grant.Envelope.OperationKind = "close-sandbox"
	wire, err := json.Marshal(grant)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if _, err := Decode(wire); err == nil {
		t.Fatal("Decode() accepted a canonical grant with a public operation kind")
	}
}

func TestEncodeRefusesAGrantWithAnUnboundedDeadline(t *testing.T) {
	grant := validGrant(t)
	grant.Deadline = grant.IssuedAt.Add(5*time.Minute + time.Nanosecond)
	if _, err := Encode(grant); err == nil {
		t.Fatal("Encode() accepted a grant past its maximum deadline")
	}
}

func TestDecodeClassifiesAnOversizedWireAsAnInvalidGrant(t *testing.T) {
	canonical, err := Encode(validGrant(t))
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	wire := append(bytes.Repeat([]byte(" "), 16<<10+1), canonical...)
	if _, err := Decode(wire); !stderrors.Is(err, ErrInvalidGrant) {
		t.Fatalf("Decode(oversized) error = %v, want ErrInvalidGrant", err)
	}
}

func testDigest(nibble rune) sandbox.Digest {
	return sandbox.Digest("sha256:" + string(repeatRune(nibble, 64)))
}

func repeatRune(value rune, count int) []rune {
	result := make([]rune, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func validGrant(t *testing.T) Grant {
	t.Helper()
	issuedAt := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	grant, err := New(EnvelopeTuple{EnvelopeID: "envelope_01", DeliveryID: "delivery_01", HostID: "host_01", HostGeneration: 7, AssignmentID: "assignment_01", LeaseEpoch: 4, FencingToken: 4, Tenant: "tenant_01", Principal: "tenant_01:operator_01", SandboxID: "sbx_01", OperationID: "operation_01", OperationKind: OperatorBootProbeOperation, EffectiveSpecDigest: testDigest('a'), CapabilityDigest: testDigest('b'), CanonicalRequestDigest: testDigest('c')}, TrustedM4Identity{VMID: "sandbox-001", FixtureVersion: "fixture-v1", PlanDigest: testDigest('d'), FixtureDigest: testDigest('e'), StageDigest: testDigest('f'), AuthorityDigest: testDigest('0')}, "MDEyMzQ1Njc4OWFiY2RlZg", issuedAt, issuedAt.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return grant
}
