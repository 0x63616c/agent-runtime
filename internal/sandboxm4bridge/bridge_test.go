package sandboxm4bridge

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/firecrackerlaunchgrant"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestNewBootProbeCapabilityMintsOnlyFromTheCurrentSignedHostAssignment(t *testing.T) {
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	observationPublic, observationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := sandboxhostprotocol.TrustBundle{Version: 1, RevocationEpoch: 4, Current: sandboxhostprotocol.SigningKey{ID: "control_01", Version: 2, PublicKey: controlPublic, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}}
	envelope := bridgeEnvelope(now, observationPublic)
	wire, err := sandboxhostprotocol.SignEnvelopeWithTrust(envelope, trust, controlPrivate)
	if err != nil {
		t.Fatal(err)
	}

	capability, err := NewBootProbeCapability(wire, "host_01", 7, trust, observationPrivate, now.Add(time.Second), bridgeM4Identity())
	if err != nil {
		t.Fatalf("NewBootProbeCapability() error = %v", err)
	}
	grant := capability.Grant()
	if grant.Envelope.AssignmentID != envelope.AssignmentID || grant.Envelope.LeaseEpoch != envelope.LeaseEpoch || grant.Envelope.FencingToken != envelope.FencingToken || grant.Envelope.Tenant != envelope.Tenant || grant.Envelope.HostID != envelope.HostID || grant.Envelope.HostGeneration != envelope.HostGeneration {
		t.Fatalf("Grant() lost signed assignment authority: %#v", grant.Envelope)
	}
}

func TestNewBootProbeCapabilityRefusesAnEnvelopeBoundToAnotherObservationKey(t *testing.T) {
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	observationPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := sandboxhostprotocol.TrustBundle{Version: 1, RevocationEpoch: 4, Current: sandboxhostprotocol.SigningKey{ID: "control_01", Version: 2, PublicKey: controlPublic, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}}
	wire, err := sandboxhostprotocol.SignEnvelopeWithTrust(bridgeEnvelope(now, observationPublic), trust, controlPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewBootProbeCapability(wire, "host_01", 7, trust, wrongPrivate, now.Add(time.Second), bridgeM4Identity()); err == nil {
		t.Fatal("NewBootProbeCapability() accepted a host observation key not enrolled in the signed assignment")
	}
}

func TestNewBootProbeCapabilityRefusesARevokedTrustEpoch(t *testing.T) {
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	observationPublic, observationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuedTrust := sandboxhostprotocol.TrustBundle{Version: 1, RevocationEpoch: 4, Current: sandboxhostprotocol.SigningKey{ID: "control_01", Version: 2, PublicKey: controlPublic, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}}
	wire, err := sandboxhostprotocol.SignEnvelopeWithTrust(bridgeEnvelope(now, observationPublic), issuedTrust, controlPrivate)
	if err != nil {
		t.Fatal(err)
	}
	revokedTrust := issuedTrust
	revokedTrust.Version++
	revokedTrust.RevocationEpoch++
	if _, err := NewBootProbeCapability(wire, "host_01", 7, revokedTrust, observationPrivate, now.Add(time.Second), bridgeM4Identity()); err == nil {
		t.Fatal("NewBootProbeCapability() accepted a revoked control epoch")
	}
}

func bridgeEnvelope(now time.Time, observationPublic ed25519.PublicKey) sandboxhostprotocol.Envelope {
	return sandboxhostprotocol.Envelope{ProtocolVersion: sandboxhostprotocol.Version, EnvelopeID: "envelope_01", DeliveryID: "delivery_01", Nonce: "MDEyMzQ1Njc4OWFiY2RlZg", IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute), HostID: "host_01", HostGeneration: 7, HostObservationKeyDigest: sandboxhostprotocol.Digest(observationPublic), AssignmentID: "assignment_01", LeaseEpoch: 4, FencingToken: 4, Tenant: "tenant_01", Principal: "tenant_01:operator_01", SandboxID: "sbx_01", OperationID: "operation_01", OperationKind: firecrackerlaunchgrant.OperatorBootProbeOperation, EffectiveSpecDigest: string(bridgeDigest('a')), CapabilityDigest: string(bridgeDigest('b')), CanonicalRequestDigest: string(bridgeDigest('c')), SequenceContract: "host-proposed/control-owned-v1", PayloadDigest: sandboxhostprotocol.Digest([]byte(`{"operator":"boot-probe"}`)), Payload: []byte(`{"operator":"boot-probe"}`)}
}

func bridgeM4Identity() firecrackerlaunchgrant.TrustedM4Identity {
	return firecrackerlaunchgrant.TrustedM4Identity{VMID: "sandbox-001", FixtureVersion: "fixture-v1", PlanDigest: bridgeDigest('d'), FixtureDigest: bridgeDigest('e'), StageDigest: bridgeDigest('f'), AuthorityDigest: bridgeDigest('0')}
}

func bridgeDigest(nibble rune) sandbox.Digest {
	bytes := make([]rune, 64)
	for index := range bytes {
		bytes[index] = nibble
	}
	return sandbox.Digest("sha256:" + string(bytes))
}
