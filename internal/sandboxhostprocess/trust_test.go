package sandboxhostprocess

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
)

func TestControlTrustReloadRotatesThenRetiresPreviousKey(t *testing.T) {
	t.Parallel()

	firstPublic, firstPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secondPublic, secondPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	first := controlTrustKeyConfig{id: "control_01", version: 1, publicKeyEnvironment: "FIRST_PUBLIC", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour)}
	second := controlTrustKeyConfig{id: "control_02", version: 2, publicKeyEnvironment: "SECOND_PUBLIC", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour)}
	lookup := func(name string) (string, bool) {
		values := map[string]string{"FIRST_PUBLIC": base64.RawStdEncoding.EncodeToString(firstPublic), "SECOND_PUBLIC": base64.RawStdEncoding.EncodeToString(secondPublic)}
		value, ok := values[name]
		return value, ok
	}
	trust, err := LoadControlTrust(controlTrustConfig{version: 1, revocationEpoch: 4, current: first, next: &second}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	oldWire, err := sandboxhostprotocol.SignEnvelopeWithTrust(processTestEnvelope(now), trust.Snapshot(), firstPrivate)
	if err != nil {
		t.Fatal(err)
	}

	if err := ReloadControlTrust(trust, controlTrustConfig{version: 2, revocationEpoch: 4, current: second, next: &first}, lookup); err != nil {
		t.Fatal(err)
	}
	if _, err := sandboxhostprotocol.VerifyEnvelopeWithTrust(oldWire, "host_01", 1, now, trust.Snapshot()); err != nil {
		t.Fatalf("previous key during overlap: %v", err)
	}
	newWire, err := sandboxhostprotocol.SignEnvelopeWithTrust(processTestEnvelope(now), trust.Snapshot(), secondPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sandboxhostprotocol.VerifyEnvelopeWithTrust(newWire, "host_01", 1, now, trust.Snapshot()); err != nil {
		t.Fatal(err)
	}

	if err := ReloadControlTrust(trust, controlTrustConfig{version: 3, revocationEpoch: 4, current: second}, lookup); err != nil {
		t.Fatal(err)
	}
	if _, err := sandboxhostprotocol.VerifyEnvelopeWithTrust(oldWire, "host_01", 1, now, trust.Snapshot()); err == nil {
		t.Fatal("retired control key remained trusted")
	}
	legacy, err := sandboxhostprotocol.SignEnvelope(processTestEnvelope(now), "control_02", secondPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sandboxhostprotocol.VerifyEnvelopeWithTrust(legacy, "host_01", 1, now, trust.Snapshot()); err == nil {
		t.Fatal("production trust accepted legacy zero key bindings")
	}
}

func TestControlTrustReloadRefusesRetiredAndRegressedKeyVersions(t *testing.T) {
	t.Parallel()

	firstPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secondPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	regressedPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	first := controlTrustKeyConfig{id: "control_01", version: 1, publicKeyEnvironment: "FIRST_PUBLIC", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour)}
	second := controlTrustKeyConfig{id: "control_02", version: 2, publicKeyEnvironment: "SECOND_PUBLIC", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour)}
	regressed := controlTrustKeyConfig{id: "control_03", version: 1, publicKeyEnvironment: "REGRESSED_PUBLIC", notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour)}
	lookup := func(name string) (string, bool) {
		values := map[string]string{
			"FIRST_PUBLIC":     base64.RawStdEncoding.EncodeToString(firstPublic),
			"SECOND_PUBLIC":    base64.RawStdEncoding.EncodeToString(secondPublic),
			"REGRESSED_PUBLIC": base64.RawStdEncoding.EncodeToString(regressedPublic),
		}
		value, ok := values[name]
		return value, ok
	}
	trust, err := LoadControlTrust(controlTrustConfig{version: 1, revocationEpoch: 4, current: first, next: &second}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if err := ReloadControlTrust(trust, controlTrustConfig{version: 2, revocationEpoch: 4, current: second}, lookup); err != nil {
		t.Fatalf("ReloadControlTrust(retire first) error = %v", err)
	}
	if err := ReloadControlTrust(trust, controlTrustConfig{version: 3, revocationEpoch: 4, current: second, next: &first}, lookup); err == nil {
		t.Fatal("ReloadControlTrust() reintroduced a retired key")
	}
	if err := ReloadControlTrust(trust, controlTrustConfig{version: 3, revocationEpoch: 4, current: second, next: &regressed}, lookup); err == nil {
		t.Fatal("ReloadControlTrust() accepted a new key with a regressed version")
	}
}

func processTestEnvelope(now time.Time) sandboxhostprotocol.Envelope {
	payload := []byte(`{"kind":"close-sandbox"}`)
	return sandboxhostprotocol.Envelope{ProtocolVersion: sandboxhostprotocol.Version, EnvelopeID: "envelope_01", DeliveryID: "delivery_01", Nonce: "nonce_01", IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), HostID: "host_01", HostGeneration: 1, AssignmentID: "assignment_01", LeaseEpoch: 1, FencingToken: 1, Tenant: "tenant_01", Principal: "tenant_01:subject_01", SandboxID: "sandbox_01", OperationID: "operation_01", OperationKind: "close-sandbox", EffectiveSpecDigest: processDigest('a'), CapabilityDigest: processDigest('b'), CanonicalRequestDigest: processDigest('c'), SequenceContract: "host-proposed/control-owned-v1", PayloadDigest: sandboxhostprotocol.Digest(payload), Payload: payload}
}

func processDigest(character byte) string {
	value := make([]byte, 64)
	for index := range value {
		value[index] = character
	}
	return "sha256:" + string(value)
}
