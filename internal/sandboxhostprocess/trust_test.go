package sandboxhostprocess

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/cockroachdb/errors"
)

func TestReloadControlTrustFileAcceptsSuccessorAndRetainsPriorSnapshotOnBadOrRegressedInput(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	firstPublic, firstPrivate, _ := ed25519.GenerateKey(rand.Reader)
	secondPublic, secondPrivate, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "control-trust.json")
	write := func(version uint64, current string, currentKey ed25519.PublicKey, next string, nextKey ed25519.PublicKey) {
		document := map[string]any{"version": version, "revocation_epoch": 1, "current": map[string]any{"id": current, "version": version, "public_key": base64.RawStdEncoding.EncodeToString(currentKey), "not_before": now.Add(-time.Hour), "not_after": now.Add(time.Hour)}}
		if next != "" {
			document["next"] = map[string]any{"id": next, "version": version + 1, "public_key": base64.RawStdEncoding.EncodeToString(nextKey), "not_before": now.Add(-time.Hour), "not_after": now.Add(time.Hour)}
		}
		wire, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, wire, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(1, "control_01", firstPublic, "control_02", secondPublic)
	trust, err := LoadControlTrustFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ReloadControlTrustFile(trust, path); err != nil {
		t.Fatalf("ReloadControlTrustFile(unchanged) = %v", err)
	}
	write(2, "control_02", secondPublic, "", nil)
	if err := ReloadControlTrustFile(trust, path); err != nil {
		t.Fatal(err)
	}
	envelope := processTestEnvelope(now)
	newWire, err := sandboxhostprotocol.SignEnvelopeWithTrust(envelope, trust.Snapshot(), secondPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sandboxhostprotocol.VerifyEnvelopeWithTrust(newWire, envelope.HostID, envelope.HostGeneration, now, trust.Snapshot()); err != nil {
		t.Fatal(err)
	}
	oldBundle := sandboxhostprotocol.TrustBundle{Version: 1, RevocationEpoch: 1, Current: sandboxhostprotocol.SigningKey{ID: "control_01", Version: 1, PublicKey: firstPublic, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}}
	oldWire, err := sandboxhostprotocol.SignEnvelopeWithTrust(envelope, oldBundle, firstPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sandboxhostprotocol.VerifyEnvelopeWithTrust(oldWire, envelope.HostID, envelope.HostGeneration, now, trust.Snapshot()); err == nil {
		t.Fatal("retired key was accepted")
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReloadControlTrustFile(trust, path); err == nil {
		t.Fatal("malformed trust file was accepted")
	}
	if _, err := sandboxhostprotocol.VerifyEnvelopeWithTrust(newWire, envelope.HostID, envelope.HostGeneration, now, trust.Snapshot()); err != nil {
		t.Fatal("last valid trust was not retained")
	}
	write(1, "control_02", secondPublic, "", nil)
	if err := ReloadControlTrustFile(trust, path); err == nil {
		t.Fatal("regressed trust file was accepted")
	}
}

func TestLoadControlTrustFileRefusesDuplicateJSONKeys(t *testing.T) {
	t.Parallel()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "control-trust.json")
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	wire := []byte(`{"version":1,"version":2,"revocation_epoch":1,"current":{"id":"control_01","version":1,"public_key":"` + base64.RawStdEncoding.EncodeToString(public) + `","not_before":"` + now.Add(-time.Hour).Format(time.RFC3339) + `","not_after":"` + now.Add(time.Hour).Format(time.RFC3339) + `"}}`)
	if err := os.WriteFile(path, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadControlTrustFile(path); err == nil {
		t.Fatal("duplicate trust-file key was accepted")
	}
}

func TestPollWithTrustReloadUsesOneHostLifetimeSnapshot(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	firstPublic, firstPrivate, _ := ed25519.GenerateKey(rand.Reader)
	secondPublic, secondPrivate, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "control-trust.json")
	write := func(version uint64, current string, public ed25519.PublicKey) {
		wire := []byte(`{"version":` + fmt.Sprint(version) + `,"revocation_epoch":1,"current":{"id":"` + current + `","version":` + fmt.Sprint(version) + `,"public_key":"` + base64.RawStdEncoding.EncodeToString(public) + `","not_before":"` + now.Add(-time.Hour).Format(time.RFC3339) + `","not_after":"` + now.Add(time.Hour).Format(time.RFC3339) + `"}}`)
		if err := os.WriteFile(path, wire, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(1, "control_01", firstPublic)
	trust, err := LoadControlTrustFile(path)
	if err != nil {
		t.Fatal(err)
	}
	firstBundle := trust.Snapshot()
	firstWire, err := sandboxhostprotocol.SignEnvelopeWithTrust(processTestEnvelope(now), firstBundle, firstPrivate)
	if err != nil {
		t.Fatal(err)
	}
	write(2, "control_02", secondPublic)
	secondWire, err := sandboxhostprotocol.SignEnvelopeWithTrust(processTestEnvelope(now), sandboxhostprotocol.TrustBundle{Version: 2, RevocationEpoch: 1, Current: sandboxhostprotocol.SigningKey{ID: "control_02", Version: 2, PublicKey: secondPublic, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}}, secondPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verifySuccessor := func(trust *sandboxhostprotocol.AtomicTrust) error {
		if _, err := sandboxhostprotocol.VerifyEnvelopeWithTrust(secondWire, "host_01", 1, now, trust.Snapshot()); err != nil {
			t.Fatalf("successor rejected after poll-boundary reload: %v", err)
		}
		if _, err := sandboxhostprotocol.VerifyEnvelopeWithTrust(firstWire, "host_01", 1, now, trust.Snapshot()); err == nil {
			t.Fatal("retired key accepted after poll-boundary reload")
		}
		return ErrNoWork
	}
	if err := pollWithTrustReload(trust, path, verifySuccessor); !errors.Is(err, ErrNoWork) {
		t.Fatalf("pollWithTrustReload(successor) = %v", err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pollWithTrustReload(trust, path, verifySuccessor); !errors.Is(err, ErrRetryable) {
		t.Fatalf("pollWithTrustReload(malformed) = %v, want degraded retryable status", err)
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
