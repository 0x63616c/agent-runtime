package agentspecbackfill_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfill"
)

func TestRequestUsesCanonicalDigestNameAndBoundedImmutableStatus(t *testing.T) {
	request := validRequest()
	digest, err := request.Digest()
	if err != nil {
		t.Fatalf("digest request: %v", err)
	}
	if digest != "sha256:a6c4897e72695f6b4884080058c1ab90b2750c4e814ee6008e04a747abad7fc4" {
		t.Fatalf("request digest = %q", digest)
	}
	if name, err := request.Name(); err != nil || name != "asb-u3cis7tsnfpwwseebaafrqnlsczhkdcoqfhomaeoastupk5np7ca" {
		t.Fatalf("request name = %q, %v", name, err)
	}
	status := agentbackfillVerifiedStatus(t, request)
	if err := status.ValidateFor(request, time.Date(2026, 8, 9, 0, 5, 0, 0, time.UTC)); err != nil {
		t.Fatalf("validate status: %v", err)
	}
	if encoded, err := status.Canonical(); err != nil || len(encoded) == 0 {
		t.Fatalf("canonical status = %x, %v", encoded, err)
	}
	changed := status
	changed.Phase = agentspecbackfill.PhaseRefused
	if err := changed.ValidateTransitionFrom(status); err == nil {
		t.Fatal("terminal status transition succeeded")
	}
	farFuture := request
	farFuture.ExpiresAt = farFuture.CreatedAt.Add(10*time.Minute + time.Nanosecond)
	if err := farFuture.ValidateAt(request.CreatedAt); err == nil {
		t.Fatal("far-future request was accepted")
	}
	futureCreated := request
	futureCreated.CreatedAt = request.CreatedAt.Add(time.Second)
	futureCreated.ExpiresAt = futureCreated.CreatedAt.Add(time.Minute)
	if err := futureCreated.ValidateAt(request.CreatedAt); err == nil {
		t.Fatal("future-created request was accepted")
	}
	if err := request.ValidateAt(request.ExpiresAt); err == nil {
		t.Fatal("request at exact expiry was accepted")
	}
	aliasNonce := request
	aliasNonce.FenceNonce = request.FenceNonce[:len(request.FenceNonce)-1] + "Z"
	if _, err := aliasNonce.Canonical(); err == nil {
		t.Fatal("noncanonical nonce alias was accepted")
	}
	upper := request
	upper.StackDigest = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := upper.Canonical(); err == nil {
		t.Fatal("uppercase digest was accepted")
	}
	unknown := status
	unknown.Phase, unknown.Reason = agentspecbackfill.PhaseRefused, "unknown"
	if _, err := unknown.Canonical(); err == nil {
		t.Fatal("unknown refusal reason was canonicalized")
	}
	notAdmitted := agentspecbackfill.Status{Phase: agentspecbackfill.PhaseRefused, RequestDigest: mustDigest(t, futureCreated), SnapshotFingerprint: futureCreated.SnapshotFingerprint, SnapshotCount: futureCreated.SnapshotCount, Reason: agentspecbackfill.RefusalNotAdmitted, CompletedAt: request.CreatedAt}
	if err := notAdmitted.ValidateFor(futureCreated, request.CreatedAt); err != nil {
		t.Fatalf("pre-creation terminal refusal: %v", err)
	}
	lateNotAdmitted := notAdmitted
	lateNotAdmitted.CompletedAt = futureCreated.CreatedAt
	if err := lateNotAdmitted.ValidateFor(futureCreated, futureCreated.CreatedAt); err == nil {
		t.Fatal("not-admitted status at creation was accepted")
	}
	tooEarlyContent := status
	tooEarlyContent.Phase, tooEarlyContent.Reason = agentspecbackfill.PhaseRefused, agentspecbackfill.RefusalContent
	tooEarlyContent.CompletedAt = request.CreatedAt.Add(-time.Nanosecond)
	if err := tooEarlyContent.ValidateFor(request, request.CreatedAt); err == nil {
		t.Fatal("pre-creation content refusal was accepted")
	}
	expiredTooEarly := status
	expiredTooEarly.Phase, expiredTooEarly.Reason = agentspecbackfill.PhaseRefused, agentspecbackfill.RefusalExpired
	if err := expiredTooEarly.ValidateFor(request, request.ExpiresAt.Add(-time.Nanosecond)); err == nil {
		t.Fatal("pre-expiry expired status was accepted")
	}
	if err := status.ValidateFor(request, request.ExpiresAt); err == nil {
		t.Fatal("verified status was accepted at expiry")
	}
}

func TestVerifyRefusesFrozenSnapshotAndImmutableContentFailures(t *testing.T) {
	request := validRequest()
	set := agentspecbackfill.FrozenLegacySet{
		Snapshot:  agentspecbackfill.Snapshot{Fingerprint: request.SnapshotFingerprint, Count: 1},
		Revisions: []agentspecbackfill.LegacyRevision{{TenantID: "tenant_a", AgentID: "agent_0000000000000001", RevisionID: "arev_0000000000000001", SpecificationDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SpecificationSizeBytes: 42}},
	}
	for _, failure := range []struct {
		err    error
		reason agentspecbackfill.Reason
	}{{agentspecbackfill.ErrStaleSnapshot, agentspecbackfill.RefusalSnapshot}, {agentspecbackfill.ErrWrongOwner, agentspecbackfill.RefusalContent}, {agentspecbackfill.ErrContentIntegrity, agentspecbackfill.RefusalContent}} {
		status, err := agentspecbackfill.Verify(context.Background(), request, fixedReader{set: set}, failingVerifier{err: failure.err}, time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC))
		if err != nil {
			t.Fatalf("verify %v: %v", failure.err, err)
		}
		if status.Phase != agentspecbackfill.PhaseRefused || status.Reason != failure.reason {
			t.Fatalf("failure %v status = %#v", failure.err, status)
		}
	}
	stale := set
	stale.Snapshot.Fingerprint = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	status, err := agentspecbackfill.Verify(context.Background(), request, fixedReader{set: stale}, passingVerifier{}, time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC))
	if err != nil || status.Phase != agentspecbackfill.PhaseRefused || status.Reason != agentspecbackfill.RefusalSnapshot {
		t.Fatalf("stale snapshot = %#v, %v", status, err)
	}
	expired := request
	expired.ExpiresAt = time.Date(2026, 8, 9, 0, 0, 30, 0, time.UTC)
	status, err = agentspecbackfill.Verify(context.Background(), expired, fixedReader{set: set}, passingVerifier{}, time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC))
	if err != nil || status.Phase != agentspecbackfill.PhaseRefused || status.Reason != agentspecbackfill.RefusalExpired {
		t.Fatalf("expired request = %#v, %v", status, err)
	}
	reader := &countingReader{set: set}
	status, err = agentspecbackfill.Verify(context.Background(), expired, reader, passingVerifier{}, time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC))
	if err != nil || status.Phase != agentspecbackfill.PhaseRefused || status.Reason != agentspecbackfill.RefusalExpired || reader.calls != 0 {
		t.Fatalf("expired request I/O = %#v, %v, calls=%d", status, err, reader.calls)
	}
	reader = &countingReader{set: set}
	status, err = agentspecbackfill.Verify(context.Background(), request, reader, passingVerifier{}, request.ExpiresAt)
	if err != nil || status.Phase != agentspecbackfill.PhaseRefused || status.Reason != agentspecbackfill.RefusalExpired || reader.calls != 0 {
		t.Fatalf("exact-expiry request I/O = %#v, %v, calls=%d", status, err, reader.calls)
	}
	future := request
	future.CreatedAt = request.CreatedAt.Add(time.Second)
	future.ExpiresAt = future.CreatedAt.Add(time.Minute)
	reader = &countingReader{set: set}
	status, err = agentspecbackfill.Verify(context.Background(), future, reader, passingVerifier{}, request.CreatedAt)
	if err != nil || status.Phase != agentspecbackfill.PhaseRefused || status.Reason != agentspecbackfill.RefusalNotAdmitted || reader.calls != 0 {
		t.Fatalf("future-created request I/O = %#v, %v, calls=%d", status, err, reader.calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = agentspecbackfill.Verify(ctx, request, fixedReader{set: set}, passingVerifier{}, time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled verification error = %v", err)
	}
	transient := errors.New("temporary reader failure")
	_, err = agentspecbackfill.Verify(context.Background(), request, errorReader{err: transient}, passingVerifier{}, time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC))
	if !errors.Is(err, transient) {
		t.Fatalf("transient reader error = %v", err)
	}
	_, err = agentspecbackfill.Verify(context.Background(), request, fixedReader{set: set}, failingVerifier{err: transient}, time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC))
	if !errors.Is(err, transient) {
		t.Fatalf("transient verifier error = %v", err)
	}
	cancelledReader := cancelThenReader{set: set}
	ctx, cancel = context.WithCancel(context.Background())
	cancelledReader.cancel = cancel
	_, err = agentspecbackfill.Verify(ctx, request, cancelledReader, passingVerifier{}, time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("reader cancellation ignored = %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	_, err = agentspecbackfill.Verify(ctx, request, fixedReader{set: set}, cancelThenVerifier{cancel: cancel}, time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("verifier cancellation ignored = %v", err)
	}
}

func TestArchiveIsRequestKeyedAndRetainsCertificateAbsentTerminalResult(t *testing.T) {
	request := validRequest()
	status := agentspecbackfill.Status{Phase: agentspecbackfill.PhaseRefused, RequestDigest: mustDigest(t, request), SnapshotFingerprint: request.SnapshotFingerprint, SnapshotCount: request.SnapshotCount, Reason: agentspecbackfill.RefusalContent, CompletedAt: time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC)}
	bundle, err := agentspecbackfill.NewArchiveBundle(request, status, agentspecbackfill.Audit{Code: "content"}, nil)
	if err != nil {
		t.Fatalf("new archive bundle: %v", err)
	}
	if bundle.CertificatePresent() {
		t.Fatal("refused terminal result has certificate")
	}
	if key := bundle.Key("retained/preflight"); key != "retained/preflight/agentspecbackfill/v1/asb-u3cis7tsnfpwwseebaafrqnlsczhkdcoqfhomaeoastupk5np7ca/sha256-a6c4897e72695f6b4884080058c1ab90b2750c4e814ee6008e04a747abad7fc4.cbor" {
		t.Fatalf("archive key = %q", key)
	}
	if _, err := bundle.Canonical(); err != nil {
		t.Fatalf("canonical archive: %v", err)
	}
	later := status
	later.CompletedAt = later.CompletedAt.Add(time.Second)
	laterBundle, err := agentspecbackfill.NewArchiveBundle(request, later, agentspecbackfill.Audit{Code: "content"}, nil)
	if err != nil {
		t.Fatalf("new later archive bundle: %v", err)
	}
	first, _ := bundle.Canonical()
	second, _ := laterBundle.Canonical()
	if string(first) == string(second) {
		t.Fatal("archive omitted terminal status completion time")
	}
}

func validRequest() agentspecbackfill.Request {
	return agentspecbackfill.Request{StackDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", MigrationVersion: 4, MigrationArtifactDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222", ManifestDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333", ControllerImageDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444", SnapshotFingerprint: "sha256:5555555555555555555555555555555555555555555555555555555555555555", SnapshotCount: 1, FenceNonce: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY", StaticReadinessDigest: "sha256:6666666666666666666666666666666666666666666666666666666666666666", DatabaseAuthorityDigest: "sha256:7777777777777777777777777777777777777777777777777777777777777777", BlobReadCapabilityDigest: "sha256:8888888888888888888888888888888888888888888888888888888888888888", CreatedAt: time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 8, 9, 0, 10, 0, 0, time.UTC)}
}

func mustDigest(t *testing.T, request agentspecbackfill.Request) string {
	t.Helper()
	value, err := request.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func agentbackfillVerifiedStatus(t *testing.T, request agentspecbackfill.Request) agentspecbackfill.Status {
	t.Helper()
	return agentspecbackfill.Status{Phase: agentspecbackfill.PhaseVerified, RequestDigest: mustDigest(t, request), SnapshotFingerprint: request.SnapshotFingerprint, SnapshotCount: request.SnapshotCount, CompletedAt: time.Date(2026, 8, 9, 0, 1, 0, 0, time.UTC)}
}

type fixedReader struct {
	set agentspecbackfill.FrozenLegacySet
}

type countingReader struct {
	set   agentspecbackfill.FrozenLegacySet
	calls int
}

func (reader *countingReader) ReadFrozen(context.Context) (agentspecbackfill.FrozenLegacySet, error) {
	reader.calls++
	return reader.set, nil
}

type errorReader struct{ err error }

func (reader errorReader) ReadFrozen(context.Context) (agentspecbackfill.FrozenLegacySet, error) {
	return agentspecbackfill.FrozenLegacySet{}, reader.err
}

type cancelThenReader struct {
	set    agentspecbackfill.FrozenLegacySet
	cancel context.CancelFunc
}

func (reader cancelThenReader) ReadFrozen(context.Context) (agentspecbackfill.FrozenLegacySet, error) {
	reader.cancel()
	return reader.set, nil
}

func (reader fixedReader) ReadFrozen(context.Context) (agentspecbackfill.FrozenLegacySet, error) {
	return reader.set, nil
}

type failingVerifier struct{ err error }

func (verifier failingVerifier) VerifyImmutable(context.Context, agentspecbackfill.LegacyRevision) error {
	return verifier.err
}

type passingVerifier struct{}

func (passingVerifier) VerifyImmutable(context.Context, agentspecbackfill.LegacyRevision) error {
	return nil
}

type cancelThenVerifier struct{ cancel context.CancelFunc }

func (verifier cancelThenVerifier) VerifyImmutable(context.Context, agentspecbackfill.LegacyRevision) error {
	verifier.cancel()
	return nil
}
