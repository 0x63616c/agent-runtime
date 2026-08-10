package agentspecbackfillexportprocess_test

import (
	"context"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfill"
	"github.com/0x63616c/agent-runtime/internal/agentspecbackfillexportprocess"
	"github.com/0x63616c/agent-runtime/internal/clock"
)

func TestProcessExportsTerminalEvidenceFromItsDedicatedSourceAfterRequestExpiry(t *testing.T) {
	evidence := validTerminalEvidence(t)
	archive := &recordingArchive{}
	exporter, err := agentspecbackfill.NewTerminalArchiveExporter(agentspecbackfill.ArchiveExportConfig{Prefix: "retained/preflight"}, archive)
	if err != nil {
		t.Fatalf("new archive exporter: %v", err)
	}
	source := &recordingSource{items: []agentspecbackfill.TerminalArchiveEvidence{evidence}}
	current, err := clock.NewFake(evidence.Request.ExpiresAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("new fake clock: %v", err)
	}
	process, err := agentspecbackfillexportprocess.New(agentspecbackfillexportprocess.Config{PollInterval: time.Second}, source, exporter, current, func(context.Context, time.Duration) error { return context.Canceled })
	if err != nil {
		t.Fatalf("new export process: %v", err)
	}

	if _, err := process.RunOnce(context.Background()); err != nil {
		t.Fatalf("run export process once: %v", err)
	}
	if source.calls != 1 || archive.calls != 1 || archive.key != "retained/preflight/agentspecbackfill/v1/1c8e3d7a-2f8b-4eea-b71a-000000000001/sha256-a6c4897e72695f6b4884080058c1ab90b2750c4e814ee6008e04a747abad7fc4.cbor" || !archive.bundle.CertificatePresent() || archive.bundle.AuditCode() != "legacy_spec_verified" {
		t.Fatalf("source calls=%d archive calls=%d key=%q certificate=%t audit=%q", source.calls, archive.calls, archive.key, archive.bundle.CertificatePresent(), archive.bundle.AuditCode())
	}
}

type recordingSource struct {
	items []agentspecbackfill.TerminalArchiveEvidence
	calls int
}

func (source *recordingSource) ListTerminalEvidence(context.Context) ([]agentspecbackfill.TerminalArchiveEvidence, error) {
	source.calls++
	return source.items, nil
}

type recordingArchive struct {
	key    string
	bundle agentspecbackfill.ArchiveBundle
	calls  int
}

func (archive *recordingArchive) PutIfAbsent(_ context.Context, key string, bundle agentspecbackfill.ArchiveBundle, digest string) (agentspecbackfill.ArchiveReceipt, error) {
	archive.calls++
	archive.key, archive.bundle = key, bundle
	return agentspecbackfill.ArchiveReceipt{Created: true, Key: key, CanonicalDigest: digest}, nil
}

func validTerminalEvidence(t *testing.T) agentspecbackfill.TerminalArchiveEvidence {
	t.Helper()
	request := agentspecbackfill.Request{
		StackDigest:              "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		MigrationVersion:         4,
		MigrationArtifactDigest:  "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		ManifestDigest:           "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		ControllerImageDigest:    "sha256:4444444444444444444444444444444444444444444444444444444444444444",
		SnapshotFingerprint:      "sha256:5555555555555555555555555555555555555555555555555555555555555555",
		SnapshotCount:            1,
		FenceNonce:               "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
		StaticReadinessDigest:    "sha256:6666666666666666666666666666666666666666666666666666666666666666",
		DatabaseAuthorityDigest:  "sha256:7777777777777777777777777777777777777777777777777777777777777777",
		BlobReadCapabilityDigest: "sha256:8888888888888888888888888888888888888888888888888888888888888888",
		CreatedAt:                time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC),
		ExpiresAt:                time.Date(2026, 8, 9, 0, 10, 0, 0, time.UTC),
	}
	digest, err := request.Digest()
	if err != nil {
		t.Fatalf("request digest: %v", err)
	}
	return agentspecbackfill.TerminalArchiveEvidence{
		RequestUID:    "1c8e3d7a-2f8b-4eea-b71a-000000000001",
		RequestDigest: digest,
		Request:       request,
		Status: agentspecbackfill.Status{
			Phase:               agentspecbackfill.PhaseVerified,
			RequestDigest:       digest,
			SnapshotFingerprint: request.SnapshotFingerprint,
			SnapshotCount:       request.SnapshotCount,
			CompletedAt:         request.CreatedAt.Add(time.Second),
		},
		Audit: agentspecbackfill.Audit{Code: "legacy_spec_verified"},
		Certificate: &agentspecbackfill.CertificateInput{
			Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
}
