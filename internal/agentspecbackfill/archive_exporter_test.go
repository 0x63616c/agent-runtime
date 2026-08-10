package agentspecbackfill_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfill"
)

func TestTerminalArchiveExporterConditionallyRetainsCertificateAbsentTerminalBundle(t *testing.T) {
	request := validRequest()
	status := agentbackfillVerifiedStatus(t, request)
	archive := &recordingConditionalArchive{}
	exporter, err := agentspecbackfill.NewTerminalArchiveExporter(archive)
	if err != nil {
		t.Fatalf("new terminal archive exporter: %v", err)
	}

	receipt, err := exporter.Export(context.Background(), request, status, status.CompletedAt)
	if err != nil {
		t.Fatalf("export terminal archive: %v", err)
	}
	if !receipt.Created || len(archive.bundles) != 1 || archive.bundles[0].CertificatePresent() {
		t.Fatalf("archive receipt = %#v, bundles=%d certificate=%t", receipt, len(archive.bundles), archive.bundles[0].CertificatePresent())
	}
	wantDigest, err := archive.bundles[0].Digest()
	if err != nil || receipt.CanonicalDigest != wantDigest {
		t.Fatalf("archive receipt digest = %q, %v, want %q", receipt.CanonicalDigest, err, wantDigest)
	}
}

func TestTerminalArchiveExporterRetainsCertificateAbsentRefusalAndReturnsIdempotentReceipt(t *testing.T) {
	request := validRequest()
	status := agentspecbackfill.Status{
		Phase:               agentspecbackfill.PhaseRefused,
		RequestDigest:       mustDigest(t, request),
		SnapshotFingerprint: request.SnapshotFingerprint,
		SnapshotCount:       request.SnapshotCount,
		Reason:              agentspecbackfill.RefusalContent,
		CompletedAt:         request.CreatedAt.Add(time.Second),
	}
	archive := &recordingConditionalArchive{receipts: make(map[string]string)}
	exporter, err := agentspecbackfill.NewTerminalArchiveExporter(archive)
	if err != nil {
		t.Fatalf("new terminal archive exporter: %v", err)
	}

	first, err := exporter.Export(context.Background(), request, status, status.CompletedAt)
	if err != nil || !first.Created || len(archive.bundles) != 1 || archive.bundles[0].CertificatePresent() {
		t.Fatalf("first refusal receipt = %#v, %v, bundles=%d", first, err, len(archive.bundles))
	}
	second, err := exporter.Export(context.Background(), request, status, status.CompletedAt)
	if err != nil || second.Created || second.CanonicalDigest != first.CanonicalDigest || len(archive.bundles) != 1 {
		t.Fatalf("idempotent refusal receipt = %#v, %v, bundles=%d", second, err, len(archive.bundles))
	}
	if got := archive.bundles[0].Key("retained/preflight"); got != "retained/preflight/agentspecbackfill/v1/asb-u3cis7tsnfpwwseebaafrqnlsczhkdcoqfhomaeoastupk5np7ca/sha256-a6c4897e72695f6b4884080058c1ab90b2750c4e814ee6008e04a747abad7fc4.cbor" {
		t.Fatalf("request-keyed archive key = %q", got)
	}
}

func TestTerminalArchiveExporterRefusesInvalidStatusAndConflictingReceiptBeforeSuccess(t *testing.T) {
	request := validRequest()
	status := agentbackfillVerifiedStatus(t, request)
	archive := &recordingConditionalArchive{existingDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	exporter, err := agentspecbackfill.NewTerminalArchiveExporter(archive)
	if err != nil {
		t.Fatalf("new terminal archive exporter: %v", err)
	}

	if _, err := exporter.Export(context.Background(), request, status, status.CompletedAt); !errors.Is(err, agentspecbackfill.ErrArchiveConflict) || archive.calls != 1 {
		t.Fatalf("conflicting receipt = %v, calls=%d", err, archive.calls)
	}
	invalid := status
	invalid.CompletedAt = status.CompletedAt.Add(time.Second)
	archive = &recordingConditionalArchive{}
	exporter, err = agentspecbackfill.NewTerminalArchiveExporter(archive)
	if err != nil {
		t.Fatalf("new terminal archive exporter: %v", err)
	}
	if _, err := exporter.Export(context.Background(), request, invalid, status.CompletedAt); err == nil || archive.calls != 0 {
		t.Fatalf("future terminal status = %v, calls=%d", err, archive.calls)
	}
}

func TestTerminalArchiveExporterCancellationPreventsArchiveIO(t *testing.T) {
	request := validRequest()
	status := agentbackfillVerifiedStatus(t, request)
	archive := &recordingConditionalArchive{}
	exporter, err := agentspecbackfill.NewTerminalArchiveExporter(archive)
	if err != nil {
		t.Fatalf("new terminal archive exporter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := exporter.Export(ctx, request, status, status.CompletedAt); !errors.Is(err, context.Canceled) || archive.calls != 0 {
		t.Fatalf("cancelled archive export = %v, calls=%d", err, archive.calls)
	}
}

type recordingConditionalArchive struct {
	bundles        []agentspecbackfill.ArchiveBundle
	receipts       map[string]string
	existingDigest string
	calls          int
}

func (archive *recordingConditionalArchive) PutIfAbsent(_ context.Context, bundle agentspecbackfill.ArchiveBundle, expectedDigest string) (agentspecbackfill.ArchiveReceipt, error) {
	archive.calls++
	if archive.existingDigest != "" {
		return agentspecbackfill.ArchiveReceipt{CanonicalDigest: archive.existingDigest}, nil
	}
	if archive.receipts == nil {
		archive.receipts = make(map[string]string)
	}
	canonical, err := bundle.Canonical()
	if err != nil {
		return agentspecbackfill.ArchiveReceipt{}, err
	}
	if observed, found := archive.receipts[string(canonical)]; found {
		return agentspecbackfill.ArchiveReceipt{CanonicalDigest: observed}, nil
	}
	archive.receipts[string(canonical)] = expectedDigest
	archive.bundles = append(archive.bundles, bundle)
	return agentspecbackfill.ArchiveReceipt{Created: true, CanonicalDigest: expectedDigest}, nil
}
