package agentspecbackfillprocess_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfill"
	"github.com/0x63616c/agent-runtime/internal/agentspecbackfillcr"
	"github.com/0x63616c/agent-runtime/internal/agentspecbackfillprocess"
	"github.com/0x63616c/agent-runtime/internal/clock"
)

func TestControllerRecoversWatchAndWritesTerminalStatusOnce(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	request, wire := testRequest(t, now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := &recordingWatch{next: func(context.Context) ([]byte, error) { return nil, errors.New("watch closed") }}
	second := &recordingWatch{next: func(context.Context) ([]byte, error) { cancel(); return nil, context.Canceled }}
	source := &recordingSource{lists: [][][]byte{{wire, wire}, {}}, watches: []agentspecbackfillprocess.Watch{first, second}}
	statuses := &recordingStatuses{}
	archives := &recordingArchives{}
	fakeClock, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	var waits []time.Duration
	controller, err := agentspecbackfillprocess.New(
		agentspecbackfillprocess.Config{ControllerImageDigest: request.Spec.ControllerImageDigest, WatchRetry: 25 * time.Millisecond},
		source, statuses, testReader{request: request.Spec}, passingVerifier{}, archives, fakeClock,
		func(context.Context, time.Duration) error { waits = append(waits, 25*time.Millisecond); return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Run(ctx); err != nil {
		t.Fatalf("run controller: %v", err)
	}
	if source.listCalls != 2 || source.watchCalls != 2 || len(waits) != 1 || waits[0] != 25*time.Millisecond || statuses.creates != 1 || len(archives.bundles) != 2 || !first.closed || !second.closed {
		t.Fatalf("expected one terminal write and recovered watch, got lists=%d watches=%d waits=%v creates=%d archives=%d closed=%t/%t", source.listCalls, source.watchCalls, waits, statuses.creates, len(archives.bundles), first.closed, second.closed)
	}
}

func TestControllerRefusesNonCanonicalWireBeforeDurablePorts(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	request, wire := testRequest(t, now)
	statuses := &recordingStatuses{}
	archives := &recordingArchives{}
	fakeClock, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := agentspecbackfillprocess.New(
		agentspecbackfillprocess.Config{ControllerImageDigest: request.Spec.ControllerImageDigest, WatchRetry: time.Millisecond},
		&recordingSource{}, statuses, testReader{request: request.Spec}, passingVerifier{}, archives, fakeClock, func(context.Context, time.Duration) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.ReconcileWire(context.Background(), append(wire, '\n')); err == nil {
		t.Fatal("expected noncanonical request wire to be refused")
	}
	if statuses.reads != 0 || statuses.creates != 0 || len(archives.bundles) != 0 {
		t.Fatalf("expected no durable ports for noncanonical wire, got reads=%d creates=%d archives=%d", statuses.reads, statuses.creates, len(archives.bundles))
	}
}

func TestParseRefusesAmbientKubernetesConfiguration(t *testing.T) {
	t.Parallel()
	config := `{"version":1,"controller_image_digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","watch_retry_millis":25}`
	if _, err := agentspecbackfillprocess.ParseConfig(bytes.NewBufferString(config)); err != nil {
		t.Fatalf("parse explicit controller configuration: %v", err)
	}
	withKubeConfig := `{"version":1,"controller_image_digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","watch_retry_millis":25,"kubeconfig":"/tmp/ambient"}`
	if _, err := agentspecbackfillprocess.ParseConfig(bytes.NewBufferString(withKubeConfig)); err == nil {
		t.Fatal("expected ambient Kubernetes configuration to be refused")
	}
}

type recordingSource struct {
	lists      [][][]byte
	watches    []agentspecbackfillprocess.Watch
	listCalls  int
	watchCalls int
}

func (source *recordingSource) List(context.Context) ([][]byte, error) {
	if source.listCalls >= len(source.lists) {
		return nil, nil
	}
	items := source.lists[source.listCalls]
	source.listCalls++
	return items, nil
}

func (source *recordingSource) Watch(context.Context) (agentspecbackfillprocess.Watch, error) {
	if source.watchCalls >= len(source.watches) {
		return nil, io.EOF
	}
	watch := source.watches[source.watchCalls]
	source.watchCalls++
	return watch, nil
}

type recordingWatch struct {
	next   func(context.Context) ([]byte, error)
	closed bool
}

func (watch *recordingWatch) Next(ctx context.Context) ([]byte, error) { return watch.next(ctx) }
func (watch *recordingWatch) Close() error                             { watch.closed = true; return nil }

type recordingStatuses struct {
	status  agentspecbackfillcr.Status
	found   bool
	reads   int
	creates int
}

func (store *recordingStatuses) ReadTerminal(context.Context, agentspecbackfillcr.Request) (agentspecbackfillcr.Status, bool, error) {
	store.reads++
	return store.status, store.found, nil
}

func (store *recordingStatuses) CreateTerminal(_ context.Context, _ agentspecbackfillcr.Request, status agentspecbackfillcr.Status) (agentspecbackfillcr.Status, bool, error) {
	store.creates++
	created := !store.found
	if created {
		store.status, store.found = status, true
	}
	return store.status, created, nil
}

type recordingArchives struct {
	bundles []agentspecbackfill.ArchiveBundle
}

func (archives *recordingArchives) PutIfAbsent(_ context.Context, bundle agentspecbackfill.ArchiveBundle, expected string) (agentspecbackfill.ArchiveWrite, error) {
	archives.bundles = append(archives.bundles, bundle)
	return agentspecbackfill.ArchiveWrite{Created: len(archives.bundles) == 1, CanonicalDigest: expected}, nil
}

type testReader struct{ request agentspecbackfill.Request }

func (reader testReader) ReadFrozen(context.Context) (agentspecbackfill.FrozenLegacySet, error) {
	return agentspecbackfill.FrozenLegacySet{Snapshot: agentspecbackfill.Snapshot{Fingerprint: reader.request.SnapshotFingerprint, Count: 1}, Revisions: []agentspecbackfill.LegacyRevision{{TenantID: "tenant-a", AgentID: "agent-0000000000000001", RevisionID: "arev-0000000000000001", SpecificationDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SpecificationSizeBytes: 42}}}, nil
}

type passingVerifier struct{}

func (passingVerifier) VerifyImmutable(context.Context, agentspecbackfill.LegacyRevision) error {
	return nil
}

func testRequest(t *testing.T, now time.Time) (agentspecbackfillcr.Request, []byte) {
	t.Helper()
	spec := agentspecbackfill.Request{StackDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", MigrationVersion: 4, MigrationArtifactDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222", ManifestDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333", ControllerImageDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444", SnapshotFingerprint: "sha256:5555555555555555555555555555555555555555555555555555555555555555", SnapshotCount: 1, FenceNonce: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY", StaticReadinessDigest: "sha256:6666666666666666666666666666666666666666666666666666666666666666", DatabaseAuthorityDigest: "sha256:7777777777777777777777777777777777777777777777777777777777777777", BlobReadCapabilityDigest: "sha256:8888888888888888888888888888888888888888888888888888888888888888", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	request, err := agentspecbackfillcr.NewRequest(spec)
	if err != nil {
		t.Fatal(err)
	}
	request.Metadata.UID, request.Metadata.Generation = "uid-01", 1
	wire, err := request.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return request, wire
}
