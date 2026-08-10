package agentspecbackfillkube_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfill"
	"github.com/0x63616c/agent-runtime/internal/agentspecbackfillcr"
	"github.com/0x63616c/agent-runtime/internal/agentspecbackfillkube"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
)

func TestAdapterListsCanonicalRequestsAndStartsItsWatchAtTheListVersion(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	first := testRequest(t, now, "3")
	second := testRequest(t, now, "4")
	resource := &recordingResource{list: &unstructured.UnstructuredList{Object: map[string]any{"metadata": map[string]any{"resourceVersion": "91"}}, Items: []unstructured.Unstructured{second, first}}}
	adapter, err := agentspecbackfillkube.New(testConfig(), resource)
	if err != nil {
		t.Fatal(err)
	}

	wires, err := adapter.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(wires) != 2 || string(wires[0]) >= string(wires[1]) {
		t.Fatalf("expected canonical sorted request wires, got %q", wires)
	}
	if _, err := agentspecbackfillcr.ParseRequest(bytes.NewReader(wires[0])); err != nil {
		t.Fatalf("first wire was not canonical: %v", err)
	}
	if _, err := adapter.Watch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if resource.watchOptions.ResourceVersion != "91" || resource.watchOptions.AllowWatchBookmarks != true {
		t.Fatalf("watch did not use list resource version: %#v", resource.watchOptions)
	}
}

func TestAdapterConditionallyWritesOneTerminalStatusWithoutOverwritingItsWinner(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	object := testRequest(t, now, "3")
	resource := &recordingResource{list: &unstructured.UnstructuredList{Object: map[string]any{"metadata": map[string]any{"resourceVersion": "91"}}, Items: []unstructured.Unstructured{object}}, object: object.DeepCopy()}
	adapter, err := agentspecbackfillkube.New(testConfig(), resource)
	if err != nil {
		t.Fatal(err)
	}
	wires, err := adapter.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request, err := agentspecbackfillcr.ParseRequest(bytes.NewReader(wires[0]))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := request.Spec.Digest()
	if err != nil {
		t.Fatal(err)
	}
	candidate := agentspecbackfillcr.Status{Phase: agentspecbackfill.PhaseVerified, RequestUID: request.Metadata.UID, ObservedGeneration: request.Metadata.Generation, ControllerImageDigest: request.Spec.ControllerImageDigest, RequestDigest: digest, SnapshotFingerprint: request.Spec.SnapshotFingerprint, SnapshotCount: request.Spec.SnapshotCount, ManifestDigest: request.Spec.ManifestDigest, StaticReadinessDigest: request.Spec.StaticReadinessDigest, VerifiedCount: request.Spec.SnapshotCount, CompletedAt: now}

	stored, created, err := adapter.CreateTerminal(context.Background(), request, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !created || !equalStatus(stored, candidate) || resource.statusUpdates != 1 {
		t.Fatalf("expected one terminal winner, got stored=%+v created=%t updates=%d", stored, created, resource.statusUpdates)
	}
	loser := candidate
	loser.CompletedAt = loser.CompletedAt.Add(time.Nanosecond)
	stored, created, err = adapter.CreateTerminal(context.Background(), request, loser)
	if err != nil {
		t.Fatal(err)
	}
	if created || !equalStatus(stored, candidate) || resource.statusUpdates != 1 {
		t.Fatalf("expected existing terminal winner without overwrite, got stored=%+v created=%t updates=%d", stored, created, resource.statusUpdates)
	}
}

func TestAdapterPreservesCallerCancellationAndClassifiesControlPlaneErrors(t *testing.T) {
	t.Parallel()
	resource := &recordingResource{listError: apierrors.NewForbidden(schema.GroupResource{Group: "runtime.0x63616c.dev", Resource: "agentspecbackfills"}, "asb-test", errors.New("denied"))}
	adapter, err := agentspecbackfillkube.New(testConfig(), resource)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adapter.List(ctx); !errors.Is(err, context.Canceled) || resource.listCalls != 0 {
		t.Fatalf("expected cancellation before API I/O, got err=%v calls=%d", err, resource.listCalls)
	}
	if _, err := adapter.List(context.Background()); !errors.Is(err, agentspecbackfillkube.ErrPermissionDenied) || errors.Is(err, agentspecbackfillkube.ErrUnavailable) {
		t.Fatalf("expected safe permission classification, got %v", err)
	}
	resource.listError = context.DeadlineExceeded
	if _, err := adapter.List(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline to be preserved, got %v", err)
	}
}

func TestAdapterRefusesAnObjectOutsideItsDeclaredNamespace(t *testing.T) {
	t.Parallel()
	object := testRequest(t, time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC), "3")
	object.SetNamespace("other-namespace")
	resource := &recordingResource{list: &unstructured.UnstructuredList{Object: map[string]any{"metadata": map[string]any{"resourceVersion": "91"}}, Items: []unstructured.Unstructured{object}}}
	adapter, err := agentspecbackfillkube.New(testConfig(), resource)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.List(context.Background()); !errors.Is(err, agentspecbackfillkube.ErrInvalidObject) {
		t.Fatalf("expected foreign namespace to be refused, got %v", err)
	}
}

func TestAdapterDoesNotOpenAWatchAfterCallerCancellation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	resource := &recordingResource{list: &unstructured.UnstructuredList{Object: map[string]any{"metadata": map[string]any{"resourceVersion": "91"}}, Items: []unstructured.Unstructured{testRequest(t, now, "3")}}}
	adapter, err := agentspecbackfillkube.New(testConfig(), resource)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adapter.Watch(ctx); !errors.Is(err, context.Canceled) || resource.watchCalls != 0 {
		t.Fatalf("expected cancellation before opening watch, got err=%v calls=%d", err, resource.watchCalls)
	}
}

func TestWatchClassifiesAPIServerPermissionEventsWithoutExposingTheirBody(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	stream := watch.NewRaceFreeFake()
	resource := &recordingResource{list: &unstructured.UnstructuredList{Object: map[string]any{"metadata": map[string]any{"resourceVersion": "91"}}, Items: []unstructured.Unstructured{testRequest(t, now, "3")}}, stream: stream}
	adapter, err := agentspecbackfillkube.New(testConfig(), resource)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	reader, err := adapter.Watch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	delivered := make(chan struct{})
	go func() {
		stream.Error(&metav1.Status{Status: metav1.StatusFailure, Code: 403, Reason: metav1.StatusReasonForbidden, Message: "sensitive API error body"})
		close(delivered)
	}()
	_, err = reader.Next(context.Background())
	<-delivered
	if !errors.Is(err, agentspecbackfillkube.ErrPermissionDenied) || strings.Contains(err.Error(), "sensitive API error body") {
		t.Fatalf("expected safe permission watch failure, got %v", err)
	}
}

func TestAdapterRefusesStatusWriteWithoutAResourceVersion(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	object := testRequest(t, now, "3")
	object.SetResourceVersion("")
	resource := &recordingResource{list: &unstructured.UnstructuredList{Object: map[string]any{"metadata": map[string]any{"resourceVersion": "91"}}, Items: []unstructured.Unstructured{object}}, object: object.DeepCopy()}
	adapter, err := agentspecbackfillkube.New(testConfig(), resource)
	if err != nil {
		t.Fatal(err)
	}
	wires, err := adapter.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request, err := agentspecbackfillcr.ParseRequest(bytes.NewReader(wires[0]))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := request.Spec.Digest()
	if err != nil {
		t.Fatal(err)
	}
	candidate := agentspecbackfillcr.Status{Phase: agentspecbackfill.PhaseVerified, RequestUID: request.Metadata.UID, ObservedGeneration: request.Metadata.Generation, ControllerImageDigest: request.Spec.ControllerImageDigest, RequestDigest: digest, SnapshotFingerprint: request.Spec.SnapshotFingerprint, SnapshotCount: request.Spec.SnapshotCount, ManifestDigest: request.Spec.ManifestDigest, StaticReadinessDigest: request.Spec.StaticReadinessDigest, VerifiedCount: request.Spec.SnapshotCount, CompletedAt: now}
	if _, _, err := adapter.CreateTerminal(context.Background(), request, candidate); !errors.Is(err, agentspecbackfillkube.ErrInvalidObject) || resource.statusUpdates != 0 {
		t.Fatalf("expected missing resource version to stop CAS, got err=%v updates=%d", err, resource.statusUpdates)
	}
}

func TestAdapterReturnsTheTerminalWinnerAfterAResourceVersionConflict(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	object := testRequest(t, now, "3")
	resource := &recordingResource{list: &unstructured.UnstructuredList{Object: map[string]any{"metadata": map[string]any{"resourceVersion": "91"}}, Items: []unstructured.Unstructured{object}}, object: object.DeepCopy()}
	adapter, err := agentspecbackfillkube.New(testConfig(), resource)
	if err != nil {
		t.Fatal(err)
	}
	wires, err := adapter.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request, err := agentspecbackfillcr.ParseRequest(bytes.NewReader(wires[0]))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := request.Spec.Digest()
	if err != nil {
		t.Fatal(err)
	}
	candidate := agentspecbackfillcr.Status{Phase: agentspecbackfill.PhaseVerified, RequestUID: request.Metadata.UID, ObservedGeneration: request.Metadata.Generation, ControllerImageDigest: request.Spec.ControllerImageDigest, RequestDigest: digest, SnapshotFingerprint: request.Spec.SnapshotFingerprint, SnapshotCount: request.Spec.SnapshotCount, ManifestDigest: request.Spec.ManifestDigest, StaticReadinessDigest: request.Spec.StaticReadinessDigest, VerifiedCount: request.Spec.SnapshotCount, CompletedAt: now}
	winner := candidate
	winner.CompletedAt = winner.CompletedAt.Add(time.Nanosecond)
	resource.updateError = apierrors.NewConflict(schema.GroupResource{Group: "runtime.0x63616c.dev", Resource: "agentspecbackfills"}, request.Metadata.Name, errors.New("competing status writer"))
	resource.onStatusUpdate = func() {
		encoded, encodeErr := winner.CanonicalFor(request, winner.CompletedAt)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		var value map[string]any
		if unmarshalErr := json.Unmarshal(encoded, &value); unmarshalErr != nil {
			t.Fatal(unmarshalErr)
		}
		if setErr := unstructured.SetNestedMap(resource.object.Object, value, "status"); setErr != nil {
			t.Fatal(setErr)
		}
		resource.object.SetResourceVersion("2")
	}

	stored, created, err := adapter.CreateTerminal(context.Background(), request, candidate)
	if err != nil || created || !equalStatus(stored, winner) || resource.statusUpdates != 1 {
		t.Fatalf("expected conflict winner, got stored=%+v created=%t updates=%d err=%v", stored, created, resource.statusUpdates, err)
	}
}

func TestAdapterRefusesMalformedNonterminalStatusBeforeAnyOverwrite(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	object := testRequest(t, now, "3")
	if err := unstructured.SetNestedMap(object.Object, map[string]any{"phase": "Pending"}, "status"); err != nil {
		t.Fatal(err)
	}
	resource := &recordingResource{list: &unstructured.UnstructuredList{Object: map[string]any{"metadata": map[string]any{"resourceVersion": "91"}}, Items: []unstructured.Unstructured{object}}, object: object.DeepCopy()}
	adapter, err := agentspecbackfillkube.New(testConfig(), resource)
	if err != nil {
		t.Fatal(err)
	}
	wires, err := adapter.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request, err := agentspecbackfillcr.ParseRequest(bytes.NewReader(wires[0]))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := request.Spec.Digest()
	if err != nil {
		t.Fatal(err)
	}
	candidate := agentspecbackfillcr.Status{Phase: agentspecbackfill.PhaseVerified, RequestUID: request.Metadata.UID, ObservedGeneration: request.Metadata.Generation, ControllerImageDigest: request.Spec.ControllerImageDigest, RequestDigest: digest, SnapshotFingerprint: request.Spec.SnapshotFingerprint, SnapshotCount: request.Spec.SnapshotCount, ManifestDigest: request.Spec.ManifestDigest, StaticReadinessDigest: request.Spec.StaticReadinessDigest, VerifiedCount: request.Spec.SnapshotCount, CompletedAt: now}
	if _, _, err := adapter.CreateTerminal(context.Background(), request, candidate); !errors.Is(err, agentspecbackfillkube.ErrInvalidObject) || resource.statusUpdates != 0 {
		t.Fatalf("expected malformed status to stop overwrite, got err=%v updates=%d", err, resource.statusUpdates)
	}
}

func testConfig() agentspecbackfillkube.Config {
	return agentspecbackfillkube.Config{APIServerURL: "https://kubernetes.example.test:6443", Namespace: "agent-spec-backfill", CAFile: "/var/run/certs/ca.crt", TokenFile: "/var/run/tokens/controller", TLSServerName: "kubernetes.example.test", RequestTimeout: time.Second}
}

func testRequest(t *testing.T, now time.Time, manifestNibble string) unstructured.Unstructured {
	t.Helper()
	spec := agentspecbackfill.Request{StackDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", MigrationVersion: 4, MigrationArtifactDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222", ManifestDigest: "sha256:" + strings.Repeat(manifestNibble, 64), ControllerImageDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444", SnapshotFingerprint: "sha256:5555555555555555555555555555555555555555555555555555555555555555", SnapshotCount: 1, FenceNonce: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY", StaticReadinessDigest: "sha256:6666666666666666666666666666666666666666666666666666666666666666", DatabaseAuthorityDigest: "sha256:7777777777777777777777777777777777777777777777777777777777777777", BlobReadCapabilityDigest: "sha256:8888888888888888888888888888888888888888888888888888888888888888", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	request, err := agentspecbackfillcr.NewRequest(spec)
	if err != nil {
		t.Fatal(err)
	}
	request.Metadata.UID, request.Metadata.Generation = "uid-01", 1
	encoded, err := request.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	object["metadata"].(map[string]any)["resourceVersion"] = "1"
	result := unstructured.Unstructured{Object: object}
	result.SetUID("uid-01")
	result.SetGeneration(1)
	result.SetNamespace("agent-spec-backfill")
	return result
}

type recordingResource struct {
	list           *unstructured.UnstructuredList
	listError      error
	listCalls      int
	watchOptions   metav1.ListOptions
	watchCalls     int
	object         *unstructured.Unstructured
	statusUpdates  int
	stream         *watch.RaceFreeFakeWatcher
	updateError    error
	onStatusUpdate func()
}

func (resource *recordingResource) List(context.Context, metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	resource.listCalls++
	return resource.list, resource.listError
}

func (resource *recordingResource) Watch(_ context.Context, options metav1.ListOptions) (watch.Interface, error) {
	resource.watchCalls++
	resource.watchOptions = options
	if resource.stream != nil {
		return resource.stream, nil
	}
	return watch.NewRaceFreeFake(), nil
}

func (resource *recordingResource) Get(context.Context, string, metav1.GetOptions) (*unstructured.Unstructured, error) {
	return resource.object.DeepCopy(), nil
}

func (resource *recordingResource) UpdateStatus(_ context.Context, object *unstructured.Unstructured, _ metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	resource.statusUpdates++
	if resource.onStatusUpdate != nil {
		resource.onStatusUpdate()
	}
	if resource.updateError != nil {
		return nil, resource.updateError
	}
	resource.object = object.DeepCopy()
	resource.object.SetResourceVersion("2")
	return resource.object.DeepCopy(), nil
}

func equalStatus(left, right agentspecbackfillcr.Status) bool {
	return left.Phase == right.Phase && left.RequestUID == right.RequestUID && left.ObservedGeneration == right.ObservedGeneration && left.ControllerImageDigest == right.ControllerImageDigest && left.RequestDigest == right.RequestDigest && left.SnapshotFingerprint == right.SnapshotFingerprint && left.SnapshotCount == right.SnapshotCount && left.ManifestDigest == right.ManifestDigest && left.StaticReadinessDigest == right.StaticReadinessDigest && left.VerifiedCount == right.VerifiedCount && left.Reason == right.Reason && left.CompletedAt.Equal(right.CompletedAt)
}
