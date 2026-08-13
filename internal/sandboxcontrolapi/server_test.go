package sandboxcontrolapi

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrol"
	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestControlHandlerPersistsSubmitGetAndWatchAcrossProcessRestart(t *testing.T) {
	now := time.Date(2030, 8, 7, 2, 0, 0, 0, time.UTC)
	fakeClock, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	store := sandboxcontrol.NewMemoryLedger()
	authenticator := mapAuthenticator{
		"Bearer principal-a-token": {Authority: "issuer-a", Tenant: "tenant-a", Subject: "subject-a", Principal: "tenant-a:subject-a"},
		"Bearer principal-b-token": {Authority: "issuer-a", Tenant: "tenant-a", Subject: "subject-b", Principal: "tenant-a:subject-b"},
	}
	key := bytes.Repeat([]byte{0x42}, 32)
	first := newTestServer(t, testServerConfig(store, authenticator, fakeClock, key))
	clientA := newPublicClient(t, first, "principal-a-token")
	capabilities, err := clientA.Capabilities(context.Background())
	if err != nil || capabilities.SchemaVersion == "" || capabilities.Digest == "" || capabilities.ControlProtocol.ContractVersion == "" {
		t.Fatalf("Capabilities() = %#v, %v", capabilities, err)
	}
	capabilities.ControlProtocol.LimitPrecision = append(capabilities.ControlProtocol.LimitPrecision, "caller-mutation")
	again, err := clientA.Capabilities(context.Background())
	if err != nil || len(again.ControlProtocol.LimitPrecision) != 0 {
		t.Fatalf("Capabilities() returned mutable service state: %#v, %v", again, err)
	}

	request := sandbox.OperationRequest{ID: "op_durable", Kind: sandbox.OperationCloseSandbox, CloseSandbox: &sandbox.CloseSandboxRequest{SandboxID: "sbx_durable"}}
	ref, err := clientA.Submit(context.Background(), request)
	if err != nil || ref.ID != request.ID || ref.AcceptedAt != now {
		t.Fatalf("Submit() = %#v, %v", ref, err)
	}
	operation, err := clientA.GetOperation(context.Background(), request.ID)
	if err != nil || operation.Ref != ref || operation.State != sandbox.OperationAccepted || operation.Target.SandboxID != "sbx_durable" || operation.LatestCursor != "operation:1" {
		t.Fatalf("GetOperation() = %#v, %v", operation, err)
	}
	if operation.CapabilityDigest != again.Digest {
		t.Fatalf("operation capability digest = %q, want advertised %q", operation.CapabilityDigest, again.Digest)
	}
	stream, err := clientA.WatchOperation(context.Background(), request.ID, "")
	if err != nil {
		t.Fatalf("WatchOperation() error = %v", err)
	}
	event, err := stream.Next(context.Background())
	if err != nil || event.Kind != sandbox.OperationEventUpdate || event.Cursor != "operation:1" || event.Update == nil || event.Update.Ref != ref {
		t.Fatalf("operation event = %#v, %v", event, err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}

	first.Close()
	second := newTestServer(t, testServerConfig(store, authenticator, fakeClock, key))
	clientAfterRestart := newPublicClient(t, second, "principal-a-token")
	reconnected, err := clientAfterRestart.Submit(context.Background(), request)
	if err != nil || reconnected != ref {
		t.Fatalf("Submit(after process restart) = %#v, %v; want %#v", reconnected, err, ref)
	}
	got, err := clientAfterRestart.GetOperation(context.Background(), request.ID)
	if err != nil || got.Ref != ref || got.EffectiveSpecDigest != operation.EffectiveSpecDigest {
		t.Fatalf("GetOperation(after process restart) = %#v, %v", got, err)
	}
}

func TestControlHandlerRejectsChangedInputOtherPrincipalAndBindingMismatch(t *testing.T) {
	now := time.Date(2030, 8, 7, 2, 0, 0, 0, time.UTC)
	fakeClock, _ := clock.NewFake(now)
	store := sandboxcontrol.NewMemoryLedger()
	authenticator := mapAuthenticator{
		"Bearer principal-a-token": {Authority: "issuer-a", Tenant: "tenant-a", Subject: "subject-a", Principal: "tenant-a:subject-a"},
		"Bearer principal-b-token": {Authority: "issuer-a", Tenant: "tenant-a", Subject: "subject-b", Principal: "tenant-a:subject-b"},
	}
	server := newTestServer(t, testServerConfig(store, authenticator, fakeClock, bytes.Repeat([]byte{0x24}, 32)))
	clientA := newPublicClient(t, server, "principal-a-token")
	request := sandbox.OperationRequest{ID: "op_private", Kind: sandbox.OperationCloseSandbox, CloseSandbox: &sandbox.CloseSandboxRequest{SandboxID: "sbx_private"}}
	if _, err := clientA.Submit(context.Background(), request); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	changed := request
	changed.CloseSandbox = &sandbox.CloseSandboxRequest{SandboxID: "sbx_changed"}
	if _, err := clientA.Submit(context.Background(), changed); failureCode(err) != sandbox.FailureOperationConflict {
		t.Fatalf("changed Submit() error = %v", err)
	}

	clientB := newPublicClient(t, server, "principal-b-token")
	if _, err := clientB.GetOperation(context.Background(), request.ID); failureCode(err) != sandbox.FailureNotFoundOrDenied {
		t.Fatalf("cross-principal GetOperation() error = %v", err)
	}
	if _, err := clientB.GetOperation(context.Background(), "op_unknown"); failureCode(err) != sandbox.FailureNotFoundOrDenied {
		t.Fatalf("unknown GetOperation() error = %v", err)
	}
	if _, err := clientB.Submit(context.Background(), request); failureCode(err) != sandbox.FailureNotFoundOrDenied {
		t.Fatalf("cross-principal collision Submit() error = %v", err)
	}

	assertion := bindAssertion(t, server, "principal-a-token")
	req, err := http.NewRequest(http.MethodGet, server.URL+operationsPath+"/op_private", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer principal-b-token")
	req.Header.Set(bindingHeader, assertion)
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close response body: %v", err)
		}
	}()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("mismatched credential/binding status = %d, want 403", response.StatusCode)
	}
}

func TestControlHandlerPersistsResolvedCopyDispatchRatherThanCallerInput(t *testing.T) {
	now := time.Date(2030, 8, 7, 2, 0, 0, 0, time.UTC)
	fakeClock, _ := clock.NewFake(now)
	store := sandboxcontrol.NewMemoryLedger()
	server := newTestServer(t, testServerConfig(store, mapAuthenticator{"Bearer token": {Authority: "issuer", Tenant: "tenant", Subject: "subject", Principal: "tenant:subject"}}, fakeClock, bytes.Repeat([]byte{0x26}, 32)))
	client := newPublicClient(t, server, "token")
	request := sandbox.OperationRequest{ID: "op_resolved_copy", Kind: sandbox.OperationCopyIn, CopyIn: &sandbox.CopyInRequest{SandboxID: "sbx_001", Source: sandbox.ArtifactRef{ID: "art_001", MediaType: "text/plain", SizeBytes: 1, Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}, Destination: "/workspace/input.txt"}}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatalf("Submit(copy-in) = %v", err)
	}
	stored, err := store.Get(context.Background(), "tenant:subject", string(request.ID))
	if err != nil {
		t.Fatal(err)
	}
	dispatch, err := sandbox.DecodeControlOperationRequest([]byte(stored.DispatchBody))
	if err != nil || dispatch.CopyIn == nil || dispatch.CopyIn.Options.Overwrite != sandbox.OverwriteFailIfExists {
		t.Fatalf("durable resolved copy dispatch = %#v, %v", dispatch, err)
	}
}

func TestControlHandlerAdmitsStableOpaqueVolumeProjection(t *testing.T) {
	now := time.Date(2030, 8, 7, 2, 0, 0, 0, time.UTC)
	fakeClock, _ := clock.NewFake(now)
	store := &volumeAdmissionStore{MemoryLedger: sandboxcontrol.NewMemoryLedger(), resources: sandboxcontrol.NewMemoryResourceReadModel()}
	authenticator := mapAuthenticator{
		"Bearer token":       {Authority: "issuer", Tenant: "tenant", Subject: "subject", Principal: "tenant:subject"},
		"Bearer other-token": {Authority: "issuer", Tenant: "tenant", Subject: "other", Principal: "tenant:other"},
	}
	server := newTestServer(t, testServerConfig(store, authenticator, fakeClock, bytes.Repeat([]byte{0x55}, 32)))
	client := newPublicClient(t, server, "token")
	request := sandbox.OperationRequest{ID: "op_volume_admission", Kind: sandbox.OperationCreateVolume, CreateVolume: &sandbox.CreateVolumeRequest{Spec: sandbox.VolumeSpec{SizeBytes: 512, Inodes: 8}}}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatalf("Submit(create-volume) error = %v", err)
	}
	operation, err := client.GetOperation(context.Background(), request.ID)
	if err != nil || operation.Target.Kind != sandbox.TargetVolume || operation.Target.VolumeID == "" || string(operation.Target.VolumeID) == string(request.ID) {
		t.Fatalf("GetOperation(create-volume) = %#v, %v", operation, err)
	}
	if _, err := client.Submit(context.Background(), request); err != nil {
		t.Fatalf("Submit(create-volume retry) error = %v", err)
	}
	if store.volume.ID != operation.Target.VolumeID || store.volume.SizeBytes != 512 || store.volume.Inodes != 8 || store.binding == nil || store.binding.Kind != sandboxcontrol.ResourceProjectionVolume || store.binding.ResourceID != string(operation.Target.VolumeID) {
		t.Fatalf("admitted volume projection = %#v binding=%#v", store.volume, store.binding)
	}
	volume, err := client.GetVolume(context.Background(), operation.Target.VolumeID)
	if err != nil || volume.ID != operation.Target.VolumeID || volume.SizeBytes != 512 || volume.Inodes != 8 {
		t.Fatalf("GetVolume() = %#v, %v", volume, err)
	}
	page, err := client.ListVolumes(context.Background(), sandbox.Page{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != operation.Target.VolumeID || page.Next != "" {
		t.Fatalf("ListVolumes() = %#v, %v", page, err)
	}
	other := newPublicClient(t, server, "other-token")
	if _, err := other.GetVolume(context.Background(), operation.Target.VolumeID); failureCode(err) != sandbox.FailureNotFoundOrDenied {
		t.Fatalf("GetVolume(cross principal) error = %v", err)
	}
}

func TestControlHandlerServesPrincipalScopedDurableProcessProjection(t *testing.T) {
	now := time.Date(2030, 8, 7, 2, 0, 0, 0, time.UTC)
	fakeClock, _ := clock.NewFake(now)
	store := &processReadStore{MemoryLedger: sandboxcontrol.NewMemoryLedger(), resources: sandboxcontrol.NewMemoryResourceReadModel()}
	process := sandbox.ProcessInfo{ID: "prc_durable_process", SandboxID: "sbx_durable_parent", State: sandbox.ProcessRunning}
	if err := store.resources.ProjectProcess(context.Background(), "tenant:subject", process); err != nil {
		t.Fatal(err)
	}
	authenticator := mapAuthenticator{
		"Bearer token":       {Authority: "issuer", Tenant: "tenant", Subject: "subject", Principal: "tenant:subject"},
		"Bearer other-token": {Authority: "issuer", Tenant: "tenant", Subject: "other", Principal: "tenant:other"},
	}
	server := newTestServer(t, testServerConfig(store, authenticator, fakeClock, bytes.Repeat([]byte{0x57}, 32)))
	client := newPublicClient(t, server, "token")
	got, err := client.GetProcess(context.Background(), process.ID)
	if err != nil || got.ID != process.ID || got.SandboxID != process.SandboxID || got.State != sandbox.ProcessRunning {
		t.Fatalf("GetProcess() = %#v, %v", got, err)
	}
	other := newPublicClient(t, server, "other-token")
	if _, err := other.GetProcess(context.Background(), process.ID); failureCode(err) != sandbox.FailureNotFoundOrDenied {
		t.Fatalf("GetProcess(cross principal) error = %v", err)
	}
}

// volumeAdmissionStore is a test-only control admission seam. Production uses
// PostgresResourceReadModel, whose acceptance/projection transaction is
// covered by the PostgreSQL integration suite.
type volumeAdmissionStore struct {
	*sandboxcontrol.MemoryLedger
	resources *sandboxcontrol.MemoryResourceReadModel
	volume    sandbox.VolumeInfo
	binding   *sandboxcontrol.ResourceProjectionBinding
}

type processReadStore struct {
	*sandboxcontrol.MemoryLedger
	resources *sandboxcontrol.MemoryResourceReadModel
}

func (store *processReadStore) GetProcess(ctx context.Context, principal string, id sandbox.ProcessID) (sandbox.ProcessInfo, error) {
	return store.resources.GetProcess(ctx, principal, id)
}

func (store *volumeAdmissionStore) AcceptVolume(ctx context.Context, operation sandboxcontrol.Operation, value sandbox.VolumeInfo) (sandboxcontrol.Operation, bool, error) {
	accepted, replay, err := store.Accept(ctx, operation)
	if err == nil && !replay {
		store.volume = value
		if err := store.resources.ProjectVolume(ctx, operation.Principal, value); err != nil {
			return sandboxcontrol.Operation{}, false, err
		}
		binding := *operation.ResourceProjectionBinding
		store.binding = &binding
	}
	return accepted, replay, err
}

func (store *volumeAdmissionStore) TransitionVolume(ctx context.Context, principal, operationID string, version uint64, next sandboxcontrol.State, value sandbox.VolumeInfo) (sandboxcontrol.Operation, error) {
	return sandboxcontrol.Operation{}, errors.New("test volume transition is not implemented")
}

func (store *volumeAdmissionStore) GetVolume(ctx context.Context, principal string, id sandbox.VolumeID) (sandbox.VolumeInfo, error) {
	return store.resources.GetVolume(ctx, principal, id)
}
func (store *volumeAdmissionStore) ListVolumes(ctx context.Context, principal string, page sandbox.Page) (sandbox.VolumePage, error) {
	return store.resources.ListVolumes(ctx, principal, page)
}

func TestControlHandlerBoundsBodiesAndHonorsCancelledWait(t *testing.T) {
	now := time.Date(2030, 8, 7, 2, 0, 0, 0, time.UTC)
	fakeClock, _ := clock.NewFake(now)
	store := sandboxcontrol.NewMemoryLedger()
	authenticator, err := NewStaticAuthenticator("Bearer token", Identity{Authority: "issuer", Tenant: "tenant", Subject: "subject", Principal: "tenant:subject"})
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServer(t, testServerConfig(store, authenticator, fakeClock, bytes.Repeat([]byte{0x66}, 32)))
	assertion := bindAssertion(t, server, "token")

	oversized := bytes.NewReader(make([]byte, maxRequestBytes+1))
	request, err := http.NewRequest(http.MethodPost, server.URL+operationsPath, oversized)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set(bindingHeader, assertion)
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close oversized response body: %v", err)
	}
	if response.StatusCode != http.StatusBadRequest && response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status = %d", response.StatusCode)
	}

	client := newPublicClient(t, server, "token")
	op := sandbox.OperationRequest{ID: "op_waiting", Kind: sandbox.OperationCloseSandbox, CloseSandbox: &sandbox.CloseSandboxRequest{SandboxID: "sbx_waiting"}}
	if _, err := client.Submit(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.WaitOperation(cancelled, op.ID); !errors.Is(err, context.Canceled) || failureCode(err) != sandbox.FailureCancelled {
		t.Fatalf("cancelled WaitOperation() error = %v", err)
	}
}

func testServerConfig(store sandboxcontrol.DurableStore, authenticator Authenticator, source clock.Clock, key []byte) Config {
	limits := sandbox.ResourceLimits{MilliCPU: 100, MemoryBytes: 1024, RootDiskBytes: 1024, TmpfsBytes: 1024, PIDs: 10, ProcessCount: 10, OpenFiles: 10, Inodes: 10, Files: 10, Lifetime: time.Hour, ProducedOutputBytes: 1024, RetainedOutputBytes: 1024, TransferBytes: 1024, NetworkConnections: 10, VolumeBytes: 1024, SnapshotBytes: 1024}
	return Config{Store: store, Authenticator: authenticator, AssertionKey: key, Entropy: bytes.NewReader(bytes.Repeat([]byte{0x99}, 4096)), Clock: source, BindingLifetime: time.Hour, Retention: 24 * time.Hour, WaitInterval: time.Millisecond, Wait: waitForContext, Admission: sandbox.OperationAdmissionPolicy{Defaults: limits, Maximum: limits}}
}

func waitForContext(ctx context.Context, _ time.Duration) error {
	<-ctx.Done()
	return ctx.Err()
}

func newTestServer(t *testing.T, config Config) *httptest.Server {
	t.Helper()
	handler, err := NewHandler(config)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return server
}

func newPublicClient(t *testing.T, server *httptest.Server, token string) sandbox.Client {
	t.Helper()
	certificate := server.Certificate()
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	trust, err := sandbox.NewStaticTrustBundleSource(map[sandbox.TrustBundleRef]sandbox.TrustBundle{"trust/test": {Version: "test/v1", PEMRoots: roots}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := sandbox.NewClient(context.Background(), sandbox.ClientConfig{Endpoint: sandbox.Endpoint{URL: server.URL}, TLS: sandbox.TLSConfig{ServerName: certificate.DNSNames[0], TrustBundleRef: "trust/test"}, Credentials: testCredentials(token), TrustBundles: trust, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	return client
}

func bindAssertion(t *testing.T, server *httptest.Server, token string) string {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, server.URL+bindPath, bytes.NewReader(canonicalBindRequest))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close bind response body: %v", err)
		}
	}()
	var body bindResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.Assertion
}

type testCredentials string

func (credentials testCredentials) Apply(_ context.Context, sink sandbox.CredentialSink) error {
	return sink.SetAuthorization("Bearer", string(credentials))
}

type mapAuthenticator map[string]Identity

func (authenticator mapAuthenticator) Authenticate(ctx context.Context, authorization string) (Identity, error) {
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	identity, ok := authenticator[authorization]
	if !ok {
		return Identity{}, errors.New("denied")
	}
	return identity, nil
}

func failureCode(err error) sandbox.FailureCode {
	failure, _ := sandbox.AsFailure(err)
	return failure.Code
}

var _ sandbox.CredentialSource = testCredentials("")
var _ Authenticator = mapAuthenticator{}
