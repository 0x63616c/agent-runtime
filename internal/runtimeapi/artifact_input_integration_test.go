//go:build integration

package runtimeapi_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/runtimeapi"
	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimepostgres"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// TestDurableStateRuntimeAuthorizesArtifactInputReferences proves DAT-002's
// authorization boundary against the disposable PostgreSQL/MinIO authority.
// A fresh runtime composition can admit only the owner's exact immutable
// Artifact reference; a forged digest and a second principal are safe misses.
func TestDurableStateRuntimeAuthorizesArtifactInputReferences(t *testing.T) {
	ctx := context.Background()
	dsn := requiredArtifactInputEnvironment(t, "AR_RUNTIME_API_POSTGRES_DSN")
	endpoint := requiredArtifactInputEnvironment(t, "AR_RUNTIME_API_MINIO_ENDPOINT")
	access := requiredArtifactInputEnvironment(t, "AR_RUNTIME_API_MINIO_ACCESS_KEY")
	secret := requiredArtifactInputEnvironment(t, "AR_RUNTIME_API_MINIO_SECRET_KEY")
	bucket := requiredArtifactInputEnvironment(t, "AR_RUNTIME_API_MINIO_BUCKET")
	minioClient, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(access, secret, ""), Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := minioClient.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil && minio.ToErrorResponse(err).Code != "BucketAlreadyOwnedByYou" {
		t.Fatal(err)
	}
	content := durableArtifactInputContent(t, minioClient, bucket)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	clockSource, err := clock.NewFake(time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, clockSource)
	if err != nil {
		t.Fatal(err)
	}
	runtime, compiler, planner := newDurableArtifactInputRuntime(t, content, store, clockSource, &artifactInputIDs{})
	admin := runtimeapi.Identity{Tenant: "artifact-input-postgres", Principal: "admin", Admin: true}
	alice := runtimeapi.Identity{Tenant: "artifact-input-postgres", Principal: "alice"}
	bob := runtimeapi.Identity{Tenant: "artifact-input-postgres", Principal: "bob"}
	agent, err := runtime.CreateAgent(ctx, admin, agentruntime.CreateAgentRequest{IdempotencyKey: "artifact-input-agent", Name: "artifact-owner", ModelProfile: "balanced", Instructions: "reference approved artifacts"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := runtime.CreateSession(ctx, alice, agentruntime.CreateSessionRequest{IdempotencyKey: "artifact-input-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := runtime.SendInput(ctx, alice, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "artifact-input-seed", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "produce an artifact"}}})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("artifact-input-postgres")
	principal, _ := runtimecontent.ParsePrincipalID("alice")
	handoff, err := content.StageArtifact(ctx, tenant, "text/plain", []byte("durable approved report"))
	if err != nil {
		t.Fatal(err)
	}
	mutation, err := compiler.CompileRegisterArtifact(runtimestate.RegisterArtifactCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "artifact-input-register", SessionID: session.ID, TurnID: accepted.Turn.ID, Artifact: handoff})
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.LoadRuntimeState(ctx, mutation.ReceiptBinding().Scope)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Plan(ctx, state, mutation)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PersistTransitionPlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	artifactID := plan.Result().Artifact.ArtifactID

	// Recompose application/runtime state from PostgreSQL after the immutable
	// blob and metadata have both committed; this is the durable read path.
	runtime, _, _ = newDurableArtifactInputRuntime(t, content, store, clockSource, &artifactInputIDs{next: 100})
	download, err := runtime.ReadArtifact(ctx, alice, artifactID)
	if err != nil || string(download.Body) != "durable approved report" {
		t.Fatalf("read restarted durable Artifact = %#v, %v", download, err)
	}
	stream, err := runtime.OpenArtifact(ctx, alice, artifactID)
	if err != nil {
		t.Fatalf("open restarted durable Artifact: %v", err)
	}
	streamed, readErr := io.ReadAll(stream.Body)
	closeErr := stream.Body.Close()
	if readErr != nil || closeErr != nil || string(streamed) != "durable approved report" || stream.Reference.SizeBytes != int64(len(streamed)) {
		t.Fatalf("read opened durable Artifact = %q read=%v close=%v reference=%#v", streamed, readErr, closeErr, stream.Reference)
	}
	handler, err := runtimeapi.NewHandler(runtimeapi.Config{Runtime: runtime, Authenticator: staticAuth{identities: map[string]runtimeapi.Identity{"alice-token-000000": alice}}, RequestIDs: &requestIDs{}})
	if err != nil {
		t.Fatalf("new durable Artifact handler: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	credential, err := agentruntime.NewStaticBearerCredential("alice-token-000000")
	if err != nil {
		t.Fatalf("new durable Artifact credential: %v", err)
	}
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: server.URL, HTTPClient: http.DefaultClient, Credentials: credential, RequestIDs: &requestIDs{}})
	if err != nil {
		t.Fatalf("new durable Artifact SDK client: %v", err)
	}
	httpStream, err := client.OpenArtifact(ctx, artifactID)
	if err != nil {
		t.Fatalf("open durable Artifact through HTTP/SDK: %v", err)
	}
	httpBody, readErr := io.ReadAll(httpStream.Body)
	closeErr = httpStream.Body.Close()
	if readErr != nil || closeErr != nil || string(httpBody) != "durable approved report" || httpStream.Artifact != download.Artifact {
		t.Fatalf("read durable Artifact through HTTP/SDK = %q read=%v close=%v metadata=%#v", httpBody, readErr, closeErr, httpStream.Artifact)
	}
	result, err := runtime.SendInput(ctx, alice, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "artifact-input-reference", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentArtifact, Artifact: &download.Artifact}}})
	if err != nil || len(result.Input.Parts) != 1 || result.Input.Parts[0].Artifact == nil || *result.Input.Parts[0].Artifact != download.Artifact {
		t.Fatalf("admit restarted durable Artifact Input = %#v, %v", result, err)
	}
	forged := download.Artifact
	forged.SHA256 = strings.Repeat("0", 64)
	if _, err := runtime.SendInput(ctx, alice, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "artifact-input-forged", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentArtifact, Artifact: &forged}}}); !hasFailure(err, agentruntime.FailureNotFound) {
		t.Fatalf("admit forged durable Artifact Input error = %v, want safe not-found", err)
	}
	bobSession, err := runtime.CreateSession(ctx, bob, agentruntime.CreateSessionRequest{IdempotencyKey: "artifact-input-bob-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.SendInput(ctx, bob, agentruntime.SendInputRequest{SessionID: bobSession.ID, IdempotencyKey: "artifact-input-cross-principal", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentArtifact, Artifact: &download.Artifact}}}); !hasFailure(err, agentruntime.FailureNotFound) {
		t.Fatalf("admit cross-principal durable Artifact Input error = %v, want safe not-found", err)
	}
}

// TestDurablePostgresMinIOCollectorDeletesExpiredUnreferencedArtifact proves
// the DAT-008 physical lifecycle boundary with the real PostgreSQL state
// authority and MinIO object adapter. An operator denial leaves the exact
// object and metadata intact; an authorized collection deletes only the
// expired Artifact while the live Session and Input remain durable.
func TestDurablePostgresMinIOCollectorDeletesExpiredUnreferencedArtifact(t *testing.T) {
	ctx := context.Background()
	dsn := requiredArtifactInputEnvironment(t, "AR_RUNTIME_API_POSTGRES_DSN")
	endpoint := requiredArtifactInputEnvironment(t, "AR_RUNTIME_API_MINIO_ENDPOINT")
	access := requiredArtifactInputEnvironment(t, "AR_RUNTIME_API_MINIO_ACCESS_KEY")
	secret := requiredArtifactInputEnvironment(t, "AR_RUNTIME_API_MINIO_SECRET_KEY")
	bucket := requiredArtifactInputEnvironment(t, "AR_RUNTIME_API_MINIO_BUCKET")
	minioClient, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(access, secret, ""), Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := minioClient.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil && minio.ToErrorResponse(err).Code != "BucketAlreadyOwnedByYou" {
		t.Fatal(err)
	}
	immutable, err := runtimecontent.NewMinIOImmutableClient(minioClient)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := runtimecontent.NewS3ImmutableObjects(immutable, bucket)
	if err != nil {
		t.Fatal(err)
	}
	content, err := runtimecontent.New("artifact-retention-postgres", objects)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	now := time.Date(2026, 8, 10, 15, 0, 0, 0, time.UTC)
	clockSource, err := clock.NewFake(now)
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, clockSource)
	if err != nil {
		t.Fatal(err)
	}
	retention := artifactRetention{fallback: 24 * time.Hour, artifact: time.Minute}
	runtime, compiler, planner := newDurableArtifactInputRuntimeWithRetention(t, content, store, clockSource, &artifactInputIDs{}, retention)
	admin := runtimeapi.Identity{Tenant: "artifact-retention-postgres", Principal: "admin", Admin: true}
	alice := runtimeapi.Identity{Tenant: "artifact-retention-postgres", Principal: "alice"}
	agent, err := runtime.CreateAgent(ctx, admin, agentruntime.CreateAgentRequest{IdempotencyKey: "retention-agent", Name: "retention-owner", ModelProfile: "balanced", Instructions: "retain metadata independently"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := runtime.CreateSession(ctx, alice, agentruntime.CreateSessionRequest{IdempotencyKey: "retention-session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := runtime.SendInput(ctx, alice, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "retention-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "produce a collectible artifact"}}})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := runtimecontent.ParseTenantID("artifact-retention-postgres")
	principal, _ := runtimecontent.ParsePrincipalID("alice")
	handoff, err := content.StageArtifact(ctx, tenant, "text/plain", []byte("expire only this immutable artifact"))
	if err != nil {
		t.Fatal(err)
	}
	mutation, err := compiler.CompileRegisterArtifact(runtimestate.RegisterArtifactCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthorityRuntimeWorker}, IdempotencyKey: "retention-artifact", SessionID: session.ID, TurnID: accepted.Turn.ID, Artifact: handoff})
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.LoadRuntimeState(ctx, mutation.ReceiptBinding().Scope)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Plan(ctx, state, mutation)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PersistTransitionPlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	artifact := plan.Result().Artifact
	objectKey := string(tenant) + "/artifact-retention-postgres/v1/sha256/" + strings.TrimPrefix(artifact.Reference.Digest, "sha256:")
	if _, err := minioClient.StatObject(ctx, bucket, objectKey, minio.StatObjectOptions{}); err != nil {
		t.Fatalf("stat staged Artifact before collection: %v", err)
	}
	controller, err := runtimecontent.NewTenantErasureController(content, integrationErasureAuthorizer{allowed: true}, objects)
	if err != nil {
		t.Fatal(err)
	}
	request := runtimepostgres.LifecycleRequest{Action: runtimepostgres.LifecycleCollectExpired, Tenant: tenant, AuthorizationID: "operator-artifact-retention-0001", EvaluatedAt: now.Add(time.Minute + time.Nanosecond)}
	if _, err := store.CollectExpiredAndContent(ctx, integrationLifecycleAuthorizer{allowed: false}, request, controller); !errors.Is(err, runtimestate.ErrNotFoundOrDenied) {
		t.Fatalf("deny Artifact retention collection error = %v, want safe denial", err)
	}
	if _, err := minioClient.StatObject(ctx, bucket, objectKey, minio.StatObjectOptions{}); err != nil {
		t.Fatalf("stat Artifact after denied collection: %v", err)
	}
	receipt, err := store.CollectExpiredAndContent(ctx, integrationLifecycleAuthorizer{allowed: true}, request, controller)
	if err != nil {
		t.Fatalf("collect expired Artifact metadata and MinIO object: %v", err)
	}
	if receipt.RemovedMetadata != 1 || len(receipt.Content.Deleted) != 1 || receipt.Content.Deleted[0] != artifact.Reference || receipt.Content.Failed != nil {
		t.Fatalf("Artifact collection receipt = %#v", receipt)
	}
	if _, err := minioClient.StatObject(ctx, bucket, objectKey, minio.StatObjectOptions{}); err == nil {
		t.Fatal("expired unreferenced Artifact object remains in MinIO")
	}
	restarted, _, _ := newDurableArtifactInputRuntimeWithRetention(t, content, store, clockSource, &artifactInputIDs{next: 100}, retention)
	if _, err := restarted.ReadArtifact(ctx, alice, artifact.ArtifactID); !hasFailure(err, agentruntime.FailureNotFound) {
		t.Fatalf("read collected Artifact error = %v, want safe not-found", err)
	}
	remaining, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: tenant, Principal: principal, Authority: runtimestate.AuthoritySessionOwner})
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining.Sessions) != 1 || len(remaining.Inputs) != 1 || len(remaining.Artifacts) != 0 {
		t.Fatalf("state after Artifact collection = %#v, want retained Session/Input and removed Artifact", remaining)
	}
}

// TestDurablePostgresMinIOTenantErasurePreservesAnotherTenant proves the
// DAT-010/DAT-013 operator erasure boundary through real PostgreSQL and
// MinIO authorities. A denied request preserves its target, while an
// authorized erasure removes only that tenant's exact state-referenced object
// and leaves another tenant's durable state and object untouched.
func TestDurablePostgresMinIOTenantErasurePreservesAnotherTenant(t *testing.T) {
	ctx := context.Background()
	dsn := requiredArtifactInputEnvironment(t, "AR_RUNTIME_API_POSTGRES_DSN")
	endpoint := requiredArtifactInputEnvironment(t, "AR_RUNTIME_API_MINIO_ENDPOINT")
	access := requiredArtifactInputEnvironment(t, "AR_RUNTIME_API_MINIO_ACCESS_KEY")
	secret := requiredArtifactInputEnvironment(t, "AR_RUNTIME_API_MINIO_SECRET_KEY")
	bucket := requiredArtifactInputEnvironment(t, "AR_RUNTIME_API_MINIO_BUCKET")
	minioClient, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(access, secret, ""), Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := minioClient.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil && minio.ToErrorResponse(err).Code != "BucketAlreadyOwnedByYou" {
		t.Fatal(err)
	}
	content := durableTenantErasureContent(t, minioClient, bucket)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	clockSource, err := clock.NewFake(time.Date(2026, 8, 11, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimepostgres.NewRuntimeStateStore(pool, clockSource)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(clockSource, &artifactInputIDs{})
	if err != nil {
		t.Fatal(err)
	}
	target, targetReference := seedDurableTenantErasureRevision(t, ctx, content, compiler, planner, store, "tenant-erasure-target")
	other, otherReference := seedDurableTenantErasureRevision(t, ctx, content, compiler, planner, store, "tenant-erasure-other")
	assertDurableReferenceExists(t, ctx, minioClient, bucket, target, "tenant-erasure-postgres", targetReference)
	assertDurableReferenceExists(t, ctx, minioClient, bucket, other, "tenant-erasure-postgres", otherReference)

	immutable, err := runtimecontent.NewMinIOImmutableClient(minioClient)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := runtimecontent.NewS3ImmutableObjects(immutable, bucket)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := runtimecontent.NewTenantErasureController(content, integrationErasureAuthorizer{allowed: true}, objects)
	if err != nil {
		t.Fatal(err)
	}
	request := runtimepostgres.LifecycleRequest{Action: runtimepostgres.LifecycleEraseTenant, Tenant: target, AuthorizationID: "operator-tenant-erasure-0001"}
	if _, err := store.EraseTenantAndContent(ctx, integrationLifecycleAuthorizer{allowed: false}, request, controller); !errors.Is(err, runtimestate.ErrNotFoundOrDenied) {
		t.Fatalf("deny tenant erasure error = %v, want safe denial", err)
	}
	assertDurableReferenceExists(t, ctx, minioClient, bucket, target, "tenant-erasure-postgres", targetReference)

	receipt, err := store.EraseTenantAndContent(ctx, integrationLifecycleAuthorizer{allowed: true}, request, controller)
	if err != nil {
		t.Fatalf("erase target tenant through PostgreSQL and MinIO: %v", err)
	}
	if receipt.Tenant != target || len(receipt.Content.Deleted) != 1 || receipt.Content.Deleted[0] != targetReference || receipt.Content.Failed != nil {
		t.Fatalf("target tenant erasure receipt = %#v", receipt)
	}
	assertDurableReferenceMissing(t, ctx, minioClient, bucket, target, "tenant-erasure-postgres", targetReference)
	assertDurableReferenceExists(t, ctx, minioClient, bucket, other, "tenant-erasure-postgres", otherReference)
	otherState, err := store.LoadRuntimeState(ctx, runtimestate.MutationScope{Tenant: other, Authority: runtimestate.AuthorityTenantAdministrator})
	if err != nil {
		t.Fatalf("load unaffected tenant after target erasure: %v", err)
	}
	if len(otherState.Revisions) != 1 || otherState.Revisions[0].Specification != otherReference {
		t.Fatalf("unaffected tenant state = %#v, want exact retained revision", otherState)
	}
}

func durableArtifactInputContent(t *testing.T, client *minio.Client, bucket string) *runtimecontent.Store {
	t.Helper()
	immutable, err := runtimecontent.NewMinIOImmutableClient(client)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := runtimecontent.NewS3ImmutableObjects(immutable, bucket)
	if err != nil {
		t.Fatal(err)
	}
	content, err := runtimecontent.New("artifact-input-postgres", objects)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func durableTenantErasureContent(t *testing.T, client *minio.Client, bucket string) *runtimecontent.Store {
	t.Helper()
	immutable, err := runtimecontent.NewMinIOImmutableClient(client)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := runtimecontent.NewS3ImmutableObjects(immutable, bucket)
	if err != nil {
		t.Fatal(err)
	}
	content, err := runtimecontent.New("tenant-erasure-postgres", objects)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func seedDurableTenantErasureRevision(t *testing.T, ctx context.Context, content *runtimecontent.Store, compiler *runtimestate.Compiler, planner *runtimestate.RuntimeStatePlanner, store runtimestate.RuntimeStateStore, tenantName string) (runtimecontent.TenantID, runtimecontent.Reference) {
	t.Helper()
	tenant, err := runtimecontent.ParseTenantID(tenantName)
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := content.StageAgentSpecificationBody(ctx, tenant, runtimecontent.AgentSpecificationBody{Name: "erasable-" + tenantName, ModelProfile: "balanced", Instructions: "remove only after explicit operator authorization"})
	if err != nil {
		t.Fatal(err)
	}
	mutation, err := compiler.CompileRegisterAgentRevision(runtimestate.RegisterAgentRevisionCommand{Scope: runtimestate.MutationScope{Tenant: tenant, Authority: runtimestate.AuthorityTenantAdministrator}, IdempotencyKey: "register-" + tenantName, Specification: handoff})
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.LoadRuntimeState(ctx, mutation.ReceiptBinding().Scope)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Plan(ctx, state, mutation)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PersistTransitionPlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	return tenant, plan.Result().Revision.Specification
}

func assertDurableReferenceExists(t *testing.T, ctx context.Context, client *minio.Client, bucket string, tenant runtimecontent.TenantID, contentRoot string, reference runtimecontent.Reference) {
	t.Helper()
	if _, err := client.StatObject(ctx, bucket, durableReferenceObjectKey(tenant, contentRoot, reference), minio.StatObjectOptions{}); err != nil {
		t.Fatalf("stat durable immutable object %q: %v", reference.Digest, err)
	}
}

func assertDurableReferenceMissing(t *testing.T, ctx context.Context, client *minio.Client, bucket string, tenant runtimecontent.TenantID, contentRoot string, reference runtimecontent.Reference) {
	t.Helper()
	if _, err := client.StatObject(ctx, bucket, durableReferenceObjectKey(tenant, contentRoot, reference), minio.StatObjectOptions{}); err == nil {
		t.Fatalf("erased immutable object %q remains in MinIO", reference.Digest)
	} else if response := minio.ToErrorResponse(err); response.Code != "NoSuchKey" && response.Code != "NoSuchObject" {
		t.Fatalf("stat erased immutable object %q = %v, want exact missing-object response", reference.Digest, err)
	}
}

func durableReferenceObjectKey(tenant runtimecontent.TenantID, contentRoot string, reference runtimecontent.Reference) string {
	return string(tenant) + "/" + contentRoot + "/v1/sha256/" + strings.TrimPrefix(reference.Digest, "sha256:")
}

func newDurableArtifactInputRuntime(t *testing.T, content *runtimecontent.Store, store runtimestate.RuntimeStateStore, clockSource clock.Clock, ids runtimestate.IdentifierSource) (*runtimeapi.StateRuntime, *runtimestate.Compiler, *runtimestate.RuntimeStatePlanner) {
	return newDurableArtifactInputRuntimeWithRetention(t, content, store, clockSource, ids, nil)
}

func newDurableArtifactInputRuntimeWithRetention(t *testing.T, content *runtimecontent.Store, store runtimestate.RuntimeStateStore, clockSource clock.Clock, ids runtimestate.IdentifierSource, retention runtimestate.RetentionPolicy) (*runtimeapi.StateRuntime, *runtimestate.Compiler, *runtimestate.RuntimeStatePlanner) {
	t.Helper()
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	options := []runtimestate.PlannerOption{}
	if retention != nil {
		options = append(options, runtimestate.WithRetentionPolicy(retention))
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(clockSource, ids, options...)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := runtimeapi.NewStateRuntime(runtimeapi.StateRuntimeConfig{Content: content, Compiler: compiler, Planner: planner, Store: store, ModelProfiles: []string{"balanced"}})
	if err != nil {
		t.Fatal(err)
	}
	return runtime, compiler, planner
}

func requiredArtifactInputEnvironment(t *testing.T, name string) string {
	t.Helper()
	if value := os.Getenv(name); value != "" {
		return value
	}
	t.Fatalf("%s is required for durable Artifact Input integration", name)
	return ""
}

type artifactInputIDs struct{ next uint64 }

func (ids *artifactInputIDs) NextIdentifier(kind runtimestate.IdentifierKind) (string, error) {
	ids.next++
	return fmt.Sprintf("%s_%016d", kind, ids.next), nil
}

type artifactRetention struct {
	fallback time.Duration
	artifact time.Duration
}

func (retention artifactRetention) RetainUntil(now time.Time) time.Time {
	return now.Add(retention.fallback)
}

func (retention artifactRetention) RetainClassUntil(class runtimestate.DataClass, now time.Time) time.Time {
	if class == runtimestate.DataClassArtifact {
		return now.Add(retention.artifact)
	}
	return retention.RetainUntil(now)
}

type integrationLifecycleAuthorizer struct{ allowed bool }

func (authorizer integrationLifecycleAuthorizer) AuthorizeLifecycle(context.Context, runtimepostgres.LifecycleRequest) error {
	if !authorizer.allowed {
		return errors.New("operator denied")
	}
	return nil
}

type integrationErasureAuthorizer struct{ allowed bool }

func (authorizer integrationErasureAuthorizer) AuthorizeErasure(context.Context, runtimecontent.ErasureRequest) error {
	if !authorizer.allowed {
		return errors.New("operator denied")
	}
	return nil
}
