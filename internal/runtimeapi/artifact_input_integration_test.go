//go:build integration

package runtimeapi_test

import (
	"context"
	"fmt"
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
	store, err := runtimepostgres.NewRuntimeStateStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	clockSource, err := clock.NewFake(time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC))
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

func newDurableArtifactInputRuntime(t *testing.T, content *runtimecontent.Store, store runtimestate.RuntimeStateStore, clockSource clock.Clock, ids runtimestate.IdentifierSource) (*runtimeapi.StateRuntime, *runtimestate.Compiler, *runtimestate.RuntimeStatePlanner) {
	t.Helper()
	compiler, err := runtimestate.NewCompiler(content)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := runtimestate.NewRuntimeStatePlanner(clockSource, ids)
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
