//go:build integration

package runtimeadmission

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresAdmissionStoresOnlyReferencesAndSerializesDistinctInputs(t *testing.T) {
	pool := openAdmissionPool(t)
	ctx := context.Background()
	resetAdmissionSchema(t, ctx, pool)
	applyAdmissionMigrations(t, ctx, pool)
	now := time.Date(2026, 8, 9, 23, 0, 0, 0, time.UTC)
	seedAdmissionSession(t, ctx, pool, "tenant_a", "alice", "sess_0000000000000001", now)

	repository, err := NewPostgresRepository(pool)
	if err != nil {
		t.Fatalf("new repository: %v", err)
	}
	content := NewMemoryContentStore()
	service, err := NewService(content, NewMemoryArtifactCatalog(), repository, fixedClock{now: now}, &integrationIDs{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	owner := Owner{TenantID: "tenant_a", PrincipalID: "alice"}
	first, err := service.SendInput(ctx, owner, agentruntime.SendInputRequest{SessionID: "sess_0000000000000001", IdempotencyKey: "send-one", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "raw prompt must stay outside postgres"}}})
	if err != nil {
		t.Fatalf("send first input: %v", err)
	}
	replay, err := service.SendInput(ctx, owner, agentruntime.SendInputRequest{SessionID: "sess_0000000000000001", IdempotencyKey: "send-one", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "raw prompt must stay outside postgres"}}})
	if err != nil {
		t.Fatalf("replay first input: %v", err)
	}
	if replay.Input.ID != first.Input.ID || replay.Turn.ID != first.Turn.ID || !replay.Input.AcceptedAt.Equal(first.Input.AcceptedAt) {
		t.Fatalf("replay = %#v, want durable original %#v", replay, first)
	}
	var digest, media string
	var size int64
	if err := pool.QueryRow(ctx, `SELECT content_digest, content_media_type, content_size_bytes FROM runtime.inputs WHERE tenant_id='tenant_a' AND principal_id='alice' AND input_id=$1`, first.Input.ID.String()).Scan(&digest, &media, &size); err != nil {
		t.Fatalf("read stored content reference: %v", err)
	}
	if digest[:7] != "sha256:" || media != InputMediaTypeV1 || size <= 0 {
		t.Fatalf("stored reference = %q %q %d", digest, media, size)
	}

	requests := []agentruntime.SendInputRequest{
		{SessionID: "sess_0000000000000001", IdempotencyKey: "send-two", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "two"}}},
		{SessionID: "sess_0000000000000001", IdempotencyKey: "send-three", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "three"}}},
	}
	results := make([]agentruntime.SendInputResult, len(requests))
	failures := make(chan error, len(requests))
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range requests {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			result, sendErr := service.SendInput(ctx, owner, requests[index])
			results[index] = result
			failures <- sendErr
		}(index)
	}
	close(start)
	wait.Wait()
	close(failures)
	for failure := range failures {
		if failure != nil {
			t.Fatalf("concurrent distinct send: %v", failure)
		}
	}
	if results[0].Turn.Position == results[1].Turn.Position || results[0].Turn.State != agentruntime.TurnQueued || results[1].Turn.State != agentruntime.TurnQueued {
		t.Fatalf("concurrent turns = %#v %#v, want distinct queued positions behind active turn", results[0].Turn, results[1].Turn)
	}
	var version, inputs, turns, audits, outbox int
	if err := pool.QueryRow(ctx, `SELECT version FROM runtime.sessions WHERE tenant_id='tenant_a' AND principal_id='alice' AND session_id='sess_0000000000000001'`).Scan(&version); err != nil {
		t.Fatalf("read session version: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime.inputs WHERE tenant_id='tenant_a' AND principal_id='alice'`).Scan(&inputs); err != nil {
		t.Fatalf("count inputs: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime.turns WHERE tenant_id='tenant_a' AND principal_id='alice'`).Scan(&turns); err != nil {
		t.Fatalf("count turns: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime.audit_records WHERE tenant_id='tenant_a'`).Scan(&audits); err != nil {
		t.Fatalf("count audit facts: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime.runtime_outbox WHERE tenant_id='tenant_a'`).Scan(&outbox); err != nil {
		t.Fatalf("count outbox facts: %v", err)
	}
	if version != 4 || inputs != 3 || turns != 3 || audits != 3 || outbox != 3 {
		t.Fatalf("durable facts version=%d inputs=%d turns=%d audits=%d outbox=%d", version, inputs, turns, audits, outbox)
	}
	if _, err := repository.AuthorizeInputRead(ctx, Owner{TenantID: "tenant_a", PrincipalID: "bob"}, "sess_0000000000000001", first.Input.ID); err == nil {
		t.Fatal("same-tenant different-principal content locator succeeded")
	}
	if _, err := repository.AuthorizeInputRead(ctx, Owner{TenantID: "tenant_b", PrincipalID: "alice"}, "sess_0000000000000001", first.Input.ID); err == nil {
		t.Fatal("cross-tenant content locator succeeded")
	}

	orphanStore := NewMemoryContentStore()
	orphanService, err := NewService(orphanStore, NewMemoryArtifactCatalog(), repository, fixedClock{now: now}, &integrationIDs{})
	if err != nil {
		t.Fatalf("new orphan service: %v", err)
	}
	_, err = orphanService.SendInput(ctx, owner, agentruntime.SendInputRequest{SessionID: "sess_0000000000000009", IdempotencyKey: "missing-session", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "orphan"}}})
	if err == nil || orphanStore.Count() != 1 {
		t.Fatalf("missing-session result=%v staged=%d, want durable refusal and retained untracked object", err, orphanStore.Count())
	}
}

func TestPostgresAdmissionRefusesUnauthorizedArtifactReferencesBeforeStaging(t *testing.T) {
	pool := openAdmissionPool(t)
	ctx := context.Background()
	resetAdmissionSchema(t, ctx, pool)
	applyAdmissionMigrations(t, ctx, pool)
	now := time.Date(2026, 8, 9, 23, 30, 0, 0, time.UTC)
	seedAdmissionSession(t, ctx, pool, "tenant_a", "alice", "sess_0000000000000001", now)
	repository, err := NewPostgresRepository(pool)
	if err != nil {
		t.Fatalf("new repository: %v", err)
	}
	store := NewMemoryContentStore()
	catalog := NewMemoryArtifactCatalog()
	allowed := agentruntime.ArtifactReference{ID: "art_0000000000000001", MediaType: "text/plain", SizeBytes: 5, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	catalog.Seed(Owner{TenantID: "tenant_a", PrincipalID: "alice"}, allowed)
	service, err := NewService(store, catalog, repository, fixedClock{now: now}, &integrationIDs{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	request := func(key string, reference agentruntime.ArtifactReference) agentruntime.SendInputRequest {
		return agentruntime.SendInputRequest{SessionID: "sess_0000000000000001", IdempotencyKey: key, Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentArtifact, Artifact: &reference}}}
	}
	if _, err := service.SendInput(ctx, Owner{TenantID: "tenant_a", PrincipalID: "alice"}, request("allowed-artifact", allowed)); err != nil {
		t.Fatalf("send authorized artifact: %v", err)
	}
	if store.Count() != 1 {
		t.Fatalf("stored authorized artifact input count = %d, want 1", store.Count())
	}
	for _, test := range []struct {
		name      string
		owner     Owner
		reference agentruntime.ArtifactReference
	}{
		{"missing", Owner{TenantID: "tenant_a", PrincipalID: "alice"}, agentruntime.ArtifactReference{ID: "art_0000000000000002", MediaType: "text/plain", SizeBytes: 5, SHA256: allowed.SHA256}},
		{"cross-tenant", Owner{TenantID: "tenant_b", PrincipalID: "alice"}, allowed},
		{"cross-principal", Owner{TenantID: "tenant_a", PrincipalID: "bob"}, allowed},
		{"metadata-mismatch", Owner{TenantID: "tenant_a", PrincipalID: "alice"}, agentruntime.ArtifactReference{ID: allowed.ID, MediaType: allowed.MediaType, SizeBytes: allowed.SizeBytes, SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.SendInput(ctx, test.owner, request("denied-"+test.name, test.reference))
			if !errors.Is(err, ErrNotFoundOrDenied) {
				t.Fatalf("send denied artifact error = %v, want ErrNotFoundOrDenied", err)
			}
			if store.Count() != 1 {
				t.Fatalf("staged content after denied artifact = %d, want 1", store.Count())
			}
		})
	}
	var inputs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime.inputs WHERE tenant_id='tenant_a' AND principal_id='alice'`).Scan(&inputs); err != nil {
		t.Fatalf("count inputs: %v", err)
	}
	if inputs != 1 {
		t.Fatalf("durable inputs after denied artifact references = %d, want 1", inputs)
	}
}

type integrationIDs struct {
	mu   sync.Mutex
	next int
}

func (source *integrationIDs) Next() (string, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.next++
	return fmt.Sprintf("%016d", source.next), nil
}

func openAdmissionPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AR_RUNTIME_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("AR_RUNTIME_POSTGRES_DSN is required")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
func resetAdmissionSchema(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS runtime.runtime_outbox, runtime.audit_records, runtime.session_events, runtime.turns, runtime.inputs, runtime.sessions, runtime.agent_revisions, runtime.tenants, runtime.schema_migrations CASCADE`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
}
func applyAdmissionMigrations(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for _, filename := range []string{"runtime-v1.up.sql", "runtime-v2.up.sql", "runtime-v3.up.sql"} {
		value, err := os.ReadFile(filepath.Join("..", "..", "deploy", "production", "migrations", filename))
		if err != nil {
			t.Fatalf("read %s: %v", filename, err)
		}
		if _, err := pool.Exec(ctx, string(value)); err != nil {
			t.Fatalf("apply %s: %v", filename, err)
		}
	}
}
func seedAdmissionSession(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant, principal, session string, now time.Time) {
	t.Helper()
	if _, err := pool.Exec(ctx, `INSERT INTO runtime.tenants (tenant_id,created_at) VALUES ($1,$2)`, tenant, now); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO runtime.agent_revisions (tenant_id,agent_id,revision_id,revision,name,model_profile,specification_digest,specification_size_bytes,created_at) VALUES ($1,'agent_0000000000000001','arev_0000000000000001',1,'assistant','balanced','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1,$2)`, tenant, now); err != nil {
		t.Fatalf("seed revision: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO runtime.sessions (tenant_id,principal_id,session_id,agent_id,agent_revision_id,state,version,created_at,updated_at) VALUES ($1,$2,$3,'agent_0000000000000001','arev_0000000000000001','open',1,$4,$4)`, tenant, principal, session, now); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}
