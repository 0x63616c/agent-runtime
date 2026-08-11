//go:build linux

package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxauthority"
)

func TestGuestSecretRunnerRefusesTreeOnlyVerifierBeforeSecretDelivery(t *testing.T) {
	area := &recordingNonSnapshotSecretArea{}
	sink, err := newGuestSecretSink(area)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := sandboxauthority.NewManager(testGuestSecretResolver{}, sink, testGuestSecretAudit{})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(guestCommand{Version: guestCommandVersion, Argv: []string{"/bin/true"}, WorkingDirectory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runGuestCommandWithSecret(context.Background(), payload, manager, sink, guestSecretRequest(), time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC), guestTreeReapVerifierFunc(func(context.Context, int, int) error { return nil })); err == nil {
		t.Fatal("runGuestCommandWithSecret() accepted a tree-only verifier")
	}
	if area.begin.ProcessID != "" || len(sink.active) != 0 {
		t.Fatalf("secret delivery began before containment proof: area=%#v active=%d", area.begin, len(sink.active))
	}
}

type testGuestSecretResolver struct{}

func (testGuestSecretResolver) Resolve(_ context.Context, request sandboxauthority.SecretRequest) (sandboxauthority.SecretValue, error) {
	return sandboxauthority.SecretValue{Version: "version-001", ExpiresAt: request.ExpiresAt, Bytes: []byte("secret")}, nil
}

type testGuestSecretAudit struct{}

func (testGuestSecretAudit) RecordSecretDelivery(context.Context, sandboxauthority.SecretAuditFact) error {
	return nil
}
