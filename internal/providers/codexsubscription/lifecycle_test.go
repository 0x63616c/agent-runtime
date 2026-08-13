package codexsubscription_test

import (
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/providers/codexsubscription"
)

func TestLifecycleModelsLocalLoginWithoutCredentialMaterial(t *testing.T) {
	lifecycle := codexsubscription.NewLifecycle()
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	reference := codexsubscription.CredentialContextRef("single-user-preview")

	status, err := lifecycle.Register(reference, now)
	if err != nil || status.State != codexsubscription.LifecycleUnavailable {
		t.Fatalf("register = %#v, %v", status, err)
	}
	if _, err := lifecycle.BeginLogin(reference, now.Add(time.Minute)); err != nil {
		t.Fatalf("begin login: %v", err)
	}
	status, err = lifecycle.CompleteLogin(reference, codexsubscription.LifecycleReady, now.Add(2*time.Minute))
	if err != nil || status.State != codexsubscription.LifecycleReady {
		t.Fatalf("complete login = %#v, %v", status, err)
	}
	if got := status.Reference; got != reference {
		t.Fatalf("status reference = %q, want %q", got, reference)
	}
}

func TestLifecycleCancelsPendingLoginAndPreservesSafeFailureStates(t *testing.T) {
	lifecycle := codexsubscription.NewLifecycle()
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	reference := codexsubscription.CredentialContextRef("cancel-and-refresh")
	if _, err := lifecycle.Register(reference, now); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.BeginLogin(reference, now); err != nil {
		t.Fatal(err)
	}
	status, err := lifecycle.CancelLogin(reference, now)
	if err != nil || status.State != codexsubscription.LifecycleUnavailable {
		t.Fatalf("cancel login = %#v, %v", status, err)
	}
	if _, err := lifecycle.BeginLogin(reference, now); err != nil {
		t.Fatal(err)
	}
	status, err = lifecycle.CompleteLogin(reference, codexsubscription.LifecycleAmbiguous, now)
	if err != nil || status.State != codexsubscription.LifecycleAmbiguous {
		t.Fatalf("complete ambiguous login = %#v, %v", status, err)
	}
	if _, err := lifecycle.AcquireRefresh(reference, "model-1", now); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("acquire ambiguous refresh = %v, want safe refusal", err)
	}
}

func TestLifecycleFencesRefreshToOneModelOwnerAndRetainsOutcomes(t *testing.T) {
	lifecycle := codexsubscription.NewLifecycle()
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	reference := codexsubscription.CredentialContextRef("isolated-context")
	if _, err := lifecycle.Register(reference, now); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.BeginLogin(reference, now); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.CompleteLogin(reference, codexsubscription.LifecycleReady, now); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.AcquireRefresh(reference, "model-a", now); err != nil {
		t.Fatalf("acquire owner: %v", err)
	}
	if _, err := lifecycle.AcquireRefresh(reference, "model-b", now); err == nil || !strings.Contains(err.Error(), "another model owner") {
		t.Fatalf("acquire second owner = %v, want fence", err)
	}
	if _, err := lifecycle.SettleRefresh(reference, "model-b", codexsubscription.LifecycleRejected, now); err == nil || !strings.Contains(err.Error(), "does not hold") {
		t.Fatalf("settle foreign owner = %v, want fence", err)
	}
	status, err := lifecycle.SettleRefresh(reference, "model-a", codexsubscription.LifecycleExpired, now)
	if err != nil || status.State != codexsubscription.LifecycleExpired {
		t.Fatalf("settle = %#v, %v", status, err)
	}
	if _, err := lifecycle.AcquireRefresh(reference, "model-b", now); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	status, err = lifecycle.SettleRefresh(reference, "model-b", codexsubscription.LifecycleRejected, now)
	if err != nil || status.State != codexsubscription.LifecycleRejected {
		t.Fatalf("settle rejected = %#v, %v", status, err)
	}
}

func TestLifecycleRejectsPathsAndNeverExposesCredentialLikeReference(t *testing.T) {
	lifecycle := codexsubscription.NewLifecycle()
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	for _, reference := range []codexsubscription.CredentialContextRef{"", "../auth.json", "https://token.example", "user:secret"} {
		if _, err := lifecycle.Register(reference, now); err == nil {
			t.Fatalf("register %q accepted credential-like/path reference", reference)
		}
	}
	if _, err := lifecycle.Register("safe-context", now); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.BeginLogin("safe-context", now); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.CompleteLogin("safe-context", codexsubscription.LifecycleReady, now); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.AcquireRefresh("safe-context", "model@credential", now); err == nil || strings.Contains(err.Error(), "model@credential") {
		t.Fatalf("unsafe owner error = %v", err)
	}
}
