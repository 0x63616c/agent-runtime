package sandboxcontrol

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStoreReconnectsSamePrincipalOperationAndConflictsChangedDigest(t *testing.T) {
	store := NewMemoryStore()
	first := AcceptedOperation{Principal: "tenant-a", ID: "op_01", Digest: "sha256:one", AcceptedAt: time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC), State: "accepted"}
	got, replay, err := store.Accept(context.Background(), first)
	if err != nil || replay || got.Digest != first.Digest {
		t.Fatalf("first Accept() = %#v, %v, %v", got, replay, err)
	}
	got, replay, err = store.Accept(context.Background(), first)
	if err != nil || !replay || got.Digest != first.Digest {
		t.Fatalf("replay Accept() = %#v, %v, %v", got, replay, err)
	}
	_, _, err = store.Accept(context.Background(), AcceptedOperation{Principal: "tenant-a", ID: "op_01", Digest: "sha256:two", AcceptedAt: first.AcceptedAt, State: "accepted"})
	if err != ErrConflict {
		t.Fatalf("changed Accept() error = %v, want conflict", err)
	}
}
