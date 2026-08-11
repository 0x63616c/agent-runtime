package runtimecontent_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
)

func TestTenantErasureControllerRequiresAuthorizationAndReturnsPartialReceipt(t *testing.T) {
	store, err := runtimecontent.New("lifecycle", &lifecycleObjects{})
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := runtimecontent.ParseTenantID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	first, second := lifecycleReference("first"), lifecycleReference("second")
	deleter := &lifecycleDeleter{failAt: 2}
	controller, err := runtimecontent.NewTenantErasureController(store, lifecycleAuthorizer{}, deleter)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := controller.Erase(context.Background(), runtimecontent.ErasureRequest{Tenant: tenant, AuthorizationID: "operator-authority-0001", References: []runtimecontent.Reference{first, second}})
	if !errors.Is(err, runtimecontent.ErrUnavailable) || len(receipt.Deleted) != 1 || receipt.Failed == nil || *receipt.Failed != second {
		t.Fatalf("erase = %#v, %v", receipt, err)
	}
}

type lifecycleObjects struct{}

func (*lifecycleObjects) PutIfAbsent(context.Context, string, []byte) (bool, error) { return true, nil }
func (*lifecycleObjects) Get(context.Context, string, int) ([]byte, error)          { return nil, nil }

type lifecycleAuthorizer struct{}

func (lifecycleAuthorizer) AuthorizeErasure(context.Context, runtimecontent.ErasureRequest) error {
	return nil
}

type lifecycleDeleter struct{ calls, failAt int }

func (d *lifecycleDeleter) DeleteExact(context.Context, string) error {
	d.calls++
	if d.calls == d.failAt {
		return errors.New("unavailable")
	}
	return nil
}
func lifecycleReference(value string) runtimecontent.Reference {
	sum := sha256.Sum256([]byte(value))
	return runtimecontent.Reference{Digest: "sha256:" + hex.EncodeToString(sum[:]), MediaType: "application/vnd.agent-runtime.conversation-entry+octets;version=1", SizeBytes: int64(len(value))}
}
