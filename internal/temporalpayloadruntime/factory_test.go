package temporalpayloadruntime

import (
	"context"
	"errors"
	"testing"

	"github.com/0x63616c/agent-runtime/temporalpayload"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

func TestFactoryRefusesClientConstructionWhenRetainedCompatibilityFails(t *testing.T) {
	t.Parallel()

	store := temporalpayload.NewMemoryBlobStore()
	codec, err := temporalpayload.NewCodec(failingStore{BlobStore: store, getErr: errors.New("blob store unavailable")}, temporalpayload.WithBlobPrefix("runtime/payloads"))
	if err != nil {
		t.Fatalf("NewCodec() error = %v", err)
	}
	factory, err := NewFactory(codec)
	if err != nil {
		t.Fatalf("NewFactory() error = %v", err)
	}
	if _, err := factory.NewClient(context.Background(), client.Options{HostPort: "127.0.0.1:1"}); err == nil {
		t.Fatal("NewClient() error = nil, want compatibility gate failure before dialing")
	}
}

func TestFactoryCreatesWorkersOnlyFromOwnedClients(t *testing.T) {
	t.Parallel()

	store := temporalpayload.NewMemoryBlobStore()
	codec, err := temporalpayload.NewCodec(store, temporalpayload.WithBlobPrefix("runtime/payloads"))
	if err != nil {
		t.Fatalf("NewCodec() error = %v", err)
	}
	factory, err := NewFactory(codec)
	if err != nil {
		t.Fatalf("NewFactory() error = %v", err)
	}
	if _, err := factory.NewWorker(nil, "runtime-test", worker.Options{}); err == nil {
		t.Fatal("NewWorker() error = nil, want owned client requirement")
	}
}

type failingStore struct {
	temporalpayload.BlobStore
	getErr error
}

func (store failingStore) Get(context.Context, temporalpayload.BlobKey, int) ([]byte, error) {
	return nil, store.getErr
}
