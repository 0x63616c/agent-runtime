package temporalpayloadruntime

import (
	"context"
	"errors"
	"testing"

	"github.com/0x63616c/agent-runtime/temporalpayload"
	"go.temporal.io/sdk/client"
)

func TestFactoryInstallsOneConverterForClientsAndWorkers(t *testing.T) {
	t.Parallel()

	codec, err := temporalpayload.NewCodec(temporalpayload.NewMemoryBlobStore(), temporalpayload.WithBlobPrefix("runtime/payloads"))
	if err != nil {
		t.Fatalf("NewCodec() error = %v", err)
	}
	factory, err := NewFactory(codec)
	if err != nil {
		t.Fatalf("NewFactory() error = %v", err)
	}
	clientOptions := factory.ClientOptions(client.Options{})
	workerClientOptions := factory.ClientOptions(client.Options{})
	clientPayload, err := clientOptions.DataConverter.ToPayload("same codec")
	if err != nil {
		t.Fatalf("client converter ToPayload() error = %v", err)
	}
	var workerValue string
	if err := workerClientOptions.DataConverter.FromPayload(clientPayload, &workerValue); err != nil {
		t.Fatalf("worker converter FromPayload() error = %v", err)
	}
	if workerValue != "same codec" {
		t.Fatalf("worker converter value = %q, want same codec", workerValue)
	}
}

func TestFactoryFailsStartupBeforeWorkWhenCompatibilityProbeCannotRoundTrip(t *testing.T) {
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
	if err := factory.CheckStartup(context.Background()); err != nil {
		t.Fatalf("CheckStartup() error = %v", err)
	}
	failingCodec, err := temporalpayload.NewCodec(failingStore{BlobStore: store, getErr: errors.New("blob store unavailable")}, temporalpayload.WithBlobPrefix("runtime/payloads"))
	if err != nil {
		t.Fatalf("NewCodec() error = %v", err)
	}
	failingFactory, err := NewFactory(failingCodec)
	if err != nil {
		t.Fatalf("NewFactory() error = %v", err)
	}
	if err := failingFactory.CheckStartup(context.Background()); err == nil {
		t.Fatal("CheckStartup() error = nil, want startup compatibility failure")
	}
}

type failingStore struct {
	temporalpayload.BlobStore
	getErr error
}

func (store failingStore) Get(context.Context, temporalpayload.BlobKey, int) ([]byte, error) {
	return nil, store.getErr
}
