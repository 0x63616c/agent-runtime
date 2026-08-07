package s3

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/0x63616c/agent-runtime/temporalpayload"
)

func TestStoreUsesOneExplicitBucketAndEnforcesReadBounds(t *testing.T) {
	t.Parallel()

	client := &recordingClient{value: []byte("value")}
	store, err := NewWithClient(client, "agent-runtime-payloads")
	if err != nil {
		t.Fatalf("NewWithClient() error = %v", err)
	}
	key := temporalpayload.BlobKey("tenant/temporal-payload/v1/sha256/0123456789abcdef")
	if err := store.Put(context.Background(), key, []byte("value")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if client.putBucket != "agent-runtime-payloads" || client.putKey != key.String() || !bytes.Equal(client.putValue, []byte("value")) {
		t.Fatalf("Put() received bucket=%q key=%q value=%q", client.putBucket, client.putKey, client.putValue)
	}
	value, err := store.Get(context.Background(), key, 5)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(value, []byte("value")) {
		t.Fatalf("Get() = %q, want value", value)
	}
	client.value = []byte("too large")
	if _, err := store.Get(context.Background(), key, 3); !errors.Is(err, temporalpayload.ErrBlobTooLarge) {
		t.Fatalf("Get() error = %v, want ErrBlobTooLarge", err)
	}
}

func TestStorePreservesNotFoundClassification(t *testing.T) {
	t.Parallel()

	store, err := NewWithClient(&recordingClient{getErr: temporalpayload.ErrBlobNotFound}, "agent-runtime-payloads")
	if err != nil {
		t.Fatalf("NewWithClient() error = %v", err)
	}
	_, err = store.Get(context.Background(), temporalpayload.BlobKey("tenant/temporal-payload/v1/sha256/0123456789abcdef"), 10)
	if !errors.Is(err, temporalpayload.ErrBlobNotFound) {
		t.Fatalf("Get() error = %v, want ErrBlobNotFound", err)
	}
}

type recordingClient struct {
	putBucket string
	putKey    string
	putValue  []byte
	value     []byte
	getErr    error
}

func (client *recordingClient) Put(_ context.Context, bucket, key string, value []byte) error {
	client.putBucket = bucket
	client.putKey = key
	client.putValue = bytes.Clone(value)
	return nil
}

func (client *recordingClient) Get(_ context.Context, _, _ string, _ int) ([]byte, error) {
	if client.getErr != nil {
		return nil, client.getErr
	}
	return bytes.Clone(client.value), nil
}
