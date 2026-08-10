package runtimecontent

import (
	"context"
	"testing"
)

func TestNewMinIOImmutableClientRequiresAClient(t *testing.T) {
	if _, err := NewMinIOImmutableClient(nil); err == nil {
		t.Fatal("NewMinIOImmutableClient(nil) error = nil")
	}
}

func TestS3ObjectsConditionallyCreatesAndBoundsReads(t *testing.T) {
	client := &recordingS3Client{values: map[string][]byte{}}
	objects, err := NewS3ImmutableObjects(client, "runtime-content")
	if err != nil {
		t.Fatalf("new objects: %v", err)
	}
	created, err := objects.PutIfAbsent(context.Background(), "tenant/sha256:abc", []byte("value"))
	if err != nil || !created {
		t.Fatalf("first put = %v, %v", created, err)
	}
	created, err = objects.PutIfAbsent(context.Background(), "tenant/sha256:abc", []byte("value"))
	if err != nil || created {
		t.Fatalf("equal replay = %v, %v", created, err)
	}
	if _, err := objects.Get(context.Background(), "tenant/sha256:abc", 4); err == nil {
		t.Fatal("oversized read error = nil")
	}
	value, err := objects.Get(context.Background(), "tenant/sha256:abc", 5)
	if err != nil || string(value) != "value" {
		t.Fatalf("get = %q, %v", value, err)
	}
}

type recordingS3Client struct{ values map[string][]byte }

func (client *recordingS3Client) PutIfAbsent(_ context.Context, bucket, key string, value []byte) (bool, error) {
	full := bucket + "/" + key
	prior, found := client.values[full]
	if found {
		if string(prior) != string(value) {
			return false, ErrIntegrity
		}
		return false, nil
	}
	client.values[full] = append([]byte(nil), value...)
	return true, nil
}
func (client *recordingS3Client) Get(_ context.Context, bucket, key string, max int) ([]byte, error) {
	value, found := client.values[bucket+"/"+key]
	if !found {
		return nil, ErrNotFoundOrDenied
	}
	if len(value) > max {
		return nil, ErrIntegrity
	}
	return append([]byte(nil), value...), nil
}
