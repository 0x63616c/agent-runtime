//go:build integration

package runtimecontent_test

import (
	"context"
	"os"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func TestRuntimeContentMinIOImmutableRoundTrip(t *testing.T) {
	endpoint, access, secret, bucket := requiredMinIO(t, "AR_MINIO_ENDPOINT"), requiredMinIO(t, "AR_MINIO_ACCESS_KEY"), requiredMinIO(t, "AR_MINIO_SECRET_KEY"), requiredMinIO(t, "AR_RUNTIME_CONTENT_BUCKET")
	client, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(access, secret, ""), Secure: false})
	if err != nil {
		t.Fatalf("new MinIO client: %v", err)
	}
	if os.Getenv("AR_MINIO_CREATE_BUCKET") == "1" {
		if err := client.MakeBucket(context.Background(), bucket, minio.MakeBucketOptions{}); err != nil && minio.ToErrorResponse(err).Code != "BucketAlreadyOwnedByYou" {
			t.Fatalf("make runtime content bucket: %v", err)
		}
	}
	adapter, err := runtimecontent.NewMinIOImmutableClient(client)
	if err != nil {
		t.Fatalf("new immutable client: %v", err)
	}
	objects, err := runtimecontent.NewS3ImmutableObjects(adapter, bucket)
	if err != nil {
		t.Fatalf("new objects: %v", err)
	}
	key := "integration/runtimecontent/immutable"
	created, err := objects.PutIfAbsent(context.Background(), key, []byte("immutable"))
	if err != nil || !created {
		t.Fatalf("first conditional write = %v, %v", created, err)
	}
	created, err = objects.PutIfAbsent(context.Background(), key, []byte("immutable"))
	if err != nil || created {
		t.Fatalf("equal replay = %v, %v", created, err)
	}
	if _, err := objects.PutIfAbsent(context.Background(), key, []byte("different")); err == nil {
		t.Fatal("different immutable replay error = nil")
	}
}

func requiredMinIO(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required for runtimecontent MinIO integration", name)
	}
	return value
}
