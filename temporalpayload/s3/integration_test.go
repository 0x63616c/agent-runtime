//go:build integration

package s3_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/0x63616c/agent-runtime/temporalpayload"
	"github.com/0x63616c/agent-runtime/temporalpayload/s3"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func TestS3CompatibleMinIOIntegration(t *testing.T) {
	endpoint := requiredEnvironment(t, "AR_MINIO_ENDPOINT")
	accessKey := requiredEnvironment(t, "AR_MINIO_ACCESS_KEY")
	secretKey := requiredEnvironment(t, "AR_MINIO_SECRET_KEY")
	bucket := requiredEnvironment(t, "AR_MINIO_BUCKET")

	client, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(accessKey, secretKey, ""), Secure: false})
	if err != nil {
		t.Fatalf("create MinIO client: %v", err)
	}
	ctx := context.Background()
	if os.Getenv("AR_MINIO_CREATE_BUCKET") == "1" {
		if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
			response := minio.ToErrorResponse(err)
			if response.Code != "BucketAlreadyOwnedByYou" && response.Code != "BucketAlreadyExists" {
				t.Fatalf("create declared integration bucket: %v", err)
			}
		}
	}
	store, err := s3.New(client, bucket)
	if err != nil {
		t.Fatalf("create S3 payload store: %v", err)
	}
	prefix := "integration/" + randomSuffix(t)
	codec, err := temporalpayload.NewCodec(store, temporalpayload.WithBlobPrefix(prefix), temporalpayload.WithMaximumBlobBytes(1<<20))
	if err != nil {
		t.Fatalf("create payload codec: %v", err)
	}
	want := make([]byte, 64*1024)
	if _, err := rand.Read(want); err != nil {
		t.Fatalf("create integration payload: %v", err)
	}
	payload, err := codec.DataConverter().ToPayload(want)
	if err != nil {
		t.Fatalf("encode through MinIO: %v", err)
	}
	var got []byte
	if err := codec.DataConverter().FromPayload(payload, &got); err != nil {
		t.Fatalf("decode through MinIO: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("MinIO payload round trip differs")
	}

	key := temporalpayload.BlobKey(prefix + "/temporal-payload/v1/sha256/immutable-contract")
	immutable := []byte("same immutable object")
	var group sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		group.Go(func() { errs <- store.Put(ctx, key, immutable) })
	}
	group.Wait()
	close(errs)
	for putErr := range errs {
		if putErr != nil {
			t.Fatalf("concurrent immutable Put() error = %v", putErr)
		}
	}
	if err := store.Put(ctx, key, []byte("different value")); !errors.Is(err, temporalpayload.ErrBlobIntegrity) {
		t.Fatalf("conflicting immutable Put() error = %v, want ErrBlobIntegrity", err)
	}
}

func requiredEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required for the real S3-compatible integration test", name)
	}
	return value
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatalf("generate integration prefix: %v", err)
	}
	return fmt.Sprintf("%x", value)
}
