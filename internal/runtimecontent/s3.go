package runtimecontent

import (
	"context"
	"io"
	"strings"

	"github.com/cockroachdb/errors"
)

// S3ImmutableClient is the content-only conditional S3 data plane. It keeps
// bucket credentials and endpoints at the composition root, outside state.
type S3ImmutableClient interface {
	PutIfAbsent(context.Context, string, string, []byte) (bool, error)
	Get(context.Context, string, string, int) ([]byte, error)
}

type s3ImmutableStreamer interface {
	Open(context.Context, string, string, int) (io.ReadCloser, error)
}

// s3ImmutableDeleter is deliberately separate from the request-path object
// client. Only the operator-owned lifecycle controller may obtain this
// capability through S3ImmutableObjects.
type s3ImmutableDeleter interface {
	DeleteExact(context.Context, string, string) error
}

// S3ImmutableObjects adapts one declared bucket to runtimecontent's immutable
// object boundary. Its keys remain runtimecontent-owned and tenant-scoped.
type S3ImmutableObjects struct {
	client S3ImmutableClient
	bucket string
}

var _ ImmutableObjectStore = (*S3ImmutableObjects)(nil)
var _ ImmutableObjectDeleter = (*S3ImmutableObjects)(nil)

// NewS3ImmutableObjects creates one bounded immutable runtime-content bucket adapter.
func NewS3ImmutableObjects(client S3ImmutableClient, bucket string) (*S3ImmutableObjects, error) {
	if client == nil || strings.TrimSpace(bucket) == "" || strings.Contains(bucket, "/") {
		return nil, errors.New("create runtime content S3 objects: client and bucket are required")
	}
	return &S3ImmutableObjects{client: client, bucket: bucket}, nil
}

// PutIfAbsent conditionally writes exact immutable runtime-content bytes.
func (objects *S3ImmutableObjects) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, errors.Wrap(err, "put immutable runtime content")
	}
	if objects == nil || objects.client == nil || !validObjectKey(key) {
		return false, ErrIntegrity
	}
	created, err := objects.client.PutIfAbsent(ctx, objects.bucket, key, append([]byte(nil), value...))
	if err != nil {
		return false, errors.Wrap(ErrUnavailable, "put immutable runtime content")
	}
	return created, nil
}

// Get reads at most maxBytes from one immutable runtime-content key.
func (objects *S3ImmutableObjects) Get(ctx context.Context, key string, maxBytes int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "get immutable runtime content")
	}
	if objects == nil || objects.client == nil || !validObjectKey(key) || maxBytes <= 0 {
		return nil, ErrIntegrity
	}
	value, err := objects.client.Get(ctx, objects.bucket, key, maxBytes)
	if err != nil {
		return nil, errors.Wrap(ErrNotFoundOrDenied, "get immutable runtime content")
	}
	if len(value) > maxBytes {
		return nil, ErrIntegrity
	}
	return append([]byte(nil), value...), nil
}

// Open opens a bounded immutable object stream when the configured client
// provides streaming support.
func (objects *S3ImmutableObjects) Open(ctx context.Context, key string, maxBytes int) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "open immutable runtime content")
	}
	if objects == nil || maxBytes <= 0 || !validObjectKey(key) {
		return nil, ErrUnavailable
	}
	client, ok := objects.client.(s3ImmutableStreamer)
	if !ok {
		return nil, ErrUnavailable
	}
	stream, err := client.Open(ctx, objects.bucket, key, maxBytes)
	if err != nil {
		return nil, errors.Wrap(ErrNotFoundOrDenied, "open immutable runtime content")
	}
	if stream == nil {
		return nil, ErrUnavailable
	}
	return stream, nil
}

// DeleteExact removes one private immutable key through the explicit
// operator-only lifecycle capability. Ordinary request paths receive only the
// ImmutableObjectStore surface and cannot call it.
func (objects *S3ImmutableObjects) DeleteExact(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, "delete immutable runtime content")
	}
	if objects == nil || objects.client == nil || !validObjectKey(key) {
		return ErrIntegrity
	}
	client, ok := objects.client.(s3ImmutableDeleter)
	if !ok {
		return ErrUnavailable
	}
	if err := client.DeleteExact(ctx, objects.bucket, key); err != nil {
		return errors.Wrap(ErrUnavailable, "delete immutable runtime content")
	}
	return nil
}

func validObjectKey(key string) bool {
	return key != "" && len(key) <= 512 && !strings.HasPrefix(key, "/") && !strings.Contains(key, "..") && !strings.Contains(key, "\\")
}
