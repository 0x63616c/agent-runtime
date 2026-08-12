package runtimecontent

import (
	"bytes"
	"context"
	"io"

	"github.com/cockroachdb/errors"
	"github.com/minio/minio-go/v7"
)

// NewMinIOImmutableClient adapts an explicitly configured MinIO client to the runtimecontent-only conditional object interface.
func NewMinIOImmutableClient(client *minio.Client) (S3ImmutableClient, error) {
	if client == nil {
		return nil, errors.New("create runtime content MinIO client: client is required")
	}
	return minioImmutableClient{client: client}, nil
}

type minioImmutableClient struct{ client *minio.Client }

func (client minioImmutableClient) PutIfAbsent(ctx context.Context, bucket, key string, value []byte) (created bool, err error) {
	options := minio.PutObjectOptions{ContentType: "application/octet-stream", UserMetadata: map[string]string{"agent-runtime-content-immutable": "true"}}
	options.SetMatchETagExcept("*")
	_, err = client.client.PutObject(ctx, bucket, key, bytes.NewReader(value), int64(len(value)), options)
	if !minioPrecondition(err) {
		if err != nil {
			return false, err
		}
		return true, nil
	}
	object, err := client.client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return false, err
	}
	defer func() {
		if closeErr := object.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	existing, err := io.ReadAll(io.LimitReader(object, int64(len(value))+1))
	if err != nil {
		return false, err
	}
	if !bytes.Equal(existing, value) {
		return false, ErrIntegrity
	}
	return false, nil
}

func (client minioImmutableClient) Get(ctx context.Context, bucket, key string, maxBytes int) (value []byte, err error) {
	object, err := client.client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := object.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	value, err = io.ReadAll(io.LimitReader(object, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(value) > maxBytes {
		return nil, ErrIntegrity
	}
	return value, nil
}

func (client minioImmutableClient) Open(ctx context.Context, bucket, key string, maxBytes int) (io.ReadCloser, error) {
	object, err := client.client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	information, err := object.Stat()
	if err != nil {
		_ = object.Close()
		return nil, err
	}
	if maxBytes <= 0 || information.Size != int64(maxBytes) {
		_ = object.Close()
		return nil, ErrIntegrity
	}
	return object, nil
}

func (client minioImmutableClient) DeleteExact(ctx context.Context, bucket, key string) error {
	return client.client.RemoveObject(ctx, bucket, key, minio.RemoveObjectOptions{})
}

func minioPrecondition(err error) bool {
	response := minio.ToErrorResponse(err)
	return response.Code == "PreconditionFailed" || response.StatusCode == 412
}
