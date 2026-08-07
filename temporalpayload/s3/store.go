// Package s3 adapts an S3-compatible object store to temporalpayload.BlobStore.
package s3

import (
	"bytes"
	"context"
	stderrors "errors"
	"io"
	"strings"

	"github.com/0x63616c/agent-runtime/temporalpayload"
	"github.com/cockroachdb/errors"
	"github.com/minio/minio-go/v7"
)

// Client is the narrow S3-compatible data-plane interface used by Store.
//
// It intentionally contains neither credentials nor endpoint configuration;
// applications configure those at their composition root and pass the resulting
// MinIO client to New.
type Client interface {
	Put(context.Context, string, string, []byte) error
	Get(context.Context, string, string, int) ([]byte, error)
}

// Store is an immutable temporalpayload.BlobStore backed by one explicit S3 bucket.
type Store struct {
	client Client
	bucket string
}

// New adapts a configured MinIO S3-compatible client and one declared bucket.
func New(client *minio.Client, bucket string) (*Store, error) {
	if client == nil {
		return nil, errors.New("S3-compatible client is required")
	}
	return NewWithClient(minioClient{client: client}, bucket)
}

// NewWithClient creates a Store from a narrow S3-compatible client seam.
func NewWithClient(client Client, bucket string) (*Store, error) {
	if client == nil {
		return nil, errors.New("S3-compatible client is required")
	}
	if strings.TrimSpace(bucket) == "" || strings.Contains(bucket, "/") {
		return nil, errors.New("S3-compatible bucket is required and must not contain a slash")
	}
	return &Store{client: client, bucket: bucket}, nil
}

// Put stores one immutable content-addressed value under key.
func (store *Store) Put(ctx context.Context, key temporalpayload.BlobKey, value []byte) error {
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, "put S3-compatible temporal payload blob")
	}
	if err := store.client.Put(ctx, store.bucket, key.String(), bytes.Clone(value)); err != nil {
		return errors.Wrapf(err, "put S3-compatible temporal payload blob %q", key)
	}
	return nil
}

// Get reads no more than maxBytes from key.
func (store *Store) Get(ctx context.Context, key temporalpayload.BlobKey, maxBytes int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "get S3-compatible temporal payload blob")
	}
	if maxBytes <= 0 {
		return nil, errors.New("S3-compatible temporal payload read limit must be positive")
	}
	value, err := store.client.Get(ctx, store.bucket, key.String(), maxBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "get S3-compatible temporal payload blob %q", key)
	}
	if len(value) > maxBytes {
		return nil, errors.Wrapf(temporalpayload.ErrBlobTooLarge, "S3-compatible blob %q has %d bytes, limit is %d", key, len(value), maxBytes)
	}
	return bytes.Clone(value), nil
}

type minioClient struct {
	client *minio.Client
}

func (client minioClient) Put(ctx context.Context, bucket, key string, value []byte) error {
	options := minio.PutObjectOptions{
		ContentType: "application/octet-stream",
		UserMetadata: map[string]string{
			"agent-runtime-immutable": "true",
		},
	}
	// MinIO's optimistic-locking extension maps this to If-None-Match: *. A
	// backend which does not support conditional create fails visibly instead of
	// silently permitting an overwrite of a content-addressed blob.
	options.SetMatchETagExcept("*")
	_, err := client.client.PutObject(ctx, bucket, key, bytes.NewReader(value), int64(len(value)), options)
	if !isPreconditionFailure(err) {
		return err
	}
	info, statErr := client.client.StatObject(ctx, bucket, key, minio.StatObjectOptions{})
	if statErr != nil {
		return errors.Wrap(statErr, "stat existing immutable S3-compatible payload blob after conditional create")
	}
	if info.Size != int64(len(value)) {
		return errors.Wrapf(temporalpayload.ErrBlobIntegrity, "existing S3-compatible blob %q has %d bytes, conditional value has %d", key, info.Size, len(value))
	}
	existing, getErr := client.Get(ctx, bucket, key, len(value))
	if getErr != nil {
		return errors.Wrap(getErr, "read existing immutable S3-compatible payload blob after conditional create")
	}
	if !bytes.Equal(existing, value) {
		return errors.Wrapf(temporalpayload.ErrBlobIntegrity, "existing S3-compatible blob %q differs after conditional create", key)
	}
	return nil
}

func (client minioClient) Get(ctx context.Context, bucket, key string, maxBytes int) (value []byte, resultErr error) {
	object, err := client.client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, mapNotFound(err)
	}
	defer func() {
		if closeErr := object.Close(); closeErr != nil {
			resultErr = stderrors.Join(resultErr, errors.Wrap(closeErr, "close S3-compatible payload object"))
		}
	}()
	info, err := object.Stat()
	if err != nil {
		return nil, mapNotFound(err)
	}
	if info.Size > int64(maxBytes) {
		return nil, errors.Wrapf(temporalpayload.ErrBlobTooLarge, "S3-compatible blob %q has %d bytes, limit is %d", key, info.Size, maxBytes)
	}
	value, err = io.ReadAll(io.LimitReader(object, int64(maxBytes)+1))
	if err != nil {
		return nil, mapNotFound(err)
	}
	if len(value) > maxBytes {
		return nil, errors.Wrapf(temporalpayload.ErrBlobTooLarge, "S3-compatible blob %q has more than %d bytes", key, maxBytes)
	}
	return value, nil
}

func mapNotFound(err error) error {
	response := minio.ToErrorResponse(err)
	if response.Code == "NoSuchKey" || response.Code == "NoSuchObject" || response.StatusCode == 404 {
		return errors.Wrap(temporalpayload.ErrBlobNotFound, "S3-compatible object is absent")
	}
	return err
}

func isPreconditionFailure(err error) bool {
	if err == nil {
		return false
	}
	response := minio.ToErrorResponse(err)
	return response.Code == "PreconditionFailed" || response.StatusCode == 412
}
