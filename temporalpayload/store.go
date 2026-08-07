package temporalpayload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
	"sync"

	"github.com/cockroachdb/errors"
)

var (
	// ErrBlobNotFound reports a payload reference whose immutable content is absent.
	ErrBlobNotFound = errors.New("temporal payload blob not found")
	// ErrBlobIntegrity reports a payload reference whose content does not match its digest or size.
	ErrBlobIntegrity = errors.New("temporal payload blob integrity check failed")
	// ErrBlobTooLarge reports a blob which exceeds the codec's configured finite bound.
	ErrBlobTooLarge = errors.New("temporal payload blob exceeds configured size limit")
)

// BlobKey identifies an immutable object owned by the payload codec.
//
// Codec creates keys from a configured prefix and the SHA-256 digest of stored
// bytes. BlobStore implementations must treat a key as opaque and must not
// infer an object-store endpoint from it.
type BlobKey string

// String returns the storage-neutral canonical key text.
func (key BlobKey) String() string {
	return string(key)
}

// BlobStore stores immutable payload content under a codec-owned BlobKey.
//
// Put must be idempotent for equal bytes and must reject a different value at
// an existing key. Get must return no more than maxBytes; this lets a store
// enforce the codec's bounded read policy before allocating unbounded content.
type BlobStore interface {
	Put(context.Context, BlobKey, []byte) error
	Get(context.Context, BlobKey, int) ([]byte, error)
}

// MemoryBlobStore is a concurrent in-memory BlobStore for tests and local
// deterministic consumers. It is not durable storage.
type MemoryBlobStore struct {
	mu     sync.RWMutex
	values map[BlobKey][]byte
}

// NewMemoryBlobStore creates a concurrent in-memory immutable BlobStore.
func NewMemoryBlobStore() *MemoryBlobStore {
	return &MemoryBlobStore{values: make(map[BlobKey][]byte)}
}

// Put stores bytes exactly once for key.
func (store *MemoryBlobStore) Put(ctx context.Context, key BlobKey, value []byte) error {
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, "put temporal payload blob")
	}
	if err := validateBlobKey(key); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if current, found := store.values[key]; found {
		if !bytes.Equal(current, value) {
			return errors.Wrapf(ErrBlobIntegrity, "put different bytes at immutable key %q", key)
		}
		return nil
	}
	store.values[key] = bytes.Clone(value)
	return nil
}

// Get retrieves an immutable value while enforcing maxBytes before cloning it.
func (store *MemoryBlobStore) Get(ctx context.Context, key BlobKey, maxBytes int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "get temporal payload blob")
	}
	if err := validateBlobKey(key); err != nil {
		return nil, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	value, found := store.values[key]
	if !found {
		return nil, errors.Wrapf(ErrBlobNotFound, "get key %q", key)
	}
	if len(value) > maxBytes {
		return nil, errors.Wrapf(ErrBlobTooLarge, "get key %q has %d bytes, limit is %d", key, len(value), maxBytes)
	}
	return bytes.Clone(value), nil
}

// Delete removes key from the deterministic test store. Production object
// stores must make deletion an explicit retention/GC operation rather than a
// normal codec concern.
func (store *MemoryBlobStore) Delete(ctx context.Context, key BlobKey) error {
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, "delete temporal payload blob")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, found := store.values[key]; !found {
		return errors.Wrapf(ErrBlobNotFound, "delete key %q", key)
	}
	delete(store.values, key)
	return nil
}

// Count returns the number of stored objects. It is intended for deterministic tests.
func (store *MemoryBlobStore) Count() int {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return len(store.values)
}

func (store *MemoryBlobStore) replace(key BlobKey, value []byte) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.values[key] = bytes.Clone(value)
}

func blobKey(prefix string, digest [sha256.Size]byte) BlobKey {
	return BlobKey(prefix + "/temporal-payload/v1/sha256/" + hex.EncodeToString(digest[:]))
}

func validateBlobKey(key BlobKey) error {
	value := string(key)
	if value == "" || path.Clean(value) != value || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") {
		return errors.Newf("invalid temporal payload blob key %q", key)
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.Newf("invalid temporal payload blob key %q", key)
		}
	}
	return nil
}

func validateBlobPrefix(prefix string) (string, error) {
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		return "", errors.New("temporal payload blob prefix is required")
	}
	if err := validateBlobKey(BlobKey(prefix + "/placeholder")); err != nil {
		return "", errors.Wrap(err, "validate temporal payload blob prefix")
	}
	return prefix, nil
}

func verifyBlob(reference remoteReference, value []byte) error {
	if uint64(len(value)) != reference.Size {
		return errors.Wrapf(ErrBlobIntegrity, "blob %q has %d bytes, reference requires %d", reference.Key, len(value), reference.Size)
	}
	digest := sha256.Sum256(value)
	if digest != reference.Digest {
		return errors.Wrapf(ErrBlobIntegrity, "blob %q digest differs from reference", reference.Key)
	}
	return nil
}

func checkReadLimit(size uint64, maxBytes int) error {
	if size > uint64(maxBytes) {
		return errors.Wrapf(ErrBlobTooLarge, "reference has %d bytes, configured limit is %d", size, maxBytes)
	}
	return nil
}

func blobStoreError(action string, key BlobKey, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s temporal payload blob %q: %w", action, key, err)
}
