package runtimeadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

// MemoryContentStore is a deterministic immutable ContentStore for focused tests.
type MemoryContentStore struct {
	mu      sync.RWMutex
	objects map[string][]byte
}

// NewMemoryContentStore creates an empty tenant-namespaced immutable store.
func NewMemoryContentStore() *MemoryContentStore {
	return &MemoryContentStore{objects: make(map[string][]byte)}
}

// PutInput canonicalizes and conditionally stores one valid public input.
func (store *MemoryContentStore) PutInput(ctx context.Context, owner Owner, parts []agentruntime.ContentPart) (ContentReference, error) {
	if err := validateOwner(owner); err != nil {
		return ContentReference{}, err
	}
	if len(parts) == 0 || len(parts) > agentruntime.MaxInputParts {
		return ContentReference{}, errors.New("input content part count is outside the public contract")
	}
	if err := validateParts(parts); err != nil {
		return ContentReference{}, err
	}
	if err := ctx.Err(); err != nil {
		return ContentReference{}, errors.Wrap(err, "stage input content")
	}
	encoded, err := encodeInput(parts)
	if err != nil {
		return ContentReference{}, err
	}
	if len(encoded) > maximumInputBytes {
		return ContentReference{}, errors.New("canonical input exceeds runtime v3 bound")
	}
	digest := sha256.Sum256(encoded)
	reference := ContentReference{Digest: "sha256:" + hex.EncodeToString(digest[:]), MediaType: InputMediaTypeV1, SizeBytes: int64(len(encoded))}
	key := objectKey(owner, reference.Digest)
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.objects[key]; ok {
		if !bytes.Equal(existing, encoded) {
			return ContentReference{}, errors.Wrap(ErrIntegrity, "immutable input content differs")
		}
		return reference, nil
	}
	store.objects[key] = bytes.Clone(encoded)
	return reference, nil
}

// GetInput verifies and decodes content addressed by a repository-issued locator.
func (store *MemoryContentStore) GetInput(ctx context.Context, locator authorizedInputLocator) ([]agentruntime.ContentPart, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "read input content")
	}
	store.mu.RLock()
	value, found := store.objects[objectKey(locator.owner, locator.reference.Digest)]
	store.mu.RUnlock()
	if !found {
		return nil, ErrNotFoundOrDenied
	}
	if int64(len(value)) != locator.reference.SizeBytes {
		return nil, ErrIntegrity
	}
	digest := sha256.Sum256(value)
	if locator.reference.Digest != "sha256:"+hex.EncodeToString(digest[:]) {
		return nil, ErrIntegrity
	}
	parts, err := decodeInput(value)
	if err != nil {
		return nil, errors.Wrap(ErrIntegrity, "decode input content")
	}
	return parts, nil
}

// Count returns staged immutable objects for deterministic orphan tests.
func (store *MemoryContentStore) Count() int {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return len(store.objects)
}

func objectKey(owner Owner, digest string) string { return owner.TenantID + "\x00" + digest }

// This uses canonical definite-length CBOR arrays and text strings. It avoids
// JSON escaping growth while retaining a format that is independently decodable.
func encodeInput(parts []agentruntime.ContentPart) ([]byte, error) {
	var result bytes.Buffer
	writeCBORHead(&result, 4, 2)
	writeCBORHead(&result, 0, 1)
	writeCBORHead(&result, 4, uint64(len(parts)))
	for _, part := range parts {
		writeCBORHead(&result, 4, 2)
		switch part.Kind {
		case agentruntime.ContentText:
			writeCBORHead(&result, 0, 1)
			writeCBORText(&result, part.Text)
		case agentruntime.ContentArtifact:
			writeCBORHead(&result, 0, 2)
			writeCBORHead(&result, 4, 4)
			writeCBORText(&result, part.Artifact.ID.String())
			writeCBORText(&result, part.Artifact.MediaType)
			writeCBORHead(&result, 0, uint64(part.Artifact.SizeBytes))
			writeCBORText(&result, part.Artifact.SHA256)
		default:
			return nil, errors.New("encode input: unsupported part")
		}
	}
	return result.Bytes(), nil
}

func decodeInput(value []byte) ([]agentruntime.ContentPart, error) {
	offset := 0
	major, count, next, err := readCBORHead(value, offset)
	if err != nil || major != 4 || count != 2 {
		return nil, errors.New("unsupported input content version")
	}
	offset = next
	major, version, next, err := readCBORHead(value, offset)
	if err != nil || major != 0 || version != 1 {
		return nil, errors.New("unsupported input content version")
	}
	offset = next
	major, count, next, err = readCBORHead(value, offset)
	if err != nil || major != 4 || count > agentruntime.MaxInputParts {
		return nil, errors.New("invalid input content parts")
	}
	offset = next
	parts := make([]agentruntime.ContentPart, 0, int(count))
	for index := uint64(0); index < count; index++ {
		major, fields, next, err := readCBORHead(value, offset)
		if err != nil || major != 4 || fields != 2 {
			return nil, errors.New("invalid input content part")
		}
		offset = next
		major, kind, next := uint8(0), uint64(0), 0
		major, kind, next, err = readCBORHead(value, offset)
		if err != nil || major != 0 {
			return nil, errors.New("invalid input content kind")
		}
		offset = next
		switch kind {
		case 1:
			text, next, err := readCBORText(value, offset)
			if err != nil {
				return nil, err
			}
			offset = next
			parts = append(parts, agentruntime.ContentPart{Kind: agentruntime.ContentText, Text: text})
		case 2:
			major, fields, next := uint8(0), uint64(0), 0
			major, fields, next, err = readCBORHead(value, offset)
			if err != nil || major != 4 || fields != 4 {
				return nil, errors.New("invalid artifact input content")
			}
			id, next, err := readCBORText(value, next)
			if err != nil {
				return nil, err
			}
			media, next, err := readCBORText(value, next)
			if err != nil {
				return nil, err
			}
			major, size, next, err := readCBORHead(value, next)
			if err != nil || major != 0 || size > uint64(^uint64(0)>>1) {
				return nil, errors.New("invalid artifact size")
			}
			digest, next, err := readCBORText(value, next)
			if err != nil {
				return nil, err
			}
			offset = next
			parts = append(parts, agentruntime.ContentPart{Kind: agentruntime.ContentArtifact, Artifact: &agentruntime.ArtifactReference{ID: agentruntime.ArtifactID(id), MediaType: media, SizeBytes: int64(size), SHA256: digest}})
		default:
			return nil, errors.New("unsupported input content part")
		}
	}
	if offset != len(value) {
		return nil, errors.New("trailing input content")
	}
	if err := validateParts(parts); err != nil {
		return nil, err
	}
	return parts, nil
}

func writeCBORText(buffer *bytes.Buffer, value string) {
	writeCBORHead(buffer, 3, uint64(len(value)))
	buffer.WriteString(value)
}
func writeCBORHead(buffer *bytes.Buffer, major byte, value uint64) {
	if value < 24 {
		buffer.WriteByte(major<<5 | byte(value))
		return
	}
	if value <= 0xff {
		buffer.WriteByte(major<<5 | 24)
		buffer.WriteByte(byte(value))
		return
	}
	if value <= 0xffff {
		buffer.WriteByte(major<<5 | 25)
		buffer.WriteByte(byte(value >> 8))
		buffer.WriteByte(byte(value))
		return
	}
	if value <= 0xffffffff {
		buffer.WriteByte(major<<5 | 26)
		for shift := uint(24); ; shift -= 8 {
			buffer.WriteByte(byte(value >> shift))
			if shift == 0 {
				return
			}
		}
	}
	buffer.WriteByte(major<<5 | 27)
	for shift := uint(56); ; shift -= 8 {
		buffer.WriteByte(byte(value >> shift))
		if shift == 0 {
			return
		}
	}
}
func readCBORHead(value []byte, offset int) (byte, uint64, int, error) {
	if offset >= len(value) {
		return 0, 0, 0, errors.New("truncated CBOR head")
	}
	first := value[offset]
	major := first >> 5
	additional := first & 31
	offset++
	if additional < 24 {
		return major, uint64(additional), offset, nil
	}
	width := 0
	switch additional {
	case 24:
		width = 1
	case 25:
		width = 2
	case 26:
		width = 4
	case 27:
		width = 8
	default:
		return 0, 0, 0, errors.New("indefinite CBOR is unsupported")
	}
	if len(value)-offset < width {
		return 0, 0, 0, errors.New("truncated CBOR value")
	}
	var result uint64
	for _, current := range value[offset : offset+width] {
		result = result<<8 | uint64(current)
	}
	minimum := uint64(24)
	if width == 2 {
		minimum = 256
	}
	if width == 4 {
		minimum = 65536
	}
	if width == 8 {
		minimum = 1 << 32
	}
	if result < minimum {
		return 0, 0, 0, errors.New("non-canonical CBOR value")
	}
	return major, result, offset + width, nil
}
func readCBORText(value []byte, offset int) (string, int, error) {
	major, size, next, err := readCBORHead(value, offset)
	if err != nil || major != 3 || size > uint64(len(value)-next) {
		return "", 0, errors.New("invalid CBOR text")
	}
	return string(value[next : next+int(size)]), next + int(size), nil
}
