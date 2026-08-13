package sandboxhostprocess

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/cockroachdb/errors"
)

const maximumControlTrustFileBytes = 16 << 10

type controlTrustFileDocument struct {
	Version         uint64                       `json:"version"`
	RevocationEpoch uint64                       `json:"revocation_epoch"`
	Current         controlTrustFileKeyDocument  `json:"current"`
	Next            *controlTrustFileKeyDocument `json:"next"`
}

type controlTrustFileKeyDocument struct {
	ID        string    `json:"id"`
	Version   uint64    `json:"version"`
	PublicKey string    `json:"public_key"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// LoadControlTrustFile reads one bounded mounted public-key trust snapshot.
func LoadControlTrustFile(path string) (*sandboxhostprotocol.AtomicTrust, error) {
	bundle, err := readControlTrustFile(path)
	if err != nil {
		return nil, err
	}
	trust, err := sandboxhostprotocol.NewAtomicTrust(bundle)
	if err != nil {
		return nil, errors.Wrap(err, "load sandbox host control trust file")
	}
	return trust, nil
}

// ReloadControlTrustFile preserves the prior complete trust snapshot when the
// projected file is malformed or regresses.
func ReloadControlTrustFile(trust *sandboxhostprotocol.AtomicTrust, path string) error {
	if trust == nil {
		return errors.New("reload sandbox host control trust file: current trust is required")
	}
	bundle, err := readControlTrustFile(path)
	if err != nil {
		return err
	}
	if sameTrustBundle(bundle, trust.Snapshot()) {
		return nil
	}
	return errors.Wrap(trust.Update(bundle), "reload sandbox host control trust file")
}

func sameTrustBundle(left, right sandboxhostprotocol.TrustBundle) bool {
	if left.Version != right.Version || left.RevocationEpoch != right.RevocationEpoch || !sameTrustKey(left.Current, right.Current) || (left.Next == nil) != (right.Next == nil) {
		return false
	}
	return left.Next == nil || sameTrustKey(*left.Next, *right.Next)
}

func sameTrustKey(left, right sandboxhostprotocol.SigningKey) bool {
	return left.ID == right.ID && left.Version == right.Version && bytes.Equal(left.PublicKey, right.PublicKey) && left.NotBefore.Equal(right.NotBefore) && left.NotAfter.Equal(right.NotAfter)
}

func readControlTrustFile(path string) (sandboxhostprotocol.TrustBundle, error) {
	file, err := os.Open(path)
	if err != nil {
		return sandboxhostprotocol.TrustBundle{}, errors.Wrap(err, "read sandbox host control trust file")
	}
	defer func() { _ = file.Close() }()
	wire, err := io.ReadAll(io.LimitReader(file, maximumControlTrustFileBytes+1))
	if err != nil || len(wire) == 0 || len(wire) > maximumControlTrustFileBytes {
		return sandboxhostprotocol.TrustBundle{}, errors.New("read sandbox host control trust file: invalid bounded input")
	}
	if err := rejectDuplicateJSONKeys(wire); err != nil {
		return sandboxhostprotocol.TrustBundle{}, errors.Wrap(err, "decode sandbox host control trust file")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var document controlTrustFileDocument
	if err := decoder.Decode(&document); err != nil {
		return sandboxhostprotocol.TrustBundle{}, errors.Wrap(err, "decode sandbox host control trust file")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return sandboxhostprotocol.TrustBundle{}, errors.New("decode sandbox host control trust file: exactly one document is required")
	}
	current, err := controlTrustFileKey(document.Current)
	if err != nil || document.Version == 0 || document.RevocationEpoch == 0 {
		return sandboxhostprotocol.TrustBundle{}, errors.New("decode sandbox host control trust file: invalid versioned trust")
	}
	bundle := sandboxhostprotocol.TrustBundle{Version: document.Version, RevocationEpoch: document.RevocationEpoch, Current: current}
	if document.Next != nil {
		next, nextErr := controlTrustFileKey(*document.Next)
		if nextErr != nil || next.ID == current.ID {
			return sandboxhostprotocol.TrustBundle{}, errors.New("decode sandbox host control trust file: invalid next key")
		}
		bundle.Next = &next
	}
	return bundle, nil
}

func rejectDuplicateJSONKeys(wire []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(wire))
	if err := inspectJSONValue(decoder); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return errors.New("exactly one JSON value is required")
	}
	return nil
}

func inspectJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[name]; exists {
				return errors.Newf("duplicate object key %q", name)
			}
			seen[name] = struct{}{}
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			if err != nil {
				return fmt.Errorf("close JSON object: %w", err)
			}
			return errors.New("close JSON object: unexpected delimiter")
		}
	case '[':
		for decoder.More() {
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			if err != nil {
				return fmt.Errorf("close JSON array: %w", err)
			}
			return errors.New("close JSON array: unexpected delimiter")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func controlTrustFileKey(document controlTrustFileKeyDocument) (sandboxhostprotocol.SigningKey, error) {
	key, err := base64.RawStdEncoding.DecodeString(document.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || document.ID == "" || document.Version == 0 || document.NotBefore.Location() != time.UTC || document.NotAfter.Location() != time.UTC || !document.NotAfter.After(document.NotBefore) {
		return sandboxhostprotocol.SigningKey{}, errors.New("invalid sandbox host control trust key")
	}
	return sandboxhostprotocol.SigningKey{ID: document.ID, Version: document.Version, PublicKey: ed25519.PublicKey(key), NotBefore: document.NotBefore, NotAfter: document.NotAfter}, nil
}
