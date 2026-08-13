package stack

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"github.com/cockroachdb/errors"
)

const bootstrapNonceDigestAnnotation = "agent-runtime.dev/bootstrap-nonce-sha256"

// NewBootstrapAuthority creates a private bootstrap capability for one reviewed rendering.
func NewBootstrapAuthority(rendered Rendered, namespaceUID ObservedUID) (BootstrapAuthority, error) {
	document, err := parseRenderedBytes(rendered.JSON())
	if err != nil {
		return BootstrapAuthority{}, errors.Wrap(err, "construct bootstrap authority")
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return BootstrapAuthority{}, errors.Wrap(err, "construct bootstrap authority nonce")
	}
	return BootstrapAuthority{
		Stack: document.Stack, Profile: document.Profile, Namespace: document.Namespace,
		NamespaceUID: namespaceUID, RenderDigest: document.Digest, Nonce: hex.EncodeToString(nonce),
	}, nil
}

// NonceDigest is the public Namespace binding for the private bootstrap nonce.
func (authority BootstrapAuthority) NonceDigest() string {
	sum := sha256.Sum256([]byte(authority.Nonce))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// WriteBootstrapAuthority creates a mode-0600 capability file without overwriting an existing path.
func WriteBootstrapAuthority(path string, authority BootstrapAuthority) error {
	if !filepath.IsAbs(path) || authority.NamespaceUID == "" || authority.Nonce == "" {
		return errors.New("write bootstrap authority: absolute path, Namespace UID, and nonce are required")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.Wrap(err, "write bootstrap authority")
	}
	defer func() { _ = file.Close() }()
	if err := json.NewEncoder(file).Encode(authority); err != nil {
		return errors.Wrap(err, "encode bootstrap authority")
	}
	if err := file.Sync(); err != nil {
		return errors.Wrap(err, "sync bootstrap authority")
	}
	return nil
}

// ReadBootstrapAuthority loads only a private mode-0600 bootstrap capability file.
func ReadBootstrapAuthority(path string) (BootstrapAuthority, error) {
	if !filepath.IsAbs(path) {
		return BootstrapAuthority{}, errors.New("read bootstrap authority: absolute path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return BootstrapAuthority{}, errors.Wrap(err, "read bootstrap authority")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 4096 {
		return BootstrapAuthority{}, errors.New("read bootstrap authority: regular mode-0600 bounded file is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return BootstrapAuthority{}, errors.Wrap(err, "open bootstrap authority")
	}
	defer func() { _ = file.Close() }()
	var authority BootstrapAuthority
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&authority); err != nil {
		return BootstrapAuthority{}, errors.Wrap(err, "decode bootstrap authority")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return BootstrapAuthority{}, errors.New("read bootstrap authority: exactly one JSON document is required")
	}
	if authority.NamespaceUID == "" || authority.Nonce == "" {
		return BootstrapAuthority{}, errors.New("read bootstrap authority: Namespace UID and nonce are required")
	}
	authority.capabilityFile = path
	return authority, nil
}

// RemoveBootstrapAuthority removes an unchanged capability after successful teardown.
func RemoveBootstrapAuthority(path string, expected BootstrapAuthority) error {
	current, err := ReadBootstrapAuthority(path)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, expected) {
		return errors.New("remove bootstrap authority: capability file changed")
	}
	if err := os.Remove(path); err != nil {
		return errors.Wrap(err, "remove bootstrap authority")
	}
	return nil
}

// TransitionBootstrapAuthority atomically replaces an unchanged private
// capability with one bound to the next reviewed render digest.
func TransitionBootstrapAuthority(path string, current, next BootstrapAuthority) error {
	stored, err := ReadBootstrapAuthority(path)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(stored, current) {
		return errors.New("transition bootstrap authority: capability changed")
	}
	if current.Stack != next.Stack || current.Profile != next.Profile || current.Namespace != next.Namespace || current.NamespaceUID != next.NamespaceUID || current.Nonce != next.Nonce || current.RenderDigest == next.RenderDigest {
		return errors.New("transition bootstrap authority: next authority must retain identity and change render digest")
	}
	next.capabilityFile = ""
	encoded, err := json.Marshal(next)
	if err != nil {
		return errors.Wrap(err, "encode transitioned bootstrap authority")
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".bootstrap-capability-transition-*")
	if err != nil {
		return errors.Wrap(err, "create transitioned bootstrap authority")
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return errors.Wrap(err, "chmod transitioned bootstrap authority")
	}
	if _, err := temporary.Write(append(encoded, '\n')); err != nil {
		_ = temporary.Close()
		return errors.Wrap(err, "write transitioned bootstrap authority")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errors.Wrap(err, "sync transitioned bootstrap authority")
	}
	if err := temporary.Close(); err != nil {
		return errors.Wrap(err, "close transitioned bootstrap authority")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return errors.Wrap(err, "replace transitioned bootstrap authority")
	}
	return nil
}

// RecordDeletedSecret durably records one exact precondition-deleted Secret for a retry.
func RecordDeletedSecret(authority *BootstrapAuthority, resource ResourceID, uid ObservedUID) error {
	if authority == nil || authority.capabilityFile == "" || resource == "" || uid == "" {
		return errors.New("record deleted Secret: capability path, resource, and UID are required")
	}
	current, err := ReadBootstrapAuthority(authority.capabilityFile)
	if err != nil {
		return err
	}
	if current.Stack != authority.Stack || current.Profile != authority.Profile || current.Namespace != authority.Namespace || current.NamespaceUID != authority.NamespaceUID || current.RenderDigest != authority.RenderDigest || current.Nonce != authority.Nonce {
		return errors.New("record deleted Secret: capability changed")
	}
	if current.DeletedSecrets == nil {
		current.DeletedSecrets = make(map[ResourceID]ObservedUID)
	}
	if previous, exists := current.DeletedSecrets[resource]; exists && previous != uid {
		return errors.New("record deleted Secret: resource progress identity changed")
	}
	current.DeletedSecrets[resource] = uid
	encoded, err := json.Marshal(current)
	if err != nil {
		return errors.Wrap(err, "encode deleted Secret progress")
	}
	if err := os.WriteFile(authority.capabilityFile, append(encoded, '\n'), 0o600); err != nil {
		return errors.Wrap(err, "write deleted Secret progress")
	}
	*authority = current
	return nil
}
