// Package sandboxtransfer implements the bounded portable workspace transfer
// data plane used by sandbox host adapters.
package sandboxtransfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync/atomic"

	"github.com/0x63616c/agent-runtime/sandbox"
)

var (
	// ErrPathDenied means a requested guest path cannot be resolved safely below the workspace root.
	ErrPathDenied = errors.New("sandbox transfer path denied")
	// ErrIntegrity means an artifact's declared immutable metadata did not match its streamed bytes.
	ErrIntegrity = errors.New("sandbox transfer integrity check failed")
	// ErrTargetExists means fail-if-exists preserved an existing workspace target.
	ErrTargetExists = errors.New("sandbox transfer target already exists")
)

const workspaceGuestRoot = "/workspace"

// ArtifactSource opens an already-authorized immutable artifact by its exact public reference.
type ArtifactSource interface {
	Open(context.Context, sandbox.ArtifactRef) (io.ReadCloser, error)
}

// ArtifactDescriptor binds the immutable metadata a sink must retain alongside streamed bytes.
type ArtifactDescriptor struct{ Reference sandbox.ArtifactRef }

// ArtifactSink stores one bounded stream and returns the exact immutable reference it retained.
type ArtifactSink interface {
	Put(context.Context, ArtifactDescriptor, io.Reader) (sandbox.ArtifactRef, error)
}

// Workspace owns one descriptor-relative host view of a guest's portable workspace.
// It has no authority to resolve any other guest or host path.
type Workspace struct {
	root         *os.Root
	maximumBytes uint64
	nextStaging  atomic.Uint64
}

// OpenWorkspace opens one existing host directory as the descriptor-relative backing root for /workspace.
func OpenWorkspace(hostDirectory string, maximumBytes uint64) (*Workspace, error) {
	if hostDirectory == "" || maximumBytes == 0 {
		return nil, fmt.Errorf("open sandbox transfer workspace: host directory and byte limit are required")
	}
	root, err := os.OpenRoot(hostDirectory)
	if err != nil {
		return nil, fmt.Errorf("open sandbox transfer workspace: %w", err)
	}
	return &Workspace{root: root, maximumBytes: maximumBytes}, nil
}

// Close releases the descriptor that pins the workspace root.
func (workspace *Workspace) Close() error {
	if workspace == nil || workspace.root == nil {
		return nil
	}
	err := workspace.root.Close()
	workspace.root = nil
	return err
}

// CopyIn streams one exact immutable artifact into /workspace without exposing a host path to the caller.
func (workspace *Workspace) CopyIn(ctx context.Context, source ArtifactSource, request sandbox.CopyInRequest) (err error) {
	if workspace == nil || workspace.root == nil || ctx == nil || source == nil || !validArtifact(request.Source) {
		return fmt.Errorf("copy artifact into sandbox workspace: invalid bounded source")
	}
	if request.Source.SizeBytes > workspace.maximumBytes || request.Source.SizeBytes > maximumStreamBytes {
		return fmt.Errorf("copy artifact into sandbox workspace: %w", ErrIntegrity)
	}
	target, err := workspace.relative(request.Destination)
	if err != nil {
		return err
	}
	if err := workspace.ensureParent(target); err != nil {
		return err
	}
	if err := workspace.checkTarget(target, request.Options.Overwrite); err != nil {
		return err
	}
	reader, err := source.Open(ctx, request.Source)
	if err != nil {
		return fmt.Errorf("copy artifact into sandbox workspace: open authorized artifact: %w", err)
	}
	defer func() { err = errors.Join(err, reader.Close()) }()
	staging := workspace.stagingName(target)
	file, err := workspace.root.OpenFile(staging, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("copy artifact into sandbox workspace: create staging file: %w", err)
	}
	cleanup := true
	closed := false
	defer func() {
		var closeErr error
		if !closed {
			closeErr = file.Close()
		}
		if cleanup {
			err = errors.Join(err, workspace.root.Remove(staging))
		}
		err = errors.Join(err, closeErr)
	}()

	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), &contextReader{context: ctx, reader: io.LimitReader(reader, int64(request.Source.SizeBytes)+1)})
	if copyErr != nil {
		return fmt.Errorf("copy artifact into sandbox workspace: stream source: %w", copyErr)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("copy artifact into sandbox workspace: %w", err)
	}
	if written != int64(request.Source.SizeBytes) || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != string(request.Source.Digest) {
		return fmt.Errorf("copy artifact into sandbox workspace: %w", ErrIntegrity)
	}
	if request.Options.Durable {
		if err := file.Sync(); err != nil {
			return fmt.Errorf("copy artifact into sandbox workspace: sync staging file: %w", err)
		}
	}
	if err := applyTransferMetadata(file, request.Options); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("copy artifact into sandbox workspace: close staging file: %w", err)
	}
	closed = true
	if err := workspace.root.Rename(staging, target); err != nil {
		return fmt.Errorf("copy artifact into sandbox workspace: commit staged file: %w", err)
	}
	cleanup = false
	return nil
}

const maximumStreamBytes = uint64(1<<63 - 2)

func applyTransferMetadata(file *os.File, options sandbox.TransferOptions) error {
	if uint32(options.Mode)&^uint32(0o777) != 0 {
		return fmt.Errorf("copy artifact into sandbox workspace: invalid file mode")
	}
	mode := os.FileMode(options.Mode)
	if mode == 0 {
		mode = 0o600
	}
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("copy artifact into sandbox workspace: apply file mode: %w", err)
	}
	if options.Owner != nil {
		if err := file.Chown(int(options.Owner.UID), int(options.Owner.GID)); err != nil {
			return fmt.Errorf("copy artifact into sandbox workspace: apply file owner: %w", err)
		}
	}
	return nil
}

// CopyOut snapshots one regular /workspace file into an authorized immutable artifact sink without returning bulk bytes.
func (workspace *Workspace) CopyOut(ctx context.Context, sink ArtifactSink, request sandbox.CopyOutRequest) (sandbox.ArtifactRef, error) {
	if ctx == nil || sink == nil || !validMediaType(request.MediaType) {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace artifact out: invalid bounded destination")
	}
	source, err := workspace.relative(request.Source)
	if err != nil {
		return sandbox.ArtifactRef{}, err
	}
	if err := workspace.ensureExistingParent(source); err != nil {
		return sandbox.ArtifactRef{}, err
	}
	info, err := workspace.root.Lstat(source)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || uint64(info.Size()) > workspace.maximumBytes {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace artifact out: %w", ErrPathDenied)
	}
	if info.IsDir() {
		if request.MediaType != ArchiveMediaType {
			return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace artifact out: directory requires %q: %w", ArchiveMediaType, ErrPathDenied)
		}
		return workspace.copyDirectoryOut(ctx, sink, source)
	}
	if !info.Mode().IsRegular() {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace artifact out: %w", ErrPathDenied)
	}
	file, err := workspace.root.Open(source)
	if err != nil {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace artifact out: open source: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	count, err := io.Copy(hash, &contextReader{context: ctx, reader: io.LimitReader(file, info.Size()+1)})
	if err != nil || count != info.Size() {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace artifact out: %w", ErrIntegrity)
	}
	if err := ctx.Err(); err != nil {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace artifact out: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace artifact out: rewind source: %w", err)
	}
	descriptor := ArtifactDescriptor{Reference: sandbox.ArtifactRef{MediaType: request.MediaType, SizeBytes: uint64(count), Digest: sandbox.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil)))}}
	result, err := sink.Put(ctx, descriptor, io.LimitReader(&contextReader{context: ctx, reader: file}, count+1))
	if err != nil {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace artifact out: store immutable artifact: %w", err)
	}
	if !validArtifact(result) || result.MediaType != descriptor.Reference.MediaType || result.SizeBytes != descriptor.Reference.SizeBytes || result.Digest != descriptor.Reference.Digest {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace artifact out: %w", ErrIntegrity)
	}
	return result, nil
}

func (workspace *Workspace) relative(guestPath sandbox.GuestPath) (string, error) {
	if workspace == nil || workspace.root == nil {
		return "", fmt.Errorf("resolve sandbox workspace path: %w", ErrPathDenied)
	}
	raw := string(guestPath)
	prefix := workspaceGuestRoot + "/"
	if len(raw) <= len(prefix) || !strings.HasPrefix(raw, prefix) || path.Clean(raw) != raw || strings.ContainsRune(raw, '\\') {
		return "", fmt.Errorf("resolve sandbox workspace path: %w", ErrPathDenied)
	}
	relative := strings.TrimPrefix(raw, prefix)
	if relative == "" {
		return "", fmt.Errorf("resolve sandbox workspace path: %w", ErrPathDenied)
	}
	for _, segment := range strings.Split(relative, "/") {
		if segment == "." || segment == ".." || segment == "" {
			return "", fmt.Errorf("resolve sandbox workspace path: %w", ErrPathDenied)
		}
	}
	for _, character := range relative {
		if character < 0x21 || character > 0x7e {
			return "", fmt.Errorf("resolve sandbox workspace path: %w", ErrPathDenied)
		}
	}
	return relative, nil
}

func (workspace *Workspace) ensureParent(target string) error {
	directory := path.Dir(target)
	if directory == "." {
		return nil
	}
	current := ""
	for _, segment := range strings.Split(directory, "/") {
		if current == "" {
			current = segment
		} else {
			current += "/" + segment
		}
		info, err := workspace.root.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := workspace.root.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("create sandbox workspace parent: %w", err)
			}
			info, err = workspace.root.Lstat(current)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("resolve sandbox workspace parent: %w", ErrPathDenied)
		}
	}
	return nil
}

func (workspace *Workspace) ensureExistingParent(target string) error {
	directory := path.Dir(target)
	if directory == "." {
		return nil
	}
	current := ""
	for _, segment := range strings.Split(directory, "/") {
		if current == "" {
			current = segment
		} else {
			current += "/" + segment
		}
		info, err := workspace.root.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("resolve sandbox workspace parent: %w", ErrPathDenied)
		}
	}
	return nil
}

func (workspace *Workspace) checkTarget(target string, overwrite sandbox.OverwriteMode) error {
	info, err := workspace.root.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect sandbox workspace target: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("inspect sandbox workspace target: %w", ErrPathDenied)
	}
	if overwrite != sandbox.OverwriteAtomicReplace {
		return ErrTargetExists
	}
	return nil
}

func (workspace *Workspace) stagingName(target string) string {
	directory := path.Dir(target)
	name := ".agent-runtime-transfer-" + fmt.Sprint(workspace.nextStaging.Add(1))
	if directory == "." {
		return name
	}
	return directory + "/" + name
}

func validArtifact(reference sandbox.ArtifactRef) bool {
	if reference.ID == "" || reference.MediaType == "" || reference.SizeBytes == 0 || len(reference.Digest) != 71 || !strings.HasPrefix(string(reference.Digest), "sha256:") {
		return false
	}
	for _, character := range string(reference.Digest)[7:] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validMediaType(value string) bool {
	if len(value) < 3 || len(value) > 255 || strings.Count(value, "/") != 1 || strings.ContainsAny(value, " ;\\\t\r\n") {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || strings.ContainsRune("!#$&^_.+-/", character) {
			continue
		}
		return false
	}
	parts := strings.Split(value, "/")
	return parts[0] != "" && parts[1] != ""
}

type contextReader struct {
	context context.Context
	reader  io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.context.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}
