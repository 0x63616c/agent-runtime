package sandboxtransfer

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/0x63616c/agent-runtime/sandbox"
)

const maximumArchiveEntries = 1024

// ArchiveEntry is one validated portable workspace member. Only regular files
// and explicit directories are representable; links, devices, and host paths
// are deliberately excluded.
type ArchiveEntry struct {
	Path      string
	Directory bool
	SizeBytes uint64
}

// ValidateArchive reads exactly one bounded ustar-compatible workspace archive
// without extracting it. It rejects path escapes, special files, duplicate or
// overlapping entries, and aggregate-size overflow before a guest binding may
// consume it.
func ValidateArchive(ctx context.Context, source io.Reader, maximumBytes uint64) ([]ArchiveEntry, error) {
	if ctx == nil || source == nil || maximumBytes == 0 {
		return nil, fmt.Errorf("validate sandbox workspace archive: %w", ErrIntegrity)
	}
	reader := tar.NewReader(source)
	var entries []ArchiveEntry
	var total uint64
	seen := map[string]bool{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("validate sandbox workspace archive: %w", ErrIntegrity)
		}
		if len(entries) >= maximumArchiveEntries || header.Size < 0 {
			return nil, fmt.Errorf("validate sandbox workspace archive: %w", ErrIntegrity)
		}
		name, directory, ok := archivePath(header)
		if !ok {
			return nil, fmt.Errorf("validate sandbox workspace archive: %w", ErrPathDenied)
		}
		if _, exists := seen[name]; exists || archiveOverlaps(seen, name) {
			return nil, fmt.Errorf("validate sandbox workspace archive: %w", ErrPathDenied)
		}
		size := uint64(header.Size)
		if directory {
			size = 0
		}
		if size > maximumBytes-total {
			return nil, fmt.Errorf("validate sandbox workspace archive: %w", ErrIntegrity)
		}
		if _, err := io.Copy(io.Discard, io.LimitReader(&contextReader{context: ctx, reader: reader}, int64(size)+1)); err != nil {
			return nil, fmt.Errorf("validate sandbox workspace archive: %w", err)
		}
		total += size
		seen[name] = directory
		entries = append(entries, ArchiveEntry{Path: name, Directory: directory, SizeBytes: size})
	}
	return entries, nil
}

func archivePath(header *tar.Header) (string, bool, bool) {
	name := strings.TrimSuffix(header.Name, "/")
	if name == "" || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return "", false, false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return "", false, false
		}
	}
	switch header.Typeflag {
	case tar.TypeReg, tar.TypeRegA:
		return name, false, true
	case tar.TypeDir:
		return name, true, true
	default:
		return "", false, false
	}
}
func archiveOverlaps(seen map[string]bool, name string) bool {
	for prior, directory := range seen {
		if (!directory && strings.HasPrefix(name, prior+"/")) || strings.HasPrefix(prior, name+"/") {
			return true
		}
	}
	return false
}

// GuestWorkspaceBinding binds one descriptor-rooted portable workspace to the
// one guest-visible `/workspace` root. It never reveals the host directory.
type GuestWorkspaceBinding struct {
	sandboxID string
	workspace *Workspace
}

func BindGuestWorkspace(sandboxID, hostDirectory string, maximumBytes uint64) (*GuestWorkspaceBinding, error) {
	if sandboxID == "" {
		return nil, fmt.Errorf("bind guest workspace: %w", ErrPathDenied)
	}
	workspace, err := OpenWorkspace(hostDirectory, maximumBytes)
	if err != nil {
		return nil, err
	}
	return &GuestWorkspaceBinding{sandboxID: sandboxID, workspace: workspace}, nil
}
func (binding *GuestWorkspaceBinding) GuestRoot() string { return workspaceGuestRoot }

// CopyIn is the sole descriptor-rooted copy-in door exposed by a guest
// workspace binding. It refuses a cross-sandbox request before the backing
// workspace is consulted and never returns its host path.
func (binding *GuestWorkspaceBinding) CopyIn(ctx context.Context, source ArtifactSource, request sandbox.CopyInRequest) error {
	if binding == nil || binding.workspace == nil || request.SandboxID == "" || string(request.SandboxID) != binding.sandboxID {
		return fmt.Errorf("copy bound guest workspace in: %w", ErrPathDenied)
	}
	return binding.workspace.CopyIn(ctx, source, request)
}

// CopyOut is the sole descriptor-rooted copy-out door exposed by a guest
// workspace binding. It returns only an immutable artifact reference.
func (binding *GuestWorkspaceBinding) CopyOut(ctx context.Context, sink ArtifactSink, request sandbox.CopyOutRequest) (sandbox.ArtifactRef, error) {
	if binding == nil || binding.workspace == nil || request.SandboxID == "" || string(request.SandboxID) != binding.sandboxID {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy bound guest workspace out: %w", ErrPathDenied)
	}
	return binding.workspace.CopyOut(ctx, sink, request)
}

func (binding *GuestWorkspaceBinding) Close() error {
	if binding == nil {
		return nil
	}
	return binding.workspace.Close()
}
