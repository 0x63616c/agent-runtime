package sandboxtransfer

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/0x63616c/agent-runtime/sandbox"
)

const maximumArchiveEntries = 1024

// ArchiveMediaType is the sole media type accepted by the portable workspace
// archive door. It is intentionally narrower than a generic file copy: an
// archive is validated then materialized as one atomic guest directory.
const ArchiveMediaType = "application/x-tar"

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
	case tar.TypeReg:
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

// CopyArchiveIn validates and atomically materializes one immutable tar
// artifact below the bound /workspace root. The destination must not exist:
// replacing a directory is deliberately not an archive operation, because a
// failed or cancelled extraction must leave the prior workspace untouched.
func (binding *GuestWorkspaceBinding) CopyArchiveIn(ctx context.Context, source ArtifactSource, request sandbox.CopyInRequest) error {
	if binding == nil || binding.workspace == nil || request.SandboxID == "" || string(request.SandboxID) != binding.sandboxID {
		return fmt.Errorf("copy archive into bound guest workspace: %w", ErrPathDenied)
	}
	return binding.workspace.CopyArchiveIn(ctx, source, request)
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

// CopyArchiveIn is the bounded archive materialization data plane. It first
// copies and verifies the immutable archive into a private descriptor-rooted
// staging file, validates every member, then extracts into a staging directory
// and renames that directory into place. No archive member can select a host
// path, create a link/special file, or leave a partial target on failure.
func (workspace *Workspace) CopyArchiveIn(ctx context.Context, source ArtifactSource, request sandbox.CopyInRequest) (err error) {
	if workspace == nil || workspace.root == nil || ctx == nil || source == nil || !validArtifact(request.Source) || request.Source.MediaType != ArchiveMediaType {
		return fmt.Errorf("copy archive into sandbox workspace: invalid bounded source")
	}
	if request.Source.SizeBytes > workspace.maximumBytes || request.Source.SizeBytes > maximumStreamBytes || request.Options.Overwrite != sandbox.OverwriteFailIfExists {
		return fmt.Errorf("copy archive into sandbox workspace: %w", ErrIntegrity)
	}
	target, err := workspace.relative(request.Destination)
	if err != nil {
		return err
	}
	if err := workspace.ensureParent(target); err != nil {
		return err
	}
	if err := workspace.checkArchiveTarget(target); err != nil {
		return err
	}

	archiveStaging := workspace.stagingName(target) + ".tar"
	extractStaging := workspace.stagingName(target)
	cleanupArchive, cleanupExtract := true, true
	defer func() {
		if cleanupExtract {
			err = errors.Join(err, workspace.root.RemoveAll(extractStaging))
		}
		if cleanupArchive {
			err = errors.Join(err, workspace.root.Remove(archiveStaging))
		}
	}()

	reader, err := source.Open(ctx, request.Source)
	if err != nil {
		return fmt.Errorf("copy archive into sandbox workspace: open authorized artifact: %w", err)
	}
	defer func() { err = errors.Join(err, reader.Close()) }()
	file, err := workspace.root.OpenFile(archiveStaging, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("copy archive into sandbox workspace: create staging artifact: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, file.Close())
		}
	}()
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), &contextReader{context: ctx, reader: io.LimitReader(reader, int64(request.Source.SizeBytes)+1)})
	if copyErr != nil {
		return fmt.Errorf("copy archive into sandbox workspace: stream source: %w", copyErr)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("copy archive into sandbox workspace: %w", err)
	}
	if written != int64(request.Source.SizeBytes) || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != string(request.Source.Digest) {
		return fmt.Errorf("copy archive into sandbox workspace: %w", ErrIntegrity)
	}
	if request.Options.Durable {
		if err := file.Sync(); err != nil {
			return fmt.Errorf("copy archive into sandbox workspace: sync staging artifact: %w", err)
		}
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("copy archive into sandbox workspace: close staging artifact: %w", err)
	}
	closed = true

	validated, err := workspace.openArchive(archiveStaging)
	if err != nil {
		return err
	}
	entries, err := ValidateArchive(ctx, validated, workspace.maximumBytes)
	closeErr := validated.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return fmt.Errorf("copy archive into sandbox workspace: close validated archive: %w", closeErr)
	}
	if err := workspace.root.Mkdir(extractStaging, 0o700); err != nil {
		return fmt.Errorf("copy archive into sandbox workspace: create extraction staging: %w", err)
	}
	if err := workspace.extractArchive(ctx, archiveStaging, extractStaging, entries, request.Options); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("copy archive into sandbox workspace: %w", err)
	}
	if err := workspace.root.Rename(extractStaging, target); err != nil {
		return fmt.Errorf("copy archive into sandbox workspace: commit staged archive: %w", err)
	}
	cleanupExtract = false
	if err := workspace.root.Remove(archiveStaging); err != nil {
		return fmt.Errorf("copy archive into sandbox workspace: remove staging artifact: %w", err)
	}
	cleanupArchive = false
	return nil
}

func (workspace *Workspace) openArchive(name string) (*os.File, error) {
	file, err := workspace.root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("copy archive into sandbox workspace: open staged archive: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("copy archive into sandbox workspace: %w", ErrIntegrity)
	}
	return file, nil
}

func (workspace *Workspace) extractArchive(ctx context.Context, archiveName, destination string, entries []ArchiveEntry, options sandbox.TransferOptions) (err error) {
	file, err := workspace.openArchive(archiveName)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	reader := tar.NewReader(file)
	for index, expected := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, err := reader.Next()
		if err != nil {
			return fmt.Errorf("copy archive into sandbox workspace: reopen validated entry %d: %w", index, ErrIntegrity)
		}
		name, directory, ok := archivePath(header)
		if !ok || name != expected.Path || directory != expected.Directory || uint64(header.Size) != expected.SizeBytes {
			return fmt.Errorf("copy archive into sandbox workspace: reopened archive changed: %w", ErrIntegrity)
		}
		member := destination + "/" + name
		if directory {
			if err := workspace.makeArchiveDirectory(member); err != nil {
				return err
			}
			continue
		}
		if err := workspace.extractArchiveFile(ctx, reader, member, expected.SizeBytes, options); err != nil {
			return err
		}
	}
	if _, err := reader.Next(); err != io.EOF {
		return fmt.Errorf("copy archive into sandbox workspace: archive changed after validation: %w", ErrIntegrity)
	}
	return nil
}

func (workspace *Workspace) makeArchiveDirectory(member string) error {
	info, err := workspace.root.Lstat(member)
	if errors.Is(err, os.ErrNotExist) {
		if err := workspace.root.Mkdir(member, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("copy archive into sandbox workspace: make archive directory: %w", err)
		}
		info, err = workspace.root.Lstat(member)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("copy archive into sandbox workspace: %w", ErrPathDenied)
	}
	return nil
}

func (workspace *Workspace) extractArchiveFile(ctx context.Context, reader io.Reader, member string, size uint64, options sandbox.TransferOptions) (err error) {
	// Archives need not spell out every directory before a member. Create any
	// implicit parent only beneath the private extraction staging directory;
	// ensureParent still rejects an existing non-directory or symlink segment.
	if err := workspace.ensureParent(member); err != nil {
		return err
	}
	file, err := workspace.root.OpenFile(member, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("copy archive into sandbox workspace: create archive member: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, file.Close())
		}
	}()
	written, copyErr := io.Copy(file, &contextReader{context: ctx, reader: io.LimitReader(reader, int64(size)+1)})
	if copyErr != nil || written != int64(size) {
		return fmt.Errorf("copy archive into sandbox workspace: extract archive member: %w", ErrIntegrity)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if options.Durable {
		if err := file.Sync(); err != nil {
			return fmt.Errorf("copy archive into sandbox workspace: sync archive member: %w", err)
		}
	}
	if err := applyTransferMetadata(file, options); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("copy archive into sandbox workspace: close archive member: %w", err)
	}
	closed = true
	return nil
}

func (workspace *Workspace) checkArchiveTarget(target string) error {
	info, err := workspace.root.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect sandbox workspace archive target: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("inspect sandbox workspace archive target: %w", ErrPathDenied)
	}
	return ErrTargetExists
}

// copyDirectoryOut constructs one bounded tar stream in a private staging file
// before giving an immutable descriptor to the artifact sink. Staging is needed
// because the sink contract requires the exact digest and length up front.
func (workspace *Workspace) copyDirectoryOut(ctx context.Context, sink ArtifactSink, source string) (result sandbox.ArtifactRef, err error) {
	staging := workspace.stagingName(source) + ".tar"
	defer func() { err = errors.Join(err, workspace.root.Remove(staging)) }()
	file, err := workspace.root.OpenFile(staging, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace directory out: create archive staging: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, file.Close())
		}
	}()
	limited := &archiveLimitWriter{writer: file, remaining: workspace.maximumBytes}
	writer := tar.NewWriter(limited)
	if err := workspace.writeArchiveDirectory(ctx, writer, source, "", limited); err != nil {
		_ = writer.Close()
		return sandbox.ArtifactRef{}, err
	}
	if err := writer.Close(); err != nil {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace directory out: finalize archive: %w", err)
	}
	if err := file.Close(); err != nil {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace directory out: close archive staging: %w", err)
	}
	closed = true

	archive, err := workspace.openArchive(staging)
	if err != nil {
		return sandbox.ArtifactRef{}, err
	}
	defer func() { err = errors.Join(err, archive.Close()) }()
	hash := sha256.New()
	count, err := io.Copy(hash, &contextReader{context: ctx, reader: io.LimitReader(archive, int64(workspace.maximumBytes)+1)})
	if err != nil || count <= 0 || uint64(count) > workspace.maximumBytes {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace directory out: %w", ErrIntegrity)
	}
	if err := ctx.Err(); err != nil {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace directory out: %w", err)
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace directory out: rewind archive: %w", err)
	}
	descriptor := ArtifactDescriptor{Reference: sandbox.ArtifactRef{MediaType: ArchiveMediaType, SizeBytes: uint64(count), Digest: sandbox.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil)))}}
	result, err = sink.Put(ctx, descriptor, io.LimitReader(&contextReader{context: ctx, reader: archive}, count+1))
	if err != nil {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace directory out: store immutable artifact: %w", err)
	}
	if !validArtifact(result) || result.MediaType != descriptor.Reference.MediaType || result.SizeBytes != descriptor.Reference.SizeBytes || result.Digest != descriptor.Reference.Digest {
		return sandbox.ArtifactRef{}, fmt.Errorf("copy sandbox workspace directory out: %w", ErrIntegrity)
	}
	return result, nil
}

func (workspace *Workspace) writeArchiveDirectory(ctx context.Context, writer *tar.Writer, directory, archivePath string, limited *archiveLimitWriter) error {
	opened, err := workspace.root.Open(directory)
	if err != nil {
		return fmt.Errorf("copy sandbox workspace directory out: open directory: %w", err)
	}
	entries, readErr := opened.ReadDir(-1)
	closeErr := opened.Close()
	if readErr != nil || closeErr != nil {
		return fmt.Errorf("copy sandbox workspace directory out: read directory: %w", errors.Join(readErr, closeErr))
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("copy sandbox workspace directory out: %w", err)
		}
		name := entry.Name()
		member := path.Join(directory, name)
		guestName := name
		if archivePath != "" {
			guestName = archivePath + "/" + name
		}
		info, err := workspace.root.Lstat(member)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("copy sandbox workspace directory out: %w", ErrPathDenied)
		}
		if info.IsDir() {
			if limited.entries >= maximumArchiveEntries {
				return fmt.Errorf("copy sandbox workspace directory out: %w", ErrIntegrity)
			}
			if err := writer.WriteHeader(&tar.Header{Name: guestName, Mode: 0o700, Typeflag: tar.TypeDir}); err != nil {
				return fmt.Errorf("copy sandbox workspace directory out: write directory header: %w", err)
			}
			limited.entries++
			if err := workspace.writeArchiveDirectory(ctx, writer, member, guestName, limited); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() || info.Size() < 0 {
			return fmt.Errorf("copy sandbox workspace directory out: %w", ErrPathDenied)
		}
		if limited.entries >= maximumArchiveEntries {
			return fmt.Errorf("copy sandbox workspace directory out: %w", ErrIntegrity)
		}
		if err := writer.WriteHeader(&tar.Header{Name: guestName, Mode: 0o600, Size: info.Size(), Typeflag: tar.TypeReg}); err != nil {
			return fmt.Errorf("copy sandbox workspace directory out: write file header: %w", err)
		}
		limited.entries++
		file, err := workspace.root.Open(member)
		if err != nil {
			return fmt.Errorf("copy sandbox workspace directory out: open source file: %w", err)
		}
		written, copyErr := io.Copy(writer, &contextReader{context: ctx, reader: io.LimitReader(file, info.Size()+1)})
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written != info.Size() {
			return fmt.Errorf("copy sandbox workspace directory out: %w", ErrIntegrity)
		}
	}
	return nil
}

type archiveLimitWriter struct {
	writer    io.Writer
	remaining uint64
	entries   uint64
}

func (writer *archiveLimitWriter) Write(data []byte) (int, error) {
	if uint64(len(data)) > writer.remaining {
		return 0, ErrIntegrity
	}
	written, err := writer.writer.Write(data)
	writer.remaining -= uint64(written)
	return written, err
}
