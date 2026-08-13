package sandboxtransfer

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestValidateArchiveAcceptsOnlyBoundedCanonicalRegularWorkspaceEntries(t *testing.T) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(&tar.Header{Name: "results", Typeflag: tar.TypeDir}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeader(&tar.Header{Name: "results/value.txt", Mode: 0o600, Size: 5, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("value")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := ValidateArchive(context.Background(), bytes.NewReader(buffer.Bytes()), 16)
	if err != nil || len(entries) != 2 || entries[1].Path != "results/value.txt" {
		t.Fatalf("ValidateArchive()=(%#v,%v)", entries, err)
	}
}

func TestGuestWorkspaceBindingCopyArchiveInMaterializesOnlyValidatedArchiveAtomically(t *testing.T) {
	archive := testArchive(t, []testArchiveMember{
		{name: "results", directory: true},
		{name: "results/value.txt", data: []byte("value")},
	})
	root := t.TempDir()
	binding, err := BindGuestWorkspace("sandbox-001", root, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	source := &archiveSource{data: archive}
	request := sandbox.CopyInRequest{SandboxID: "sandbox-001", Source: archiveArtifact(archive), Destination: "/workspace/restored", Options: sandbox.TransferOptions{Overwrite: sandbox.OverwriteFailIfExists, Durable: true}}
	if err := binding.CopyArchiveIn(context.Background(), source, request); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "restored", "results", "value.txt"))
	if err != nil || string(got) != "value" || source.opens != 1 {
		t.Fatalf("CopyArchiveIn() value=%q err=%v opens=%d", got, err, source.opens)
	}
}

func TestGuestWorkspaceBindingCopyArchiveInRefusesTraversalAndLeavesNoTarget(t *testing.T) {
	archive := testArchive(t, []testArchiveMember{{name: "../escape", data: []byte("x")}})
	root := t.TempDir()
	binding, err := BindGuestWorkspace("sandbox-001", root, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	if err := binding.CopyArchiveIn(context.Background(), &archiveSource{data: archive}, sandbox.CopyInRequest{SandboxID: "sandbox-001", Source: archiveArtifact(archive), Destination: "/workspace/rejected", Options: sandbox.TransferOptions{Overwrite: sandbox.OverwriteFailIfExists}}); !errors.Is(err, ErrPathDenied) {
		t.Fatalf("CopyArchiveIn() error = %v, want path denial", err)
	}
	if _, err := os.Stat(filepath.Join(root, "rejected")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected target stat = %v, want absent", err)
	}
}

func TestGuestWorkspaceBindingCopyArchiveInCancellationAndExistingTargetPreserveWorkspace(t *testing.T) {
	archive := testArchive(t, []testArchiveMember{{name: "result.txt", data: bytes.Repeat([]byte("x"), 1024)}})
	root := t.TempDir()
	binding, err := BindGuestWorkspace("sandbox-001", root, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	ctx, cancel := context.WithCancel(context.Background())
	source := &archiveSource{data: archive, cancel: cancel}
	request := sandbox.CopyInRequest{SandboxID: "sandbox-001", Source: archiveArtifact(archive), Destination: "/workspace/cancelled", Options: sandbox.TransferOptions{Overwrite: sandbox.OverwriteFailIfExists}}
	if err := binding.CopyArchiveIn(ctx, source, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("CopyArchiveIn() cancellation = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "cancelled")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled target stat = %v, want absent", err)
	}
	if err := os.Mkdir(filepath.Join(root, "existing"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "existing", "keep.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := &archiveSource{data: archive}
	request.Destination = "/workspace/existing"
	if err := binding.CopyArchiveIn(context.Background(), fresh, request); !errors.Is(err, ErrTargetExists) || fresh.opens != 0 {
		t.Fatalf("CopyArchiveIn() existing = %v opens=%d", err, fresh.opens)
	}
	got, err := os.ReadFile(filepath.Join(root, "existing", "keep.txt"))
	if err != nil || string(got) != "keep" {
		t.Fatalf("existing target changed: %q, %v", got, err)
	}
}

func TestGuestWorkspaceBindingCopiesADirectoryOutAsABoundedImmutableArchive(t *testing.T) {
	root := t.TempDir()
	binding, err := BindGuestWorkspace("sandbox-001", root, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	if err := os.MkdirAll(filepath.Join(root, "results", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "results", "nested", "value.txt"), []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}

	sink := &recordingSink{}
	result, err := binding.CopyOut(context.Background(), sink, sandbox.CopyOutRequest{SandboxID: "sandbox-001", Source: "/workspace/results", MediaType: ArchiveMediaType})
	if err != nil {
		t.Fatalf("CopyOut(directory) = %v", err)
	}
	if result.MediaType != ArchiveMediaType || result.SizeBytes != uint64(len(sink.content)) || result.Digest == "" {
		t.Fatalf("CopyOut(directory) result = %#v, want immutable archive metadata", result)
	}
	entries, err := ValidateArchive(context.Background(), bytes.NewReader(sink.content), 1<<20)
	if err != nil || len(entries) != 2 || entries[0] != (ArchiveEntry{Path: "nested", Directory: true}) || entries[1] != (ArchiveEntry{Path: "nested/value.txt", SizeBytes: 5}) {
		t.Fatalf("CopyOut(directory) archive entries = %#v, %v", entries, err)
	}
}

func TestGuestWorkspaceBindingDirectoryCopyOutRefusesSymlinksAndCleansStagingAfterCancellation(t *testing.T) {
	root := t.TempDir()
	binding, err := BindGuestWorkspace("sandbox-001", root, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	if err := os.Mkdir(filepath.Join(root, "results"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "results", "escape")); err != nil {
		t.Fatal(err)
	}
	request := sandbox.CopyOutRequest{SandboxID: "sandbox-001", Source: "/workspace/results", MediaType: ArchiveMediaType}
	if _, err := binding.CopyOut(context.Background(), &recordingSink{}, request); !errors.Is(err, ErrPathDenied) {
		t.Fatalf("CopyOut(directory with symlink) = %v, want path denial", err)
	}
	if err := os.Remove(filepath.Join(root, "results", "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "results", "value.txt"), []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := binding.CopyOut(ctx, cancelSink{cancel: cancel}, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("CopyOut(cancelled directory) = %v, want cancellation", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || entries[0].Name() != "results" {
		t.Fatalf("workspace after cancelled directory copy-out = %#v, %v; want only results", entries, err)
	}
}

type testArchiveMember struct {
	name      string
	directory bool
	data      []byte
}

func testArchive(t *testing.T, members []testArchiveMember) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, member := range members {
		header := &tar.Header{Name: member.name, Mode: 0o600, Typeflag: tar.TypeReg, Size: int64(len(member.data))}
		if member.directory {
			header.Typeflag, header.Size = tar.TypeDir, 0
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(member.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func archiveArtifact(data []byte) sandbox.ArtifactRef {
	hash := sha256.Sum256(data)
	return sandbox.ArtifactRef{ID: "archive-001", MediaType: ArchiveMediaType, SizeBytes: uint64(len(data)), Digest: sandbox.Digest("sha256:" + hex.EncodeToString(hash[:]))}
}

type archiveSource struct {
	data   []byte
	opens  int
	cancel context.CancelFunc
}

type cancelSink struct{ cancel context.CancelFunc }

func (sink cancelSink) Put(_ context.Context, _ ArtifactDescriptor, source io.Reader) (sandbox.ArtifactRef, error) {
	sink.cancel()
	_, err := io.ReadAll(source)
	return sandbox.ArtifactRef{}, err
}

func (source *archiveSource) Open(_ context.Context, _ sandbox.ArtifactRef) (io.ReadCloser, error) {
	source.opens++
	if source.cancel == nil {
		return io.NopCloser(bytes.NewReader(source.data)), nil
	}
	return io.NopCloser(&archiveCancelAfterFirstRead{reader: bytes.NewReader(source.data), cancel: source.cancel}), nil
}

type archiveCancelAfterFirstRead struct {
	reader io.Reader
	cancel context.CancelFunc
	done   bool
}

func (reader *archiveCancelAfterFirstRead) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	if !reader.done {
		reader.done = true
		reader.cancel()
	}
	return count, err
}
func TestValidateArchiveRefusesPathEscapeAndLinks(t *testing.T) {
	for _, header := range []*tar.Header{{Name: "../escape", Size: 1, Typeflag: tar.TypeReg}, {Name: "link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink}} {
		var buffer bytes.Buffer
		writer := tar.NewWriter(&buffer)
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			_, _ = writer.Write([]byte("x"))
		}
		_ = writer.Close()
		if _, err := ValidateArchive(context.Background(), bytes.NewReader(buffer.Bytes()), 16); err == nil {
			t.Fatalf("ValidateArchive accepted %#v", header)
		}
	}
}
