package sandboxtransfer

import (
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

// S9/S10 adapter behavior matrix for SBX-026/027: a bounded immutable
// artifact copies into a canonical workspace path, a symlink escape is denied
// before host access, and checksum failure preserves the previous target.
func TestWorkspaceCopiesVerifiedArtifactsWithoutEscapingTheGuestRoot(t *testing.T) {
	root := t.TempDir()
	workspace, err := OpenWorkspace(root, 1024)
	if err != nil {
		t.Fatalf("OpenWorkspace(): %v", err)
	}
	t.Cleanup(func() { _ = workspace.Close() })
	content := []byte("portable transfer")
	ref := artifactReference(content)
	store := memoryArtifacts{sources: map[sandbox.ArtifactID][]byte{ref.ID: content}}
	request := sandbox.CopyInRequest{SandboxID: "sbx_01", Source: ref, Destination: "/workspace/results/value.txt", Options: sandbox.TransferOptions{Overwrite: sandbox.OverwriteFailIfExists}}
	if err := workspace.CopyIn(context.Background(), store, request); err != nil {
		t.Fatalf("CopyIn(): %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "results", "value.txt"))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("workspace file = %q, %v; want %q", got, err, content)
	}

	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatalf("Symlink(): %v", err)
	}
	request.Destination = "/workspace/escape/owned.txt"
	if err := workspace.CopyIn(context.Background(), store, request); !errors.Is(err, ErrPathDenied) {
		t.Fatalf("CopyIn(symlink escape) error = %v, want path denial", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "owned.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside target = %v, want absent", err)
	}
}

func TestWorkspacePreservesThePreviousTargetWhenAnArtifactDigestDoesNotMatch(t *testing.T) {
	root := t.TempDir()
	workspace, err := OpenWorkspace(root, 1024)
	if err != nil {
		t.Fatalf("OpenWorkspace(): %v", err)
	}
	t.Cleanup(func() { _ = workspace.Close() })
	if err := os.WriteFile(filepath.Join(root, "existing.txt"), []byte("previous"), 0o600); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	content := []byte("altered")
	ref := artifactReference(content)
	ref.Digest = sandbox.Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	store := memoryArtifacts{sources: map[sandbox.ArtifactID][]byte{ref.ID: content}}
	request := sandbox.CopyInRequest{SandboxID: "sbx_01", Source: ref, Destination: "/workspace/existing.txt", Options: sandbox.TransferOptions{Overwrite: sandbox.OverwriteAtomicReplace}}
	if err := workspace.CopyIn(context.Background(), store, request); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("CopyIn(digest mismatch) error = %v, want integrity refusal", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "existing.txt"))
	if err != nil || string(got) != "previous" {
		t.Fatalf("previous target = %q, %v; want preserved", got, err)
	}
}

func TestWorkspaceCancelsAnIncompleteCopyWithoutLeavingAStagingFile(t *testing.T) {
	root := t.TempDir()
	workspace, err := OpenWorkspace(root, 1024)
	if err != nil {
		t.Fatalf("OpenWorkspace(): %v", err)
	}
	t.Cleanup(func() { _ = workspace.Close() })
	content := []byte("cancel this transfer")
	ref := artifactReference(content)
	ctx, cancel := context.WithCancel(context.Background())
	store := memoryArtifacts{sources: map[sandbox.ArtifactID][]byte{ref.ID: content}, afterFirstRead: cancel}
	request := sandbox.CopyInRequest{SandboxID: "sbx_01", Source: ref, Destination: "/workspace/cancelled.txt", Options: sandbox.TransferOptions{Overwrite: sandbox.OverwriteFailIfExists}}
	if err := workspace.CopyIn(ctx, store, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("CopyIn(cancelled) error = %v, want context cancellation", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("workspace after cancellation = %#v, %v; want no partial target or staging file", entries, err)
	}
}

func TestWorkspaceCopiesOutARegularFileAsABoundedImmutableArtifact(t *testing.T) {
	root := t.TempDir()
	workspace, err := OpenWorkspace(root, 1024)
	if err != nil {
		t.Fatalf("OpenWorkspace(): %v", err)
	}
	t.Cleanup(func() { _ = workspace.Close() })
	content := []byte("outbound artifact")
	if err := os.WriteFile(filepath.Join(root, "result.txt"), content, 0o600); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	sink := &recordingSink{}
	ref, err := workspace.CopyOut(context.Background(), sink, sandbox.CopyOutRequest{SandboxID: "sbx_01", Source: "/workspace/result.txt", MediaType: "text/plain"})
	if err != nil {
		t.Fatalf("CopyOut(): %v", err)
	}
	want := artifactReference(content)
	want.MediaType = "text/plain"
	if !bytes.Equal(sink.content, content) || ref != want || sink.descriptor.Reference.ID != "" || sink.descriptor.Reference.MediaType != ref.MediaType || sink.descriptor.Reference.SizeBytes != ref.SizeBytes || sink.descriptor.Reference.Digest != ref.Digest {
		t.Fatalf("CopyOut() = %#v, sink = %#v; want immutable outbound artifact", ref, sink)
	}
}

type memoryArtifacts struct {
	sources        map[sandbox.ArtifactID][]byte
	afterFirstRead func()
}

func (store memoryArtifacts) Open(_ context.Context, reference sandbox.ArtifactRef) (io.ReadCloser, error) {
	content, found := store.sources[reference.ID]
	if !found {
		return nil, os.ErrNotExist
	}
	reader := io.Reader(bytes.NewReader(content))
	if store.afterFirstRead != nil {
		reader = &cancelAfterFirstRead{reader: reader, afterFirstRead: store.afterFirstRead}
	}
	return io.NopCloser(reader), nil
}

type cancelAfterFirstRead struct {
	reader         io.Reader
	afterFirstRead func()
	called         bool
}

func (reader *cancelAfterFirstRead) Read(buffer []byte) (int, error) {
	read, err := reader.reader.Read(buffer)
	if !reader.called {
		reader.called = true
		reader.afterFirstRead()
	}
	return read, err
}

func artifactReference(content []byte) sandbox.ArtifactRef {
	digest := sha256.Sum256(content)
	return sandbox.ArtifactRef{ID: "art_01", MediaType: "application/octet-stream", SizeBytes: uint64(len(content)), Digest: sandbox.Digest("sha256:" + hex.EncodeToString(digest[:]))}
}

type recordingSink struct {
	descriptor ArtifactDescriptor
	content    []byte
}

func (sink *recordingSink) Put(_ context.Context, descriptor ArtifactDescriptor, source io.Reader) (sandbox.ArtifactRef, error) {
	content, err := io.ReadAll(source)
	if err != nil {
		return sandbox.ArtifactRef{}, err
	}
	sink.descriptor = descriptor
	sink.content = content
	result := descriptor.Reference
	result.ID = "art_01"
	return result, nil
}
