// firecracker-release-preflight checks the local, reviewable inputs for the
// one later publication of an M4 fixture release.  It is deliberately
// read-only: it has no GitHub client, never changes fixtures.lock, and never
// starts a guest.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
)

const projectReleasePrefix = "https://github.com/0x63616c/agent-runtime/releases/download/"

type measured struct {
	SHA256    string `json:"sha256"`
	SizeBytes uint64 `json:"size_bytes"`
}

type inputManifest struct {
	SchemaVersion  string   `json:"schema_version"`
	SourceRevision string   `json:"source_revision"`
	SourceTree     measured `json:"source_tree"`
}

type commandRunner func(string, ...string) ([]byte, error)

func main() {
	candidateDir := flag.String("candidate-dir", "", "directory emitted by tools/firecracker/assemble-fixtures.sh")
	flag.Parse()
	if flag.NArg() != 0 || *candidateDir == "" {
		fmt.Fprintln(os.Stderr, "usage: firecracker-release-preflight -candidate-dir DIR")
		os.Exit(2)
	}
	if err := run(*candidateDir, runCommand); err != nil {
		fmt.Fprintln(os.Stderr, "firecracker-release-preflight:", err)
		os.Exit(1)
	}
	fmt.Println("release preflight passed: publication remains an explicit operator action")
}

func run(candidateDir string, command commandRunner) error {
	revision, err := cleanRevision(command)
	if err != nil {
		return err
	}
	lockPath := filepath.Join(candidateDir, "fixtures.lock.candidate.json")
	lockFile, err := os.Open(lockPath)
	if err != nil {
		return fmt.Errorf("open candidate lock: %w", err)
	}
	lock, parseErr := firecracker.ParseFixtureLock(lockFile)
	closeErr := lockFile.Close()
	if parseErr != nil {
		return fmt.Errorf("parse candidate lock: %w", parseErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close candidate lock: %w", closeErr)
	}
	if err := validateReleaseTarget(lock, revision); err != nil {
		return err
	}
	archive, err := archiveTree(command, revision)
	if err != nil {
		return err
	}
	for _, name := range []string{"guest-agent-inputs.json", "rootfs-inputs.json"} {
		manifest, err := readManifest(filepath.Join(candidateDir, name))
		if err != nil {
			return err
		}
		if manifest.SourceRevision != revision {
			return fmt.Errorf("%s binds %q, want current clean revision %q", name, manifest.SourceRevision, revision)
		}
		if manifest.SourceTree != measure(archive) {
			return fmt.Errorf("%s source tree does not match the current clean revision", name)
		}
	}
	for _, asset := range []struct {
		sourceID string
		path     string
	}{
		{"kernel", filepath.Join(candidateDir, "bundles", "kernel-vmlinux")},
		{"rootfs", filepath.Join(candidateDir, "bundles", "rootfs-bundle.tar.gz")},
		{"guest-agent", filepath.Join(candidateDir, "bundles", "guest-agent-bundle.tar.gz")},
	} {
		source, ok := sourceByID(lock, asset.sourceID)
		if !ok {
			return fmt.Errorf("candidate lock has no %s source", asset.sourceID)
		}
		contents, err := os.ReadFile(asset.path)
		if err != nil {
			return fmt.Errorf("read publication asset %s: %w", asset.sourceID, err)
		}
		if measure(contents) != (measured{SHA256: string(source.Digest), SizeBytes: source.SizeBytes}) {
			return fmt.Errorf("publication asset %s does not match candidate lock", asset.sourceID)
		}
	}
	return nil
}

func cleanRevision(command commandRunner) (string, error) {
	head, err := command("git", "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("read HEAD: %w", err)
	}
	revision := strings.TrimSpace(string(head))
	if len(revision) != 40 || strings.Trim(revision, "0123456789abcdef") != "" {
		return "", errors.New("HEAD must be an exact lowercase commit SHA")
	}
	for _, args := range [][]string{{"diff", "--quiet"}, {"diff", "--cached", "--quiet"}} {
		if _, err := command("git", args...); err != nil {
			return "", errors.New("checkout must be clean before release preflight")
		}
	}
	return revision, nil
}

func archiveTree(command commandRunner, revision string) ([]byte, error) {
	archive, err := command("git", "archive", "--format=tar", revision)
	if err != nil {
		return nil, fmt.Errorf("archive current source tree: %w", err)
	}
	return archive, nil
}

func validateReleaseTarget(lock firecracker.FixtureLock, revision string) error {
	target := projectReleasePrefix + "commit-" + revision + "/"
	for _, pair := range []struct{ id, asset string }{{"kernel", "kernel-vmlinux"}, {"rootfs", "rootfs-bundle.tar.gz"}, {"guest-agent", "guest-agent-bundle.tar.gz"}} {
		source, ok := sourceByID(lock, pair.id)
		if !ok {
			return fmt.Errorf("candidate lock has no %s source", pair.id)
		}
		if source.URL != target+pair.asset || source.Reference != "commit:"+revision {
			return fmt.Errorf("%s must target exactly %s", pair.id, target+pair.asset)
		}
	}
	return nil
}

func sourceByID(lock firecracker.FixtureLock, id string) (firecracker.LockedSource, bool) {
	for _, source := range lock.Sources {
		if source.ID == id {
			return source, true
		}
	}
	return firecracker.LockedSource{}, false
}

func readManifest(path string) (inputManifest, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return inputManifest{}, fmt.Errorf("read input manifest %s: %w", filepath.Base(path), err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var manifest inputManifest
	if err := decoder.Decode(&manifest); err != nil {
		return inputManifest{}, fmt.Errorf("decode input manifest %s: %w", filepath.Base(path), err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || manifest.SchemaVersion != "agent-runtime.firecracker.fixture-inputs/v1" || manifest.SourceRevision == "" || manifest.SourceTree.SHA256 == "" || manifest.SourceTree.SizeBytes == 0 {
		return inputManifest{}, fmt.Errorf("input manifest %s is incomplete", filepath.Base(path))
	}
	return manifest, nil
}

func measure(contents []byte) measured {
	digest := sha256.Sum256(contents)
	return measured{SHA256: "sha256:" + hex.EncodeToString(digest[:]), SizeBytes: uint64(len(contents))}
}

func runCommand(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}
