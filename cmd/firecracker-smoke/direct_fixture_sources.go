package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
)

const directFixtureSourceRoot = "/var/lib/agent-runtime/firecracker-fixtures/home-server"

// directFixtureSourceMap is deliberately a path-to-locked-URL map. The lock
// remains the complete provenance and digest authority; this file only says
// where an operator placed those exact bytes for a direct, offline run.
type directFixtureSourceMap struct {
	SchemaVersion     string            `json:"schema_version"`
	FixtureLockSHA256 string            `json:"fixture_lock_sha256"`
	Sources           map[string]string `json:"sources"`
}

type directFixtureFetcher struct{ paths map[string]string }

func loadDirectFixtureSourceMap(mapPath, lockPath string) (firecracker.FixtureFetcher, error) {
	if mapPath != directFixtureSourceMapPath {
		return nil, errors.New("direct fixture source map does not match the reviewed authority")
	}
	info, err := os.Stat(mapPath)
	if err != nil || !info.Mode().IsRegular() || validateRootOwnedDirect(info) != nil {
		return nil, errors.New("root-owned direct fixture source map is unavailable")
	}
	contents, err := os.ReadFile(mapPath)
	if err != nil {
		return nil, errors.New("root-owned direct fixture source map is unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var mapping directFixtureSourceMap
	if err := decoder.Decode(&mapping); err != nil {
		return nil, errors.New("root-owned direct fixture source map is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("root-owned direct fixture source map has trailing data")
	}
	lockContents, err := os.ReadFile(lockPath)
	if err != nil || mapping.FixtureLockSHA256 != "sha256:"+sha256Hex(lockContents) {
		return nil, errors.New("direct fixture source map is not bound to the fixture lock")
	}
	if mapping.SchemaVersion != "agent-runtime.firecracker-direct-fixtures/v1" || len(mapping.Sources) != 4 {
		return nil, errors.New("root-owned direct fixture source map has an incomplete schema")
	}
	for _, directory := range []string{directFixtureSourceRoot, filepath.Join(directFixtureSourceRoot, "input"), filepath.Join(directFixtureSourceRoot, "bundles")} {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || validateRootOwnedDirect(info) != nil {
			return nil, errors.New("root-owned direct fixture directory is unavailable")
		}
	}
	lock, err := firecracker.ParseFixtureLock(bytes.NewReader(lockContents))
	if err != nil {
		return nil, errors.New("direct fixture lock is invalid")
	}
	paths := make(map[string]string, len(mapping.Sources))
	for _, id := range []string{"firecracker-release", "kernel", "rootfs", "guest-agent"} {
		path, ok := mapping.Sources[id]
		if !ok || !validDirectFixturePath(path) {
			return nil, errors.New("root-owned direct fixture source map has an invalid source path")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || validateRootOwnedDirect(info) != nil {
			return nil, errors.New("root-owned direct fixture source is unavailable")
		}
		for _, source := range lock.Sources {
			if source.ID == id {
				paths[source.URL] = path
			}
		}
	}
	return directFixtureFetcher{paths: paths}, nil
}

func validDirectFixturePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && strings.HasPrefix(path, directFixtureSourceRoot+"/")
}

func (fetcher directFixtureFetcher) Open(ctx context.Context, source string) (firecracker.FixtureResponse, error) {
	if ctx == nil {
		return firecracker.FixtureResponse{}, errors.New("fixture context is required")
	}
	if err := ctx.Err(); err != nil {
		return firecracker.FixtureResponse{}, err
	}
	path, ok := fetcher.paths[source]
	if !ok {
		return firecracker.FixtureResponse{}, fmt.Errorf("direct fixture source URL is not mapped")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || validateRootOwnedDirect(info) != nil {
		return firecracker.FixtureResponse{}, errors.New("root-owned direct fixture source changed after validation")
	}
	file, err := os.Open(path)
	if err != nil {
		return firecracker.FixtureResponse{}, err
	}
	return firecracker.FixtureResponse{Body: file, ContentLength: info.Size()}, nil
}

func sha256Hex(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}
