// firecracker-fixture-preflight validates a locally assembled candidate through
// the exact fixture provisioning boundary used by the protected smoke runner.
// It never contacts a remote URL, publishes an asset, writes a lock, or boots
// a guest.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
)

func main() {
	lockPath := flag.String("lock", "", "candidate firecracker.fixtures/v2 lock")
	firecrackerArchive := flag.String("firecracker-archive", "", "local Firecracker release archive")
	kernel := flag.String("kernel", "", "local kernel mirror")
	rootFSBundle := flag.String("rootfs-bundle", "", "local rootfs bundle")
	guestAgentBundle := flag.String("guest-agent-bundle", "", "local guest-agent bundle")
	flag.Parse()
	if flag.NArg() != 0 || *lockPath == "" || *firecrackerArchive == "" || *kernel == "" || *rootFSBundle == "" || *guestAgentBundle == "" {
		fmt.Fprintln(os.Stderr, "usage: firecracker-fixture-preflight -lock LOCK -firecracker-archive ARCHIVE -kernel KERNEL -rootfs-bundle BUNDLE -guest-agent-bundle BUNDLE")
		os.Exit(2)
	}
	if err := run(*lockPath, map[string]string{
		"firecracker-release": *firecrackerArchive,
		"kernel":              *kernel,
		"rootfs":              *rootFSBundle,
		"guest-agent":         *guestAgentBundle,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "firecracker-fixture-preflight:", err)
		os.Exit(1)
	}
}

func run(lockPath string, files map[string]string) error {
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

	urls := make(map[string]string, len(lock.Sources))
	for _, source := range lock.Sources {
		localPath, ok := files[source.ID]
		if !ok || localPath == "" {
			return fmt.Errorf("local source for %s is required", source.ID)
		}
		info, err := os.Stat(localPath)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("local source for %s must be a regular file", source.ID)
		}
		urls[source.URL] = localPath
	}
	staging, err := os.MkdirTemp("", "agent-runtime-firecracker-fixture-preflight-")
	if err != nil {
		return fmt.Errorf("create private staging: %w", err)
	}
	defer os.RemoveAll(staging)
	_, err = firecracker.ProvisionFixtures(context.Background(), lock, localFetcher{files: urls}, filepath.Join(staging, "fixtures"))
	if err != nil {
		return fmt.Errorf("provision candidate fixtures: %w", err)
	}
	return nil
}

type localFetcher struct{ files map[string]string }

func (fetcher localFetcher) Open(_ context.Context, fixtureURL string) (firecracker.FixtureResponse, error) {
	path, ok := fetcher.files[fixtureURL]
	if !ok {
		return firecracker.FixtureResponse{}, fmt.Errorf("candidate source URL is not registered")
	}
	file, err := os.Open(path)
	if err != nil {
		return firecracker.FixtureResponse{}, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return firecracker.FixtureResponse{}, err
	}
	return firecracker.FixtureResponse{Body: file, ContentLength: info.Size()}, nil
}
