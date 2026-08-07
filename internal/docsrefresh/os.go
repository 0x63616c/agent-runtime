package docsrefresh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// OSFiles atomically persists generated files beneath one resolved repository root.
type OSFiles struct {
	Root string
}

// ReadFile reads one manifest-validated path.
func (f OSFiles) ReadFile(path string) ([]byte, error) {
	if err := f.ensureContained(path, false); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// WriteFileAtomic fsyncs a same-directory temporary file before replacing its target.
func (f OSFiles) WriteFileAtomic(path string, content []byte) (returnErr error) {
	directory := filepath.Dir(path)
	if err := f.ensureContained(directory, true); err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create generated output directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".docs-refresh-*")
	if err != nil {
		return fmt.Errorf("create atomic temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if returnErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return fmt.Errorf("set generated output permissions: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write atomic temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync atomic temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close atomic temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace generated output: %w", err)
	}
	return nil
}

func (f OSFiles) ensureContained(path string, allowMissing bool) error {
	root, err := filepath.EvalSymlinks(f.Root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("make repository root absolute: %w", err)
	}
	candidate, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("make documentation path absolute: %w", err)
	}
	if allowMissing {
		candidate = nearestExisting(candidate)
	}
	candidate, err = filepath.EvalSymlinks(candidate)
	if err != nil {
		return fmt.Errorf("resolve documentation path: %w", err)
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("documentation path escapes repository")
	}
	return nil
}

func nearestExisting(path string) string {
	for {
		if _, err := os.Lstat(path); err == nil {
			return path
		}
		parent := filepath.Dir(path)
		if parent == path {
			return path
		}
		path = parent
	}
}

// GitChanges checks one generated path without reading or mutating Git configuration.
type GitChanges struct {
	Root string
}

// Dirty reports staged, unstaged, or untracked changes for the exact output path.
func (g GitChanges) Dirty(ctx context.Context, path string) (bool, error) {
	command := exec.CommandContext(ctx, "git", "status", "--porcelain=v1", "--", path)
	command.Dir = g.Root
	output, err := command.Output()
	if err != nil {
		return false, fmt.Errorf("run git status: %w", err)
	}
	status := strings.TrimSpace(string(output))
	return status != "", nil
}
