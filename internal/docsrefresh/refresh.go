// Package docsrefresh deterministically renders allow-listed public documentation.
package docsrefresh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

var (
	// ErrDirty means a generated output has uncommitted edits that refresh will not replace.
	ErrDirty = errors.New("generated documentation has local edits")
	// ErrNotExist identifies an absent file without coupling the renderer to an OS filesystem.
	ErrNotExist = fs.ErrNotExist
	// ErrStale means check mode found missing or byte-different generated output.
	ErrStale = errors.New("generated documentation is stale")
)

// Manifest declares every source and destination that a refresh may access.
type Manifest struct {
	SchemaVersion   int        `json:"schemaVersion"`
	RendererVersion string     `json:"rendererVersion"`
	Generated       []Artifact `json:"generated"`
	Curated         []string   `json:"curated"`
}

// Artifact declares one generated public document and its complete source allow-list.
type Artifact struct {
	Output       string   `json:"output"`
	Inputs       []string `json:"inputs"`
	Kind         string   `json:"artifactKind"`
	PublicStatus string   `json:"publicStatus"`
}

// Options selects byte-comparison-only validation instead of regeneration.
type Options struct {
	Check bool
}

// Result reports exact repository-relative paths affected by a refresh.
type Result struct {
	Changed []string
	Stale   []string
}

// Files is the narrow storage seam required by the deterministic renderer.
type Files interface {
	ReadFile(path string) ([]byte, error)
	WriteFileAtomic(path string, content []byte) error
}

// Changes reports whether replacing an existing generated path would destroy local work.
type Changes interface {
	Dirty(ctx context.Context, path string) (bool, error)
}

// LoadManifest parses a manifest without applying filesystem or VCS side effects.
func LoadManifest(content []byte) (Manifest, error) {
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode docs source manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Manifest{}, errors.New("decode docs source manifest: multiple JSON values")
		}
		return Manifest{}, fmt.Errorf("decode docs source manifest trailing content: %w", err)
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// Refresh renders every declared artifact in stable order and never reads undeclared input.
func Refresh(ctx context.Context, root string, manifest Manifest, files Files, changes Changes, options Options) (Result, error) {
	if err := validateManifest(manifest); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	curated := append([]string(nil), manifest.Curated...)
	sort.Strings(curated)
	for _, path := range curated {
		if _, err := files.ReadFile(resolve(root, path)); err != nil {
			return Result{}, fmt.Errorf("read curated documentation %q: %w", path, err)
		}
	}

	artifacts := append([]Artifact(nil), manifest.Generated...)
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Output < artifacts[j].Output })
	result := Result{}
	for _, artifact := range artifacts {
		desired, err := render(root, manifest.RendererVersion, artifact, files)
		if err != nil {
			return Result{}, err
		}
		current, err := files.ReadFile(resolve(root, artifact.Output))
		missing := errors.Is(err, ErrNotExist)
		if err != nil && !missing {
			return Result{}, fmt.Errorf("read generated output %q: %w", artifact.Output, err)
		}
		if !missing && !options.Check {
			dirty, err := changes.Dirty(ctx, artifact.Output)
			if err != nil {
				return Result{}, fmt.Errorf("inspect generated output %q: %w", artifact.Output, err)
			}
			if dirty {
				return Result{}, fmt.Errorf("%w: %s", ErrDirty, artifact.Output)
			}
		}
		if !missing && bytes.Equal(current, desired) {
			continue
		}
		if options.Check {
			result.Stale = append(result.Stale, artifact.Output)
			continue
		}
		if err := files.WriteFileAtomic(resolve(root, artifact.Output), desired); err != nil {
			return Result{}, fmt.Errorf("atomically write generated output %q: %w", artifact.Output, err)
		}
		result.Changed = append(result.Changed, artifact.Output)
	}
	if len(result.Stale) > 0 {
		return result, ErrStale
	}
	return result, nil
}

// ReviewDiffArgs returns the only paths included in the skill's final unfiltered review.
func ReviewDiffArgs() []string {
	return []string{
		"diff", "--no-ext-diff", "HEAD", "--",
		"website/",
		"skills/refresh-agent-runtime-docs/",
		"skills/develop-with-agent-runtime/",
		"deploy/catalog.yaml",
	}
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != 1 {
		return fmt.Errorf("unsupported docs source manifest schema %d", manifest.SchemaVersion)
	}
	if manifest.RendererVersion != "source-inventory/v1" {
		return fmt.Errorf("unsupported docs renderer %q", manifest.RendererVersion)
	}
	if len(manifest.Generated) == 0 {
		return errors.New("docs source manifest has no generated outputs")
	}
	seenOutputs := map[string]struct{}{}
	for _, artifact := range manifest.Generated {
		if err := validatePath(artifact.Output); err != nil {
			return fmt.Errorf("output %q %w", artifact.Output, err)
		}
		if !strings.HasPrefix(filepath.ToSlash(artifact.Output), "website/docs/reference/generated/") {
			return fmt.Errorf("output %q is outside generated reference ownership", artifact.Output)
		}
		if _, exists := seenOutputs[artifact.Output]; exists {
			return fmt.Errorf("duplicate generated output %q", artifact.Output)
		}
		seenOutputs[artifact.Output] = struct{}{}
		if len(artifact.Inputs) == 0 || artifact.Kind == "" || artifact.PublicStatus == "" {
			return fmt.Errorf("output %q is missing inputs, artifact kind, or public status", artifact.Output)
		}
		seenInputs := map[string]struct{}{}
		for _, input := range artifact.Inputs {
			if err := validatePath(input); err != nil {
				return fmt.Errorf("input %q %w", input, err)
			}
			if input == artifact.Output {
				return fmt.Errorf("output %q cannot be its own input", artifact.Output)
			}
			if _, duplicate := seenInputs[input]; duplicate {
				return fmt.Errorf("output %q has duplicate input %q", artifact.Output, input)
			}
			seenInputs[input] = struct{}{}
		}
	}
	seenCurated := map[string]struct{}{}
	for _, curated := range manifest.Curated {
		if err := validatePath(curated); err != nil {
			return fmt.Errorf("curated path %q %w", curated, err)
		}
		if _, generated := seenOutputs[curated]; generated {
			return fmt.Errorf("curated path %q is also generated", curated)
		}
		if _, duplicate := seenCurated[curated]; duplicate {
			return fmt.Errorf("duplicate curated path %q", curated)
		}
		seenCurated[curated] = struct{}{}
	}
	return nil
}

func validatePath(path string) error {
	cleaned := filepath.Clean(path)
	if path == "" || filepath.IsAbs(path) || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return errors.New("escapes repository")
	}
	if cleaned == "." || filepath.ToSlash(cleaned) != filepath.ToSlash(path) {
		return errors.New("is not a canonical repository-relative path")
	}
	return nil
}

func render(root, rendererVersion string, artifact Artifact, files Files) ([]byte, error) {
	inputs := append([]string(nil), artifact.Inputs...)
	sort.Strings(inputs)
	var output strings.Builder
	output.WriteString("---\ntitle: Source inventory\ndescription: Deterministic inventory of the sources behind this public documentation foundation.\n---\n\n")
	output.WriteString("{/* Generated by refresh-agent-runtime-docs; do not edit. */}\n\n")
	output.WriteString("# Source inventory\n\n")
	output.WriteString("This page proves which repository sources were included in the current documentation refresh. It does not claim that planned runtime capabilities exist.\n\n")
	output.WriteString("| Source | SHA-256 | Artifact | Public status | Renderer |\n")
	output.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, input := range inputs {
		content, err := files.ReadFile(resolve(root, input))
		if err != nil {
			return nil, fmt.Errorf("read declared input %q: %w", input, err)
		}
		digest := sha256.Sum256(content)
		fmt.Fprintf(&output, "| `%s` | `%s` | %s | %s | `%s` |\n", input, hex.EncodeToString(digest[:]), artifact.Kind, artifact.PublicStatus, rendererVersion)
	}
	return []byte(output.String()), nil
}

func resolve(root, path string) string {
	if root == "." || root == "" {
		return filepath.ToSlash(path)
	}
	return filepath.Join(root, filepath.FromSlash(path))
}
