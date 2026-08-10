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
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/openapicontract"
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

// GoSDKSourceLister discovers the package files that the Go tool accepts for the public SDK.
type GoSDKSourceLister interface {
	GoSDKFiles(context.Context) ([]string, error)
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

// ValidateGoSDKSourceList rejects an index whose declared source files differ from the Go tool's package discovery.
func ValidateGoSDKSourceList(ctx context.Context, manifest Manifest, lister GoSDKSourceLister) error {
	if err := validateManifest(manifest); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if lister == nil {
		return errors.New("discover Go SDK sources: lister is required")
	}
	declared := make([]string, 0)
	for _, artifact := range manifest.Generated {
		if artifact.Kind == "go-sdk-symbol-index" {
			declared = append(declared, artifact.Inputs...)
		}
	}
	if len(declared) != 0 {
		discovered, err := lister.GoSDKFiles(ctx)
		if err != nil {
			return fmt.Errorf("discover Go SDK sources: %w", err)
		}
		if err := validateGoSDKSourcePaths(discovered); err != nil {
			return err
		}
		sort.Strings(declared)
		sort.Strings(discovered)
		if !equalStrings(declared, discovered) {
			return errors.New("Go SDK source manifest differs from go list")
		}
	}
	return nil
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
		switch artifact.Kind {
		case "source-inventory":
		case "openapi-operation-index":
			if len(artifact.Inputs) != 1 || artifact.Inputs[0] != "api/openapi/openapi.yaml" {
				return fmt.Errorf("OpenAPI operation index %q must declare only api/openapi/openapi.yaml", artifact.Output)
			}
		case "go-sdk-symbol-index":
			if !containsPath(artifact.Inputs, "sdk/go/doc.go") {
				return fmt.Errorf("Go SDK symbol index %q must declare sdk/go/doc.go", artifact.Output)
			}
			for _, input := range artifact.Inputs {
				if !strings.HasPrefix(input, "sdk/go/") || !strings.HasSuffix(input, ".go") {
					return fmt.Errorf("Go SDK symbol index %q may declare only sdk/go Go sources", artifact.Output)
				}
			}
		default:
			return fmt.Errorf("output %q has unsupported artifact kind %q", artifact.Output, artifact.Kind)
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

func validateGoSDKSourcePaths(paths []string) error {
	if len(paths) == 0 {
		return errors.New("go list discovered no Go SDK source files")
	}
	seen := map[string]struct{}{}
	for _, path := range paths {
		if !strings.HasPrefix(path, "sdk/go/") || !strings.HasSuffix(path, ".go") {
			return fmt.Errorf("go list discovered invalid Go SDK source %q", path)
		}
		if _, duplicate := seen[path]; duplicate {
			return fmt.Errorf("go list discovered duplicate Go SDK source %q", path)
		}
		seen[path] = struct{}{}
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
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
	switch artifact.Kind {
	case "source-inventory":
		return renderSourceInventory(root, rendererVersion, artifact, files)
	case "openapi-operation-index":
		return renderOpenAPIOperationIndex(root, artifact, files)
	case "go-sdk-symbol-index":
		return renderGoSDKSymbolIndex(root, artifact, files)
	default:
		return nil, fmt.Errorf("render unsupported documentation artifact %q", artifact.Kind)
	}
}

func containsPath(paths []string, wanted string) bool {
	for _, path := range paths {
		if path == wanted {
			return true
		}
	}
	return false
}

func renderSourceInventory(root, rendererVersion string, artifact Artifact, files Files) ([]byte, error) {
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

func renderOpenAPIOperationIndex(root string, artifact Artifact, files Files) ([]byte, error) {
	content, err := files.ReadFile(resolve(root, artifact.Inputs[0]))
	if err != nil {
		return nil, fmt.Errorf("read declared OpenAPI contract %q: %w", artifact.Inputs[0], err)
	}
	routes, err := openapicontract.Parse(content)
	if err != nil {
		return nil, fmt.Errorf("validate declared OpenAPI contract %q: %w", artifact.Inputs[0], err)
	}
	sort.Slice(routes, func(left, right int) bool {
		if routes[left].Path != routes[right].Path {
			return routes[left].Path < routes[right].Path
		}
		return routes[left].Method < routes[right].Method
	})
	var output strings.Builder
	output.WriteString("---\ntitle: HTTP operation index\ndescription: Generated operation index for the current public Agent Runtime OpenAPI contract.\n---\n\n")
	output.WriteString("{/* Generated by refresh-agent-runtime-docs; do not edit. */}\n\n")
	output.WriteString("# HTTP operation index\n\n")
	fmt.Fprintf(&output, "This generated index is derived only from the checked-in `%s` OpenAPI `%s` contract. It lists currently declared routes; it does not claim production durability or complete runtime availability.\n\n", artifact.Inputs[0], openapicontract.SpecificationVersion)
	output.WriteString("| Method | Path | Operation ID | Successful responses |\n")
	output.WriteString("| --- | --- | --- | --- |\n")
	for _, route := range routes {
		fmt.Fprintf(&output, "| `%s` | `%s` | `%s` | `%s` |\n", route.Method, route.Path, route.Name, route.Status)
	}
	return []byte(output.String()), nil
}

type goSDKSymbol struct {
	Kind string
	Name string
	Doc  string
}

func renderGoSDKSymbolIndex(root string, artifact Artifact, files Files) ([]byte, error) {
	inputs := append([]string(nil), artifact.Inputs...)
	sort.Strings(inputs)
	fileSet := token.NewFileSet()
	symbols := make([]goSDKSymbol, 0)
	packageDoc := false
	for _, input := range inputs {
		content, err := files.ReadFile(resolve(root, input))
		if err != nil {
			return nil, fmt.Errorf("read declared Go SDK source %q: %w", input, err)
		}
		file, err := parser.ParseFile(fileSet, input, content, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parse declared Go SDK source %q: %w", input, err)
		}
		if file.Name.Name != "agentruntime" {
			return nil, fmt.Errorf("declared Go SDK source %q has package %q, want agentruntime", input, file.Name.Name)
		}
		if input == "sdk/go/doc.go" {
			if file.Doc == nil || !strings.HasPrefix(strings.TrimSpace(file.Doc.Text()), "Package agentruntime ") {
				return nil, fmt.Errorf("declared Go SDK package comment must begin with Package agentruntime")
			}
			packageDoc = true
		}
		for _, declaration := range file.Decls {
			declaredSymbols, err := exportedGoSDKSymbols(declaration)
			if err != nil {
				return nil, err
			}
			symbols = append(symbols, declaredSymbols...)
		}
	}
	if !packageDoc {
		return nil, errors.New("declared Go SDK source is missing package documentation")
	}
	if len(symbols) == 0 {
		return nil, errors.New("declared Go SDK source has no exported symbols")
	}
	sort.Slice(symbols, func(left, right int) bool {
		if symbols[left].Name != symbols[right].Name {
			return symbols[left].Name < symbols[right].Name
		}
		return symbols[left].Kind < symbols[right].Kind
	})
	var output strings.Builder
	output.WriteString("---\ntitle: Go SDK symbol index\ndescription: Generated public symbols for the current Agent Runtime Go SDK contract.\n---\n\n")
	output.WriteString("{/* Generated by refresh-agent-runtime-docs; do not edit. */}\n\n")
	output.WriteString("# Go SDK symbol index\n\n")
	output.WriteString("This index is derived only from the declared public `sdk/go` source files. It lists documented public declarations and methods in `github.com/0x63616c/agent-runtime/sdk/go` (package `agentruntime`); it does not claim runtime availability beyond the current public contract.\n\n")
	output.WriteString("| Kind | Symbol | Documentation |\n")
	output.WriteString("| --- | --- | --- |\n")
	for _, symbol := range symbols {
		fmt.Fprintf(&output, "| `%s` | `%s` | %s |\n", symbol.Kind, symbol.Name, escapeMDXTableCell(symbol.Doc))
	}
	return []byte(output.String()), nil
}

func exportedGoSDKSymbols(declaration ast.Decl) ([]goSDKSymbol, error) {
	var symbols []goSDKSymbol
	switch declaration := declaration.(type) {
	case *ast.FuncDecl:
		if declaration.Name.IsExported() {
			kind, name := "func", declaration.Name.Name
			if declaration.Recv != nil {
				receiver := goSDKReceiverName(declaration.Recv)
				if receiver == "" {
					return nil, fmt.Errorf("public Go SDK method %s has an unsupported receiver", declaration.Name.Name)
				}
				if !ast.IsExported(receiver) {
					return symbols, nil
				}
				kind, name = "method", receiver+"."+declaration.Name.Name
			}
			symbol, err := documentedGoSDKSymbol(kind, name, declaration.Name.Name, declaration.Doc)
			if err != nil {
				return nil, err
			}
			symbols = append(symbols, symbol)
		}
	case *ast.GenDecl:
		switch declaration.Tok {
		case token.TYPE:
			for _, specification := range declaration.Specs {
				typeSpec := specification.(*ast.TypeSpec)
				if typeSpec.Name.IsExported() {
					symbol, err := documentedGoSDKSymbol("type", typeSpec.Name.Name, typeSpec.Name.Name, firstComment(typeSpec.Doc, declaration.Doc))
					if err != nil {
						return nil, err
					}
					symbols = append(symbols, symbol)
					interfaceSymbols, err := exportedGoSDKInterfaceMethods(typeSpec)
					if err != nil {
						return nil, err
					}
					symbols = append(symbols, interfaceSymbols...)
				}
			}
		case token.CONST, token.VAR:
			kind := declaration.Tok.String()
			for _, specification := range declaration.Specs {
				valueSpec := specification.(*ast.ValueSpec)
				for _, name := range valueSpec.Names {
					if name.IsExported() {
						symbol, err := documentedGoSDKSymbol(kind, name.Name, name.Name, firstComment(valueSpec.Doc, declaration.Doc))
						if err != nil {
							return nil, err
						}
						symbols = append(symbols, symbol)
					}
				}
			}
		}
	}
	return symbols, nil
}

func exportedGoSDKInterfaceMethods(typeSpec *ast.TypeSpec) ([]goSDKSymbol, error) {
	interfaceType, ok := typeSpec.Type.(*ast.InterfaceType)
	if !ok || interfaceType.Methods == nil {
		return nil, nil
	}
	var symbols []goSDKSymbol
	for _, method := range interfaceType.Methods.List {
		for _, name := range method.Names {
			if !name.IsExported() {
				continue
			}
			symbol, err := documentedGoSDKSymbol("method", typeSpec.Name.Name+"."+name.Name, name.Name, method.Doc)
			if err != nil {
				return nil, err
			}
			symbols = append(symbols, symbol)
		}
	}
	return symbols, nil
}

func goSDKReceiverName(receiver *ast.FieldList) string {
	if receiver == nil || len(receiver.List) != 1 {
		return ""
	}
	return goSDKReceiverTypeName(receiver.List[0].Type)
}

func goSDKReceiverTypeName(expression ast.Expr) string {
	switch expression := expression.(type) {
	case *ast.Ident:
		return expression.Name
	case *ast.StarExpr:
		return goSDKReceiverTypeName(expression.X)
	case *ast.IndexExpr:
		return goSDKReceiverTypeName(expression.X)
	case *ast.IndexListExpr:
		return goSDKReceiverTypeName(expression.X)
	default:
		return ""
	}
}

func documentedGoSDKSymbol(kind, name, commentPrefix string, comment *ast.CommentGroup) (goSDKSymbol, error) {
	documentation := strings.Join(strings.Fields(commentText(comment)), " ")
	if documentation == "" || !strings.HasPrefix(documentation, commentPrefix+" ") {
		return goSDKSymbol{}, fmt.Errorf("undocumented public Go SDK %s %s", kind, name)
	}
	return goSDKSymbol{Kind: kind, Name: name, Doc: documentation}, nil
}

func firstComment(primary, fallback *ast.CommentGroup) *ast.CommentGroup {
	if primary != nil {
		return primary
	}
	return fallback
}

func commentText(comment *ast.CommentGroup) string {
	if comment == nil {
		return ""
	}
	return comment.Text()
}

func escapeMDXTableCell(value string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"|", "\\|",
		"{", "\\{",
		"}", "\\}",
		"<", "&lt;",
		">", "&gt;",
	)
	return replacer.Replace(value)
}

func resolve(root, path string) string {
	if root == "." || root == "" {
		return filepath.ToSlash(path)
	}
	return filepath.Join(root, filepath.FromSlash(path))
}
