// Package nowait checks owned Go code for nondeterministic real-time waiting.
package nowait

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
)

// Violation identifies one forbidden real-time wait.
type Violation struct {
	// Path identifies the source file within the checked filesystem.
	Path string
	// Line identifies the one-based source line.
	Line int
	// Rule names the deterministic-time rule that was violated.
	Rule string
}

// CheckDir checks the OS-backed source tree at root while honoring cancellation.
func CheckDir(ctx context.Context, root string) ([]Violation, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Wrap(err, "check source directory")
	}
	if root == "" {
		return nil, errors.New("check source directory: root is required")
	}
	return CheckFS(ctx, os.DirFS(root))
}

// CheckFS deterministically checks Go source supplied through an injected filesystem.
func CheckFS(ctx context.Context, sources fs.FS) ([]Violation, error) {
	if sources == nil {
		return nil, errors.New("check source filesystem: filesystem is required")
	}
	var violations []Violation
	err := fs.WalkDir(sources, ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return errors.Wrapf(walkErr, "walk source path %q", path)
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || isTestFixture(path) {
			return nil
		}
		source, err := fs.ReadFile(sources, path)
		if err != nil {
			return errors.Wrapf(err, "read Go source %q", path)
		}
		files := token.NewFileSet()
		parsed, err := parser.ParseFile(files, path, source, 0)
		if err != nil {
			return errors.Wrapf(err, "parse Go source %q", path)
		}
		violations = append(violations, inspect(path, files, parsed)...)
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "check source filesystem")
	}
	return violations, nil
}

func isTestFixture(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == "testdata" {
			return true
		}
	}
	return false
}

func inspect(path string, files *token.FileSet, file *ast.File) []Violation {
	timeNames := map[string]struct{}{}
	dotTime := false
	for _, imported := range file.Imports {
		if strings.Trim(imported.Path.Value, `"`) != "time" {
			continue
		}
		name := "time"
		if imported.Name != nil {
			name = imported.Name.Name
		}
		if name == "." {
			dotTime = true
			continue
		}
		timeNames[name] = struct{}{}
	}
	var violations []Violation
	ast.Inspect(file, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		if ident, isIdent := call.Fun.(*ast.Ident); isIdent && dotTime && forbiddenTimeCall(ident.Name) {
			violations = append(violations, newViolation(path, files, call, ident.Name))
			return true
		}
		selector, isSelector := call.Fun.(*ast.SelectorExpr)
		if !isSelector {
			return true
		}
		ident, isIdent := selector.X.(*ast.Ident)
		if !isIdent {
			return true
		}
		if _, importedTime := timeNames[ident.Name]; importedTime && forbiddenTimeCall(selector.Sel.Name) {
			violations = append(violations, newViolation(path, files, call, selector.Sel.Name))
		}
		return true
	})
	return violations
}

func newViolation(path string, files *token.FileSet, call *ast.CallExpr, name string) Violation {
	return Violation{Path: path, Line: files.Position(call.Pos()).Line, Rule: "real-time " + name}
}

func forbiddenTimeCall(name string) bool {
	switch name {
	case "Sleep", "After", "AfterFunc", "NewTimer", "NewTicker", "Tick":
		return true
	default:
		return false
	}
}
