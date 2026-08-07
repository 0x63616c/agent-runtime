package sandbox_test

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestPublicSandboxAPIDoesNotImportBackendPackages(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(filepath.Dir(file), "api.go"), nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse public API: %v", err)
	}
	for _, imported := range parsed.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("unquote import: %v", err)
		}
		if strings.Contains(strings.ToLower(path), "backend") || strings.Contains(strings.ToLower(path), "firecracker") || strings.Contains(strings.ToLower(path), "provider") {
			t.Fatalf("public sandbox API imports forbidden backend package %q", path)
		}
	}
}
