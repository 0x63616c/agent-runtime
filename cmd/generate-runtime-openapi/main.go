// Command generate-runtime-openapi derives private server and SDK route tables from the public OpenAPI authority.
package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/openapicontract"
)

const specificationPath = "api/openapi/openapi.yaml"

func main() {
	check := flag.Bool("check", false, "fail when generated route files are stale")
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	if err := run(*root, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(root string, check bool) error {
	data, err := os.ReadFile(filepath.Join(root, specificationPath))
	if err != nil {
		return fmt.Errorf("read runtime OpenAPI authority: %w", err)
	}
	routes, err := openapicontract.Parse(data)
	if err != nil {
		return err
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	outputs := map[string][]byte{
		"internal/runtimeapi/openapi_routes_gen.go": render("runtimeapi", digest, routes),
		"sdk/go/openapi_routes_gen.go":              render("agentruntime", digest, routes),
	}
	for path, source := range outputs {
		formatted, err := format.Source(source)
		if err != nil {
			return fmt.Errorf("format generated runtime route table %s: %w", path, err)
		}
		fullPath := filepath.Join(root, path)
		if check {
			existing, readErr := os.ReadFile(fullPath)
			if readErr != nil || !bytes.Equal(existing, formatted) {
				return fmt.Errorf("generated runtime route table is stale: %s", path)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			return fmt.Errorf("create generated runtime route directory: %w", err)
		}
		if err := os.WriteFile(fullPath, formatted, 0o644); err != nil {
			return fmt.Errorf("write generated runtime route table: %w", err)
		}
	}
	return nil
}

func render(packageName, digest string, routes []openapicontract.Route) []byte {
	var output strings.Builder
	output.WriteString("// Code generated from api/openapi/openapi.yaml; DO NOT EDIT.\n\npackage ")
	output.WriteString(packageName)
	output.WriteString("\n\nconst (\n\topenAPIContractSHA256 = \"")
	output.WriteString(digest)
	output.WriteString("\"\n")
	for _, route := range routes {
		fmt.Fprintf(&output, "\topenAPIMethod%s = %q\n", upperFirst(route.Name), route.Method)
		fmt.Fprintf(&output, "\topenAPIPath%s = %q\n", upperFirst(route.Name), route.Path)
	}
	output.WriteString(")\n")
	return []byte(output.String())
}

func upperFirst(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}
