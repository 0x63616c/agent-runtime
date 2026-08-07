// Command generate-runtime-openapi derives private server and SDK route tables from the public OpenAPI authority.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const specificationPath = "api/openapi/openapi.yaml"

type specification struct {
	OpenAPI    string                          `json:"openapi"`
	Info       json.RawMessage                 `json:"info"`
	Servers    json.RawMessage                 `json:"servers"`
	Security   json.RawMessage                 `json:"security"`
	Paths      map[string]map[string]operation `json:"paths"`
	Components json.RawMessage                 `json:"components"`
}

type operation struct {
	OperationID string          `json:"operationId"`
	Parameters  json.RawMessage `json:"parameters"`
	RequestBody json.RawMessage `json:"requestBody"`
	Responses   json.RawMessage `json:"responses"`
}

type route struct {
	Name, Method, Path, Status string
	Mutation                   bool
}

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
	var document specification
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode runtime OpenAPI authority: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("decode runtime OpenAPI authority: exactly one document is required")
	}
	if document.OpenAPI != "3.1.0" {
		return fmt.Errorf("validate runtime OpenAPI authority: version must be 3.1.0")
	}
	if len(document.Info) == 0 || len(document.Servers) == 0 || len(document.Security) == 0 || len(document.Components) == 0 {
		return fmt.Errorf("validate runtime OpenAPI authority: info, servers, security, and components are required")
	}
	routes, err := collectRoutes(document.Paths)
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

func collectRoutes(paths map[string]map[string]operation) ([]route, error) {
	expected := map[string]route{
		"createAgent":      {Method: "POST", Path: "/v1/admin/agents", Status: "201", Mutation: true},
		"reviseAgent":      {Method: "POST", Path: "/v1/admin/agents/{agent_id}/revisions", Status: "201", Mutation: true},
		"getAgentRevision": {Method: "GET", Path: "/v1/admin/agents/{agent_id}/revisions/{revision_id}", Status: "200"},
		"createSession":    {Method: "POST", Path: "/v1/sessions", Status: "201", Mutation: true},
		"inspectSession":   {Method: "GET", Path: "/v1/sessions/{session_id}", Status: "200"},
		"sendInput":        {Method: "POST", Path: "/v1/sessions/{session_id}/inputs", Status: "202", Mutation: true},
		"inspectTurn":      {Method: "GET", Path: "/v1/sessions/{session_id}/turns/{turn_id}", Status: "200"},
		"listEvents":       {Method: "GET", Path: "/v1/sessions/{session_id}/events", Status: "200"},
		"cancelTurn":       {Method: "POST", Path: "/v1/sessions/{session_id}/turns/{turn_id}/cancel", Status: "200", Mutation: true},
		"closeSession":     {Method: "POST", Path: "/v1/sessions/{session_id}/close", Status: "200", Mutation: true},
	}
	var routes []route
	for path, methods := range paths {
		if !strings.HasPrefix(path, "/v1/") {
			return nil, fmt.Errorf("validate runtime OpenAPI authority: path %s is not versioned", path)
		}
		for method, operation := range methods {
			expectedRoute, ok := expected[operation.OperationID]
			if !ok {
				return nil, fmt.Errorf("validate runtime OpenAPI authority: unknown operation %s", operation.OperationID)
			}
			actualMethod := strings.ToUpper(method)
			if expectedRoute.Method != actualMethod || expectedRoute.Path != path || len(operation.Responses) == 0 {
				return nil, fmt.Errorf("validate runtime OpenAPI authority: operation %s has an unexpected route or no responses", operation.OperationID)
			}
			if err := validateOperationContract(operation, expectedRoute); err != nil {
				return nil, fmt.Errorf("validate runtime OpenAPI authority: operation %s: %w", operation.OperationID, err)
			}
			delete(expected, operation.OperationID)
			routes = append(routes, route{Name: operation.OperationID, Method: actualMethod, Path: path, Status: expectedRoute.Status, Mutation: expectedRoute.Mutation})
		}
	}
	if len(expected) != 0 {
		return nil, fmt.Errorf("validate runtime OpenAPI authority: missing %d required operations", len(expected))
	}
	sort.Slice(routes, func(left, right int) bool { return routes[left].Name < routes[right].Name })
	return routes, nil
}

func validateOperationContract(operation operation, expected route) error {
	var parameters []struct {
		Reference string `json:"$ref"`
	}
	if err := json.Unmarshal(operation.Parameters, &parameters); err != nil {
		return fmt.Errorf("parameters are invalid: %w", err)
	}
	references := make(map[string]struct{}, len(parameters))
	for _, parameter := range parameters {
		references[parameter.Reference] = struct{}{}
	}
	if _, ok := references["#/components/parameters/RequestID"]; !ok {
		return fmt.Errorf("request ID parameter is required")
	}
	_, hasIdempotency := references["#/components/parameters/IdempotencyKey"]
	if expected.Mutation != hasIdempotency {
		return fmt.Errorf("idempotency parameter does not match mutation semantics")
	}
	if expected.Mutation != (len(operation.RequestBody) != 0) {
		return fmt.Errorf("request body does not match mutation semantics")
	}
	var responses map[string]json.RawMessage
	if err := json.Unmarshal(operation.Responses, &responses); err != nil {
		return fmt.Errorf("responses are invalid: %w", err)
	}
	if len(responses[expected.Status]) == 0 || len(responses["default"]) == 0 {
		return fmt.Errorf("expected success and default failure responses are required")
	}
	return nil
}

func render(packageName, digest string, routes []route) []byte {
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
