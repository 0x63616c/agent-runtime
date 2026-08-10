// Package openapicontract validates the repository-owned public Agent Runtime OpenAPI contract.
package openapicontract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	// SpecificationVersion is the only OpenAPI version accepted by the repository contract.
	SpecificationVersion = "3.1.0"
	apiInfoVersion       = "v1"
)

// Route is one validated public HTTP operation from the canonical OpenAPI contract.
type Route struct {
	Name     string
	Method   string
	Path     string
	Status   string
	Mutation bool
}

// Operation is the narrow operation shape required to validate the repository contract.
type Operation struct {
	OperationID string          `json:"operationId"`
	Parameters  json.RawMessage `json:"parameters"`
	RequestBody json.RawMessage `json:"requestBody"`
	Responses   json.RawMessage `json:"responses"`
}

type specification struct {
	OpenAPI    string                          `json:"openapi"`
	Info       info                            `json:"info"`
	Servers    []server                        `json:"servers"`
	Security   json.RawMessage                 `json:"security"`
	Paths      map[string]map[string]Operation `json:"paths"`
	Components json.RawMessage                 `json:"components"`
}

type info struct {
	Title       string `json:"title"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

type server struct {
	URL string `json:"url"`
}

// Parse decodes exactly one complete repository-owned OpenAPI document and returns its exact public route contract.
func Parse(data []byte) ([]Route, error) {
	var document specification
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode runtime OpenAPI authority: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("decode runtime OpenAPI authority: exactly one document is required")
	}
	if document.OpenAPI != SpecificationVersion {
		return nil, fmt.Errorf("validate runtime OpenAPI authority: version must be %s", SpecificationVersion)
	}
	if document.Info.Title == "" || document.Info.Version != apiInfoVersion || len(document.Servers) == 0 {
		return nil, fmt.Errorf("validate runtime OpenAPI authority: title, v1 info version, and servers are required")
	}
	for _, declaredServer := range document.Servers {
		if declaredServer.URL == "" {
			return nil, fmt.Errorf("validate runtime OpenAPI authority: server URL is required")
		}
	}
	if err := validateSecurityAuthority(document.Security, document.Components); err != nil {
		return nil, fmt.Errorf("validate runtime OpenAPI authority: %w", err)
	}
	return CollectRoutes(document.Paths)
}

// CollectRoutes validates the exact public route set independently of document decoding.
func CollectRoutes(paths map[string]map[string]Operation) ([]Route, error) {
	expected := map[string]Route{
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
	var routes []Route
	for path, methods := range paths {
		if !strings.HasPrefix(path, "/v1/") || methods == nil {
			return nil, fmt.Errorf("validate runtime OpenAPI authority: path %s is not a concrete versioned path item", path)
		}
		for method, operation := range methods {
			expectedRoute, ok := expected[operation.OperationID]
			if !ok {
				return nil, fmt.Errorf("validate runtime OpenAPI authority: unknown or duplicate operation %s", operation.OperationID)
			}
			actualMethod := strings.ToUpper(method)
			if expectedRoute.Method != actualMethod || expectedRoute.Path != path || len(operation.Responses) == 0 {
				return nil, fmt.Errorf("validate runtime OpenAPI authority: operation %s has an unexpected route or no responses", operation.OperationID)
			}
			if err := validateOperationContract(operation, expectedRoute); err != nil {
				return nil, fmt.Errorf("validate runtime OpenAPI authority: operation %s: %w", operation.OperationID, err)
			}
			delete(expected, operation.OperationID)
			expectedRoute.Name = operation.OperationID
			routes = append(routes, expectedRoute)
		}
	}
	if len(expected) != 0 {
		return nil, fmt.Errorf("validate runtime OpenAPI authority: missing %d required operations", len(expected))
	}
	sort.Slice(routes, func(left, right int) bool { return routes[left].Name < routes[right].Name })
	return routes, nil
}

func validateOperationContract(operation Operation, expected Route) error {
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
	if expected.Mutation != validJSONObject(operation.RequestBody) {
		return fmt.Errorf("request body is invalid or does not match mutation semantics")
	}
	var responses map[string]json.RawMessage
	if err := json.Unmarshal(operation.Responses, &responses); err != nil {
		return fmt.Errorf("responses are invalid: %w", err)
	}
	if !validJSONObject(responses[expected.Status]) || !validJSONObject(responses["default"]) {
		return fmt.Errorf("expected success and default failure responses are required")
	}
	return nil
}

func validateSecurityAuthority(rawSecurity, rawComponents json.RawMessage) error {
	var components map[string]json.RawMessage
	if err := json.Unmarshal(rawComponents, &components); err != nil || len(components) == 0 {
		return fmt.Errorf("components are required")
	}
	var schemes map[string]json.RawMessage
	if err := json.Unmarshal(components["securitySchemes"], &schemes); err != nil || len(schemes) == 0 {
		return fmt.Errorf("security schemes are required")
	}
	for name, rawScheme := range schemes {
		var scheme struct {
			Type string `json:"type"`
		}
		if !validJSONObject(rawScheme) || json.Unmarshal(rawScheme, &scheme) != nil || scheme.Type == "" {
			return fmt.Errorf("security scheme %q is invalid", name)
		}
	}
	var requirements []map[string]json.RawMessage
	if err := json.Unmarshal(rawSecurity, &requirements); err != nil || len(requirements) == 0 {
		return fmt.Errorf("security requirements are required")
	}
	for _, requirement := range requirements {
		if len(requirement) == 0 {
			return fmt.Errorf("security requirement is empty")
		}
		for name, rawScopes := range requirement {
			if _, exists := schemes[name]; !exists {
				return fmt.Errorf("unknown security scheme %q", name)
			}
			var scopes []string
			if bytes.Equal(rawScopes, []byte("null")) || json.Unmarshal(rawScopes, &scopes) != nil {
				return fmt.Errorf("security requirement scopes for %q are invalid", name)
			}
		}
	}
	return nil
}

func validJSONObject(value json.RawMessage) bool {
	var fields map[string]json.RawMessage
	return json.Unmarshal(value, &fields) == nil && len(fields) > 0
}
