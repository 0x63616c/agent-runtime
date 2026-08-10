package main

import (
	"path/filepath"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/openapicontract"
)

func TestCheckedInOpenAPIAuthorityAndGeneratedBindingsAgree(t *testing.T) {
	t.Parallel()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("repository root: %v", err)
	}
	if err := run(root, true); err != nil {
		t.Fatalf("run(check): %v", err)
	}
}

func TestCollectRoutesRejectsOperationMovedToAnotherPath(t *testing.T) {
	t.Parallel()
	paths := validPaths()
	paths["/v1/sessions"]["post"] = openapicontract.Operation{OperationID: "createAgent", Responses: []byte(`{}`)}
	if _, err := openapicontract.CollectRoutes(paths); err == nil {
		t.Fatal("CollectRoutes(moved operation) error = nil")
	}
}

func TestCollectRoutesRequiresEveryPublicOperation(t *testing.T) {
	t.Parallel()
	paths := validPaths()
	delete(paths, "/v1/sessions/{session_id}/close")
	if _, err := openapicontract.CollectRoutes(paths); err == nil {
		t.Fatal("CollectRoutes(missing operation) error = nil")
	}
}

func validPaths() map[string]map[string]openapicontract.Operation {
	parameters := []byte(`[{"$ref":"#/components/parameters/RequestID"}]`)
	mutationParameters := []byte(`[{"$ref":"#/components/parameters/RequestID"},{"$ref":"#/components/parameters/IdempotencyKey"}]`)
	requestBody := []byte(`{"$ref":"#/components/requestBodies/Mutation"}`)
	responses := []byte(`{"201":{"description":"success"},"202":{"description":"success"},"200":{"description":"success"},"default":{"description":"failure"}}`)
	return map[string]map[string]openapicontract.Operation{
		"/v1/admin/agents":                                    {"post": {OperationID: "createAgent", Parameters: mutationParameters, RequestBody: requestBody, Responses: responses}},
		"/v1/admin/agents/{agent_id}/revisions":               {"post": {OperationID: "reviseAgent", Parameters: mutationParameters, RequestBody: requestBody, Responses: responses}},
		"/v1/admin/agents/{agent_id}/revisions/{revision_id}": {"get": {OperationID: "getAgentRevision", Parameters: parameters, Responses: responses}},
		"/v1/artifacts/{artifact_id}":                         {"get": {OperationID: "readArtifact", Parameters: parameters, Responses: responses}},
		"/v1/sessions":                                        {"post": {OperationID: "createSession", Parameters: mutationParameters, RequestBody: requestBody, Responses: responses}},
		"/v1/sessions/{session_id}":                           {"get": {OperationID: "inspectSession", Parameters: parameters, Responses: responses}},
		"/v1/sessions/{session_id}/inputs":                    {"post": {OperationID: "sendInput", Parameters: mutationParameters, RequestBody: requestBody, Responses: responses}},
		"/v1/sessions/{session_id}/turns/{turn_id}":           {"get": {OperationID: "inspectTurn", Parameters: parameters, Responses: responses}},
		"/v1/sessions/{session_id}/events":                    {"get": {OperationID: "listEvents", Parameters: parameters, Responses: responses}},
		"/v1/sessions/{session_id}/turns/{turn_id}/cancel":    {"post": {OperationID: "cancelTurn", Parameters: mutationParameters, RequestBody: requestBody, Responses: responses}},
		"/v1/sessions/{session_id}/close":                     {"post": {OperationID: "closeSession", Parameters: mutationParameters, RequestBody: requestBody, Responses: responses}},
	}
}
