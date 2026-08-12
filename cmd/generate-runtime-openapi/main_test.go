package main

import (
	"path/filepath"
	"testing"
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
	paths["/v1/sessions"]["post"] = operation{OperationID: "createAgent", Responses: []byte(`{}`)}
	if _, err := collectRoutes(paths); err == nil {
		t.Fatal("collectRoutes(moved operation) error = nil")
	}
}

func TestCollectRoutesRequiresEveryPublicOperation(t *testing.T) {
	t.Parallel()
	paths := validPaths()
	delete(paths, "/v1/sessions/{session_id}/close")
	if _, err := collectRoutes(paths); err == nil {
		t.Fatal("collectRoutes(missing operation) error = nil")
	}
}

func validPaths() map[string]map[string]operation {
	responses := []byte(`{}`)
	return map[string]map[string]operation{
		"/v1/admin/agents":                                    {"post": {OperationID: "createAgent", Responses: responses}},
		"/v1/admin/agents/{agent_id}/revisions":               {"post": {OperationID: "reviseAgent", Responses: responses}},
		"/v1/admin/agents/{agent_id}/revisions/{revision_id}": {"get": {OperationID: "getAgentRevision", Responses: responses}},
		"/v1/sessions":                                        {"post": {OperationID: "createSession", Responses: responses}},
		"/v1/sessions/{session_id}":                           {"get": {OperationID: "inspectSession", Responses: responses}},
		"/v1/sessions/{session_id}/inputs":                    {"post": {OperationID: "sendInput", Responses: responses}},
		"/v1/sessions/{session_id}/turns/{turn_id}":           {"get": {OperationID: "inspectTurn", Responses: responses}},
		"/v1/sessions/{session_id}/events":                    {"get": {OperationID: "listEvents", Responses: responses}},
		"/v1/sessions/{session_id}/turns/{turn_id}/cancel":    {"post": {OperationID: "cancelTurn", Responses: responses}},
		"/v1/sessions/{session_id}/close":                     {"post": {OperationID: "closeSession", Responses: responses}},
	}
}
