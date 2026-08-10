// Code generated from api/openapi/openapi.yaml; DO NOT EDIT.

package runtimeapi

const (
	openAPIContractSHA256         = "cf159bd26d64e1e8c010ac5b9ed6ed6216b784d7f6c67ea6aede4e30eba08354"
	openAPIMethodCancelTurn       = "POST"
	openAPIPathCancelTurn         = "/v1/sessions/{session_id}/turns/{turn_id}/cancel"
	openAPIMethodCloseSession     = "POST"
	openAPIPathCloseSession       = "/v1/sessions/{session_id}/close"
	openAPIMethodCreateAgent      = "POST"
	openAPIPathCreateAgent        = "/v1/admin/agents"
	openAPIMethodCreateSession    = "POST"
	openAPIPathCreateSession      = "/v1/sessions"
	openAPIMethodGetAgentRevision = "GET"
	openAPIPathGetAgentRevision   = "/v1/admin/agents/{agent_id}/revisions/{revision_id}"
	openAPIMethodInspectSession   = "GET"
	openAPIPathInspectSession     = "/v1/sessions/{session_id}"
	openAPIMethodInspectTurn      = "GET"
	openAPIPathInspectTurn        = "/v1/sessions/{session_id}/turns/{turn_id}"
	openAPIMethodListEvents       = "GET"
	openAPIPathListEvents         = "/v1/sessions/{session_id}/events"
	openAPIMethodReadArtifact     = "GET"
	openAPIPathReadArtifact       = "/v1/artifacts/{artifact_id}"
	openAPIMethodReviseAgent      = "POST"
	openAPIPathReviseAgent        = "/v1/admin/agents/{agent_id}/revisions"
	openAPIMethodSendInput        = "POST"
	openAPIPathSendInput          = "/v1/sessions/{session_id}/inputs"
)
