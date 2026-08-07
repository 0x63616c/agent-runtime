// Code generated from api/openapi/openapi.yaml; DO NOT EDIT.

package runtimeapi

const (
	openAPIContractSHA256         = "dce3748e6c524c153b01298754dcc6d952f4f776a9455806334b88a70c0d30a2"
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
	openAPIMethodReviseAgent      = "POST"
	openAPIPathReviseAgent        = "/v1/admin/agents/{agent_id}/revisions"
	openAPIMethodSendInput        = "POST"
	openAPIPathSendInput          = "/v1/sessions/{session_id}/inputs"
)
