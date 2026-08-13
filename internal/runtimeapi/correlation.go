package runtimeapi

import (
	"context"
	"strings"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

// CorrelationValues is the finite set of runtime references that may be sent
// to an operator's trace or log sink. Values are deliberately references, not
// names, content, credentials, paths, provider handles, or arbitrary labels.
//
// The fields are not metric dimensions. In particular, implementations must
// not turn this envelope into a high-cardinality metric label set.
type CorrelationValues struct {
	AgentID         string
	AgentRevisionID string
	SessionID       string
	TurnID          string
	InvocationID    string
	ToolCallID      string
	ToolExecutionID string
	ApprovalID      string
	SandboxID       string
	ProcessID       string
	OperationID     string
}

// CorrelationEnvelope is a validated, finite observability-only projection of
// runtime IDs. Its fields are private so an injected composition provider
// cannot accidentally bypass validation.
type CorrelationEnvelope struct{ values CorrelationValues }

// NewCorrelationEnvelope rejects an unsafe or oversized correlation value.
// Empty fields are omitted, which lets a caller provide only the references it
// knows without inventing cross-resource relationships.
func NewCorrelationEnvelope(values CorrelationValues) (CorrelationEnvelope, error) {
	for _, candidate := range []string{
		values.AgentID, values.AgentRevisionID, values.SessionID, values.TurnID,
		values.InvocationID, values.ToolCallID, values.ToolExecutionID,
		values.ApprovalID, values.SandboxID, values.ProcessID, values.OperationID,
	} {
		if candidate != "" && !validCorrelationReference(candidate) {
			return CorrelationEnvelope{}, errors.New("create correlation envelope: reference is unsafe or exceeds 128 bytes")
		}
	}
	return CorrelationEnvelope{values: values}, nil
}

// Values returns a value copy suitable for an observability exporter. It must
// never be used to populate application responses, public events, or metrics.
func (envelope CorrelationEnvelope) Values() CorrelationValues { return envelope.values }

func (envelope CorrelationEnvelope) merge(other CorrelationEnvelope) CorrelationEnvelope {
	merged := envelope.values
	from := other.values
	if merged.AgentID == "" {
		merged.AgentID = from.AgentID
	}
	if merged.AgentRevisionID == "" {
		merged.AgentRevisionID = from.AgentRevisionID
	}
	if merged.SessionID == "" {
		merged.SessionID = from.SessionID
	}
	if merged.TurnID == "" {
		merged.TurnID = from.TurnID
	}
	if merged.InvocationID == "" {
		merged.InvocationID = from.InvocationID
	}
	if merged.ToolCallID == "" {
		merged.ToolCallID = from.ToolCallID
	}
	if merged.ToolExecutionID == "" {
		merged.ToolExecutionID = from.ToolExecutionID
	}
	if merged.ApprovalID == "" {
		merged.ApprovalID = from.ApprovalID
	}
	if merged.SandboxID == "" {
		merged.SandboxID = from.SandboxID
	}
	if merged.ProcessID == "" {
		merged.ProcessID = from.ProcessID
	}
	if merged.OperationID == "" {
		merged.OperationID = from.OperationID
	}
	return CorrelationEnvelope{values: merged}
}

// RequestCorrelationProvider is the explicit seam through which a trusted
// runtime composition can add durable IDs that are not present in the public
// HTTP route (for example an invocation, tool execution, sandbox, or process).
// It receives the already-redacted observation: never the request body,
// credentials, raw identity, URL, or provider/backend details.
type RequestCorrelationProvider interface {
	CorrelateRequest(context.Context, RequestObservation) CorrelationEnvelope
}

func requestRouteCorrelation(path string) CorrelationEnvelope {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	values := CorrelationValues{}
	for index := 0; index+1 < len(parts); index++ {
		value := parts[index+1]
		switch parts[index] {
		case "agents":
			if id, err := agentruntime.ParseAgentID(value); err == nil {
				values.AgentID = id.String()
			}
		case "revisions":
			if id, err := agentruntime.ParseAgentRevisionID(value); err == nil {
				values.AgentRevisionID = id.String()
			}
		case "sessions":
			if id, err := agentruntime.ParseSessionID(value); err == nil {
				values.SessionID = id.String()
			}
		case "turns":
			if id, err := agentruntime.ParseTurnID(value); err == nil {
				values.TurnID = id.String()
			}
		case "approvals":
			if id, err := agentruntime.ParseApprovalID(value); err == nil {
				values.ApprovalID = id.String()
			}
		}
	}
	envelope, err := NewCorrelationEnvelope(values)
	if err != nil {
		return CorrelationEnvelope{}
	}
	return envelope
}

func validCorrelationReference(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '-' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}
