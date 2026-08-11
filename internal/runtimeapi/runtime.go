package runtimeapi

import (
	"context"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// Runtime owns the internal application operations used by the public HTTP routes.
type Runtime interface {
	CreateAgent(context.Context, Identity, agentruntime.CreateAgentRequest) (agentruntime.AgentSpecification, error)
	ReviseAgent(context.Context, Identity, agentruntime.ReviseAgentRequest) (agentruntime.AgentSpecification, error)
	GetAgentRevision(context.Context, Identity, agentruntime.AgentID, agentruntime.AgentRevisionID) (agentruntime.AgentSpecification, error)
	CreatePolicy(context.Context, Identity, agentruntime.CreatePolicyRequest) (agentruntime.Policy, error)
	RevisePolicy(context.Context, Identity, agentruntime.RevisePolicyRequest) (agentruntime.Policy, error)
	GetPolicy(context.Context, Identity, string, uint64) (agentruntime.Policy, error)
	ReadArtifact(context.Context, Identity, agentruntime.ArtifactID) (agentruntime.ArtifactDownload, error)
	InspectApproval(context.Context, Identity, agentruntime.ApprovalID) (agentruntime.Approval, error)
	DecideApproval(context.Context, Identity, agentruntime.DecideApprovalRequest) (agentruntime.Approval, error)
	IdempotencyStatus(context.Context, Identity, string) (agentruntime.IdempotencyStatus, error)
	CreateSession(context.Context, Identity, agentruntime.CreateSessionRequest) (agentruntime.Session, error)
	SendInput(context.Context, Identity, agentruntime.SendInputRequest) (agentruntime.SendInputResult, error)
	InspectSession(context.Context, Identity, agentruntime.SessionID) (agentruntime.SessionView, error)
	InspectTurn(context.Context, Identity, agentruntime.SessionID, agentruntime.TurnID) (agentruntime.Turn, error)
	Events(context.Context, Identity, agentruntime.SessionID, agentruntime.Cursor, int) (agentruntime.EventPage, error)
	CancelTurn(context.Context, Identity, agentruntime.CancelTurnRequest) (agentruntime.Turn, error)
	CloseSession(context.Context, Identity, agentruntime.CloseSessionRequest) (agentruntime.Session, error)
}
