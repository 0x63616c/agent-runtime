package runtimeapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/0x63616c/agent-runtime/internal/runtime/kernel"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
	"github.com/cockroachdb/errors"
)

// NewKernelRuntime adapts the deterministic memory-mode kernel to the internal Runtime seam.
func NewKernelRuntime(service *kernel.Kernel) (Runtime, error) {
	if service == nil {
		return nil, errors.New("create kernel runtime: kernel is required")
	}
	return kernelRuntime{kernel: service}, nil
}

type kernelRuntime struct {
	kernel *kernel.Kernel
}

var _ Runtime = kernelRuntime{}

func (runtime kernelRuntime) CreateAgent(ctx context.Context, identity Identity, request agentruntime.CreateAgentRequest) (agentruntime.AgentSpecification, error) {
	return runtime.kernel.CreateAgent(ctx, tenantScope(identity), request)
}

func (runtime kernelRuntime) ReviseAgent(ctx context.Context, identity Identity, request agentruntime.ReviseAgentRequest) (agentruntime.AgentSpecification, error) {
	return runtime.kernel.ReviseAgent(ctx, tenantScope(identity), request)
}

func (runtime kernelRuntime) GetAgentRevision(ctx context.Context, identity Identity, agentID agentruntime.AgentID, revisionID agentruntime.AgentRevisionID) (agentruntime.AgentSpecification, error) {
	return runtime.kernel.GetAgentRevision(ctx, tenantScope(identity), agentID, revisionID)
}

// ReadArtifact is intentionally unavailable in the legacy memory-only kernel.
// Artifact reads require the state-authorized immutable-content authority.
func (runtime kernelRuntime) ReadArtifact(context.Context, Identity, agentruntime.ArtifactID) (agentruntime.ArtifactDownload, error) {
	return agentruntime.ArtifactDownload{}, &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureNotFound, Message: "resource not found"}}
}

// InspectApproval is unavailable in the legacy memory-only kernel. Durable
// approval inspection requires the state authority.
func (runtime kernelRuntime) InspectApproval(context.Context, Identity, agentruntime.ApprovalID) (agentruntime.Approval, error) {
	return agentruntime.Approval{}, &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureNotFound, Message: "resource not found"}}
}

// DecideApproval is unavailable in the legacy memory-only kernel. Durable
// approval decisions require the state authority.
func (runtime kernelRuntime) DecideApproval(context.Context, Identity, agentruntime.DecideApprovalRequest) (agentruntime.Approval, error) {
	return agentruntime.Approval{}, &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureNotFound, Message: "resource not found"}}
}

// IdempotencyStatus requires the durable state receipt authority.
func (runtime kernelRuntime) IdempotencyStatus(context.Context, Identity, string) (agentruntime.IdempotencyStatus, error) {
	return agentruntime.IdempotencyStatus{}, &agentruntime.Error{Failure: agentruntime.Failure{Code: agentruntime.FailureNotFound, Message: "resource not found"}}
}

func (runtime kernelRuntime) CreateSession(ctx context.Context, identity Identity, request agentruntime.CreateSessionRequest) (agentruntime.Session, error) {
	revision, err := runtime.kernel.ResolveAgentRevision(ctx, tenantScope(identity), request.AgentRevision)
	if err != nil {
		return agentruntime.Session{}, err
	}
	return runtime.kernel.CreateSessionFromRevision(ctx, principalScope(identity), request, revision)
}

func (runtime kernelRuntime) SendInput(ctx context.Context, identity Identity, request agentruntime.SendInputRequest) (agentruntime.SendInputResult, error) {
	return runtime.kernel.SendInput(ctx, principalScope(identity), request)
}

func (runtime kernelRuntime) InspectSession(ctx context.Context, identity Identity, sessionID agentruntime.SessionID) (agentruntime.SessionView, error) {
	return runtime.kernel.InspectSession(ctx, principalScope(identity), sessionID)
}

func (runtime kernelRuntime) InspectTurn(ctx context.Context, identity Identity, sessionID agentruntime.SessionID, turnID agentruntime.TurnID) (agentruntime.Turn, error) {
	return runtime.kernel.InspectTurn(ctx, principalScope(identity), sessionID, turnID)
}

func (runtime kernelRuntime) Events(ctx context.Context, identity Identity, sessionID agentruntime.SessionID, after agentruntime.Cursor, limit int) (agentruntime.EventPage, error) {
	return runtime.kernel.Events(ctx, principalScope(identity), sessionID, after, limit)
}

func (runtime kernelRuntime) CancelTurn(ctx context.Context, identity Identity, request agentruntime.CancelTurnRequest) (agentruntime.Turn, error) {
	if _, err := runtime.kernel.InspectTurn(ctx, principalScope(identity), request.SessionID, request.TurnID); err != nil {
		return agentruntime.Turn{}, err
	}
	return runtime.kernel.CancelTurn(ctx, principalScope(identity), request)
}

func (runtime kernelRuntime) CloseSession(ctx context.Context, identity Identity, request agentruntime.CloseSessionRequest) (agentruntime.Session, error) {
	return runtime.kernel.CloseSession(ctx, principalScope(identity), request)
}

func tenantScope(identity Identity) kernel.Scope {
	return scope("tenant", identity.Tenant)
}

func principalScope(identity Identity) kernel.Scope {
	return scope("principal", identity.Tenant+"\x00"+identity.Principal)
}

func scope(kind, value string) kernel.Scope {
	digest := sha256.Sum256([]byte(kind + "\x00" + value))
	parsed, _ := kernel.ParseScope(kind + "_" + hex.EncodeToString(digest[:16]))
	return parsed
}
