package runtimestate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

// CommandKind is the closed runtime-state mutation vocabulary.
type CommandKind string

const (
	CommandRegisterAgentRevision  CommandKind = "register_agent_revision"
	CommandRegisterPolicyRevision CommandKind = "register_policy_revision"
	CommandCreateSession          CommandKind = "create_session"
	CommandAdmitInput             CommandKind = "admit_input"
	CommandRegisterArtifact       CommandKind = "register_artifact"
	CommandAppendConversation     CommandKind = "append_conversation"
	CommandRecordToolIntent       CommandKind = "record_tool_intent"
	CommandRequestApproval        CommandKind = "request_approval"
	CommandDecideApproval         CommandKind = "decide_approval"
	CommandConsumeCapabilityGrant CommandKind = "consume_capability_grant"
	CommandBeginToolExecution     CommandKind = "begin_tool_execution"
	CommandRecordToolOutcome      CommandKind = "record_tool_execution_outcome"
	CommandBeginInvocation        CommandKind = "begin_invocation_attempt"
	CommandRecordOutcome          CommandKind = "record_invocation_outcome"
	CommandSettleTurn             CommandKind = "settle_turn"
	CommandCancelTurn             CommandKind = "cancel_turn"
	CommandCloseSession           CommandKind = "close_session"
	CommandClaimOutbox            CommandKind = "claim_outbox"
	CommandAcknowledgeOutbox      CommandKind = "acknowledge_outbox"
)

// ReceiptBinding is the safe compiler-owned idempotency commitment. It is not an adapter input.
type ReceiptBinding struct {
	Scope          MutationScope
	IdempotencyKey string
	Command        CommandKind
	RequestDigest  RequestDigest
}

// CompiledMutation is an opaque canonical command accepted by RuntimeStatePlanner.
// Only Compiler creates it, after it validates authority and content commitments.
type CompiledMutation struct{ mutation compiledMutation }

type compiledMutation struct {
	kind    CommandKind
	receipt ReceiptBinding
	command any
}

// Kind returns the closed command kind represented by this compiled mutation.
func (mutation CompiledMutation) Kind() CommandKind { return mutation.mutation.kind }

// ReceiptBinding returns the compiler-created idempotency binding.
func (mutation CompiledMutation) ReceiptBinding() ReceiptBinding { return mutation.mutation.receipt }

// Compiler is the sole command canonicalizer and content-handoff verifier.
type Compiler struct{ content ContentHandoffValidator }

// NewCompiler constructs the command boundary from the exact content authority that issued handoffs.
func NewCompiler(content ContentHandoffValidator) (*Compiler, error) {
	if content == nil {
		return nil, errors.New("create runtime state compiler: content handoff validator is required")
	}
	return &Compiler{content: content}, nil
}

// CompileRegisterAgentRevision validates one administrator-authorized staged identity-free specification body.
func (compiler *Compiler) CompileRegisterAgentRevision(command RegisterAgentRevisionCommand) (CompiledMutation, error) {
	command = command.Owned()
	if err := validateScope(command.Scope, AuthorityTenantAdministrator, false); err != nil {
		return CompiledMutation{}, err
	}
	if command.AgentID == "" {
		if command.ExpectedRevision != 0 {
			return CompiledMutation{}, errors.New("compile register Agent revision: new Agent has expected revision")
		}
	} else if err := validAgent(command.AgentID); err != nil || command.ExpectedRevision == 0 {
		return CompiledMutation{}, errors.New("compile register Agent revision: invalid revision target")
	}
	commitment, err := compiler.content.ValidateAgentSpecificationBodyHandoff(command.Specification)
	if err != nil || commitment.Tenant != command.Scope.Tenant || !validReference(commitment.Reference) || !validName(commitment.Name) || !validName(commitment.ModelProfile) {
		return CompiledMutation{}, ErrIntegrity
	}
	return compiler.compile(CommandRegisterAgentRevision, command.Scope, command.IdempotencyKey, struct {
		AgentID       string
		Reference     runtimecontent.Reference
		Name, Profile string
	}{command.AgentID.String(), commitment.Reference, commitment.Name, commitment.ModelProfile}, compiledRegister{command: command, commitment: commitment})
}

// CompileRegisterPolicyRevision seals a bounded immutable policy revision.
func (compiler *Compiler) CompileRegisterPolicyRevision(command RegisterPolicyRevisionCommand) (CompiledMutation, error) {
	command = command.Owned()
	if err := validateScope(command.Scope, AuthorityTenantAdministrator, false); err != nil || !validName(command.Name) || !validPolicyRules(command.Rules) {
		return CompiledMutation{}, errors.New("compile register Policy revision: invalid scope or revision")
	}
	return compiler.compile(CommandRegisterPolicyRevision, command.Scope, command.IdempotencyKey, struct {
		Name             string
		ExpectedRevision uint64
		Rules            []agentruntime.PolicyRule
	}{command.Name, command.ExpectedRevision, command.Rules}, command)
}

// CompileCreateSession validates a principal-owned revision-pinned Session command.
func (compiler *Compiler) CompileCreateSession(command CreateSessionCommand) (CompiledMutation, error) {
	command = command.Owned()
	if err := validateScope(command.Scope, AuthoritySessionOwner, true); err != nil || validRevision(command.RevisionID) != nil {
		return CompiledMutation{}, errors.New("compile create Session: invalid scope or revision")
	}
	return compiler.compile(CommandCreateSession, command.Scope, command.IdempotencyKey, struct{ Revision string }{command.RevisionID.String()}, command)
}

// CompileAdmitInput validates a principal-owned staged Input envelope command.
func (compiler *Compiler) CompileAdmitInput(command AdmitInputCommand) (CompiledMutation, error) {
	command = command.Owned()
	if err := validateScope(command.Scope, AuthoritySessionOwner, true); err != nil || validSession(command.SessionID) != nil {
		return CompiledMutation{}, errors.New("compile admit Input: invalid scope or Session")
	}
	commitment, err := compiler.content.ValidateInputEnvelopeHandoff(command.Input)
	if err != nil || commitment.Tenant != command.Scope.Tenant || !validReference(commitment.Reference) {
		return CompiledMutation{}, ErrIntegrity
	}
	return compiler.compile(CommandAdmitInput, command.Scope, command.IdempotencyKey, struct {
		Session   string
		Reference runtimecontent.Reference
	}{command.SessionID.String(), commitment.Reference}, compiledAdmit{command: command, commitment: commitment})
}

// CompileRegisterArtifact validates a worker-owned artifact tied to one exact
// Session/Turn.  A public caller cannot forge a digest or choose another owner.
func (compiler *Compiler) CompileRegisterArtifact(command RegisterArtifactCommand) (CompiledMutation, error) {
	command = command.Owned()
	if err := validateScope(command.Scope, AuthorityRuntimeWorker, true); err != nil || validSession(command.SessionID) != nil || validTurn(command.TurnID) != nil {
		return CompiledMutation{}, errors.New("compile register Artifact: invalid scope or target")
	}
	commitment, err := compiler.content.ValidateArtifactHandoff(command.Artifact)
	if err != nil || commitment.Tenant != command.Scope.Tenant || !validArtifactReference(commitment.Reference) {
		return CompiledMutation{}, ErrIntegrity
	}
	return compiler.compile(CommandRegisterArtifact, command.Scope, command.IdempotencyKey, struct {
		Session, Turn string
		Reference     runtimecontent.Reference
	}{command.SessionID.String(), command.TurnID.String(), commitment.Reference}, compiledArtifact{command: command, commitment: commitment})
}

// CompileAppendConversation validates a worker-owned immutable entry and its
// expected version before the pure planner decides conflict/idempotency.
func (compiler *Compiler) CompileAppendConversation(command AppendConversationCommand) (CompiledMutation, error) {
	command = command.Owned()
	if err := validateScope(command.Scope, AuthorityRuntimeWorker, true); err != nil || validSession(command.SessionID) != nil {
		return CompiledMutation{}, errors.New("compile append conversation: invalid scope or Session")
	}
	commitment, err := compiler.content.ValidateConversationEntryHandoff(command.Entry)
	if err != nil || commitment.Tenant != command.Scope.Tenant || !validConversationReference(commitment.Reference) {
		return CompiledMutation{}, ErrIntegrity
	}
	return compiler.compile(CommandAppendConversation, command.Scope, command.IdempotencyKey, struct {
		Session   string
		Expected  uint64
		Reference runtimecontent.Reference
	}{command.SessionID.String(), command.ExpectedVersion, commitment.Reference}, compiledConversation{command: command, commitment: commitment})
}

func (compiler *Compiler) CompileRecordToolIntent(command RecordToolIntentCommand) (CompiledMutation, error) {
	command = command.Owned()
	commitment, descriptorErr := compiler.content.ValidateToolActionDescriptorHandoff(command.Descriptor)
	if err := validateWorkerCommand(command.Scope, command.SessionID, command.TurnID, OperationID(command.ToolCallID)); err != nil || descriptorErr != nil || commitment.Tenant != command.Scope.Tenant || !validOpaque(command.ToolName, 128) || !validDigest(command.ActionDigest) || !validDigest(command.PolicyRevisionDigest) {
		return CompiledMutation{}, errors.New("compile tool intent: invalid command")
	}
	return compiler.compile(CommandRecordToolIntent, command.Scope, command.IdempotencyKey, commitment.Reference, compiledToolIntent{command, commitment.Reference})
}
func (compiler *Compiler) CompileRequestApproval(command RequestApprovalCommand) (CompiledMutation, error) {
	command = command.Owned()
	if _, parseErr := agentruntime.ParseApprovalID(command.ApprovalID); parseErr != nil || validateWorkerCommand(command.Scope, command.SessionID, command.TurnID, OperationID(command.ToolCallID)) != nil || !validDigest(command.ActionDigest) || !validDigest(command.PolicyRevisionDigest) || !validDigest(command.CapabilityDigest) || command.MaximumUses == 0 || command.MaximumUses > 32 || command.ExpiresAt.IsZero() {
		return CompiledMutation{}, errors.New("compile approval request: invalid command")
	}
	return compiler.compile(CommandRequestApproval, command.Scope, command.IdempotencyKey, command, command)
}
func (compiler *Compiler) CompileDecideApproval(command DecideApprovalCommand) (CompiledMutation, error) {
	command = command.Owned()
	if _, parseErr := agentruntime.ParseApprovalID(command.ApprovalID); parseErr != nil || validateScope(command.Scope, AuthoritySessionOwner, true) != nil || (command.Decision != "approved" && command.Decision != "denied") {
		return CompiledMutation{}, errors.New("compile approval decision: invalid command")
	}
	return compiler.compile(CommandDecideApproval, command.Scope, command.IdempotencyKey, command, command)
}

// CompileConsumeCapabilityGrant authorizes one worker-owned tool execution
// against a previously approved, bounded capability grant. The grant is never
// itself a credential and this command records no tool arguments.
func (compiler *Compiler) CompileConsumeCapabilityGrant(command ConsumeCapabilityGrantCommand) (CompiledMutation, error) {
	command = command.Owned()
	if err := validateWorkerCommand(command.Scope, command.SessionID, command.TurnID, OperationID(command.ToolCallID)); err != nil || !validOpaque(command.GrantID, 128) || !validDigest(command.PolicyRevisionDigest) {
		return CompiledMutation{}, errors.New("compile consume capability grant: invalid command")
	}
	return compiler.compile(CommandConsumeCapabilityGrant, command.Scope, command.IdempotencyKey, command, command)
}

// CompileBeginToolExecution validates one capability-bound external operation intent.
func (compiler *Compiler) CompileBeginToolExecution(command BeginToolExecutionCommand) (CompiledMutation, error) {
	command = command.Owned()
	if err := validateWorkerCommand(command.Scope, command.SessionID, command.TurnID, command.OperationID); err != nil || !validOpaque(command.GrantID, 128) || !validOpaque(command.ToolCallID, 128) {
		return CompiledMutation{}, errors.New("compile tool execution intent: invalid command")
	}
	return compiler.compile(CommandBeginToolExecution, command.Scope, command.IdempotencyKey, command, command)
}

// CompileRecordToolExecutionOutcome validates a terminal tool observation.
func (compiler *Compiler) CompileRecordToolExecutionOutcome(command RecordToolExecutionOutcomeCommand) (CompiledMutation, error) {
	command = command.Owned()
	valid := command.Outcome == ToolExecutionSucceeded && command.Result != nil && command.Failure == nil && validReference(*command.Result) || (command.Outcome == ToolExecutionFailed || command.Outcome == ToolExecutionUncertain) && command.Result == nil && validFailure(command.Failure)
	if err := validateWorkerCommand(command.Scope, command.SessionID, command.TurnID, command.OperationID); err != nil || !validOpaque(command.ToolCallID, 128) || !valid {
		return CompiledMutation{}, errors.New("compile tool execution outcome: invalid command")
	}
	return compiler.compile(CommandRecordToolOutcome, command.Scope, command.IdempotencyKey, command, command)
}

// CompileBeginInvocationAttempt validates a fenced runtime-worker intent command.
func (compiler *Compiler) CompileBeginInvocationAttempt(command BeginInvocationAttemptCommand) (CompiledMutation, error) {
	command = command.Owned()
	if err := validateWorkerCommand(command.Scope, command.SessionID, command.TurnID, command.OperationID); err != nil || command.ExpectedSessionVersion == 0 || command.ExpectedTurnVersion == 0 {
		return CompiledMutation{}, errors.New("compile invocation intent: invalid fence or scope")
	}
	return compiler.compile(CommandBeginInvocation, command.Scope, command.IdempotencyKey, command, command)
}

// CompileRecordInvocationOutcome validates one safe exact fenced invocation outcome.
func (compiler *Compiler) CompileRecordInvocationOutcome(command RecordInvocationOutcomeCommand) (CompiledMutation, error) {
	command = command.Owned()
	if err := validateWorkerCommand(command.Scope, command.SessionID, command.TurnID, command.OperationID); err != nil || command.Ordinal == 0 || command.Fence == 0 || command.ExpectedSessionVersion == 0 || command.ExpectedTurnVersion == 0 || !validOutcome(command.Outcome, command.Result, command.Failure) {
		return CompiledMutation{}, errors.New("compile invocation outcome: invalid outcome or fence")
	}
	return compiler.compile(CommandRecordOutcome, command.Scope, command.IdempotencyKey, outcomeDigestShape(command), command)
}

// CompileSettleTurn validates one fenced terminal settlement command.
func (compiler *Compiler) CompileSettleTurn(command SettleTurnCommand) (CompiledMutation, error) {
	command = command.Owned()
	if err := validateScope(command.Scope, AuthorityRuntimeWorker, true); err != nil || validSession(command.SessionID) != nil || validTurn(command.TurnID) != nil || command.ExpectedSessionVersion == 0 || command.ExpectedTurnVersion == 0 || !validTerminal(command.Outcome) {
		return CompiledMutation{}, errors.New("compile settle Turn: invalid outcome or fence")
	}
	return compiler.compile(CommandSettleTurn, command.Scope, command.IdempotencyKey, command, command)
}

// CompileCancelTurn validates a principal-owned cancellation command.
func (compiler *Compiler) CompileCancelTurn(command CancelTurnCommand) (CompiledMutation, error) {
	command = command.Owned()
	if err := validateScope(command.Scope, AuthoritySessionOwner, true); err != nil || validSession(command.SessionID) != nil || validTurn(command.TurnID) != nil {
		return CompiledMutation{}, errors.New("compile cancel Turn: invalid scope or target")
	}
	return compiler.compile(CommandCancelTurn, command.Scope, command.IdempotencyKey, command, command)
}

// CompileCloseSession validates a principal-owned Session close command.
func (compiler *Compiler) CompileCloseSession(command CloseSessionCommand) (CompiledMutation, error) {
	command = command.Owned()
	if err := validateScope(command.Scope, AuthoritySessionOwner, true); err != nil || validSession(command.SessionID) != nil {
		return CompiledMutation{}, errors.New("compile close Session: invalid scope or target")
	}
	return compiler.compile(CommandCloseSession, command.Scope, command.IdempotencyKey, command, command)
}

// CompileClaimOutbox validates one publisher-authorized lease command.
func (compiler *Compiler) CompileClaimOutbox(command ClaimOutboxCommand) (CompiledMutation, error) {
	command = command.Owned()
	if err := validateScope(command.Scope, AuthorityOutboxPublisher, false); err != nil || !validOpaque(string(command.OutboxID), 128) || command.ExpectedVersion == 0 || !validOpaque(command.Claimer, 128) || command.ClaimUntil.IsZero() {
		return CompiledMutation{}, errors.New("compile claim Outbox: invalid lease")
	}
	return compiler.compile(CommandClaimOutbox, command.Scope, command.IdempotencyKey, command, command)
}

// CompileAcknowledgeOutbox validates one publisher-authorized exact lease acknowledgement.
func (compiler *Compiler) CompileAcknowledgeOutbox(command AcknowledgeOutboxCommand) (CompiledMutation, error) {
	command = command.Owned()
	if err := validateScope(command.Scope, AuthorityOutboxPublisher, false); err != nil || !validOpaque(string(command.OutboxID), 128) || command.ExpectedVersion == 0 || !validOpaque(command.Claimer, 128) || command.PublishedAt.IsZero() {
		return CompiledMutation{}, errors.New("compile acknowledge Outbox: invalid acknowledgement")
	}
	return compiler.compile(CommandAcknowledgeOutbox, command.Scope, command.IdempotencyKey, command, command)
}

// AgentSpecificationBodyReadCommand requests compiler-validated state-scoped body-read authority.
type AgentSpecificationBodyReadCommand struct {
	Scope      MutationScope
	AgentID    agentruntime.AgentID
	RevisionID agentruntime.AgentRevisionID
}

// InputEnvelopeReadCommand requests compiler-validated state-scoped Input-read authority.
type InputEnvelopeReadCommand struct {
	Scope     MutationScope
	SessionID agentruntime.SessionID
	InputID   agentruntime.InputID
}

// ArtifactReadCommand requests compiler-validated principal-owned artifact read authority.
type ArtifactReadCommand struct {
	Scope      MutationScope
	ArtifactID agentruntime.ArtifactID
}
type ToolActionDescriptorReadCommand struct {
	Scope      MutationScope
	SessionID  agentruntime.SessionID
	TurnID     agentruntime.TurnID
	ToolCallID string
}

// CompiledReadAuthorization is an opaque validated reader capability for an adapter query.
type CompiledReadAuthorization struct {
	scope      MutationScope
	agentID    agentruntime.AgentID
	revisionID agentruntime.AgentRevisionID
	sessionID  agentruntime.SessionID
	inputID    agentruntime.InputID
	artifactID agentruntime.ArtifactID
	turnID     agentruntime.TurnID
	toolCallID string
}

// Scope returns the authenticated reader scope.
func (authorization CompiledReadAuthorization) Scope() MutationScope { return authorization.scope }

// AgentRevision returns the authorized Agent revision reader target.
func (authorization CompiledReadAuthorization) AgentRevision() (agentruntime.AgentID, agentruntime.AgentRevisionID) {
	return authorization.agentID, authorization.revisionID
}

// Input returns the authorized Input reader target.
func (authorization CompiledReadAuthorization) Input() (agentruntime.SessionID, agentruntime.InputID) {
	return authorization.sessionID, authorization.inputID
}

// Artifact returns the exact authorized immutable artifact target.
func (authorization CompiledReadAuthorization) Artifact() agentruntime.ArtifactID {
	return authorization.artifactID
}
func (authorization CompiledReadAuthorization) ToolActionDescriptor() (agentruntime.SessionID, agentruntime.TurnID, string) {
	return authorization.sessionID, authorization.turnID, authorization.toolCallID
}

// CompileAuthorizeAgentSpecificationBodyRead validates a tenant-scoped metadata reader request.
func (compiler *Compiler) CompileAuthorizeAgentSpecificationBodyRead(command AgentSpecificationBodyReadCommand) (CompiledReadAuthorization, error) {
	if err := validateScope(command.Scope, AuthorityTenantAdministrator, false); err != nil || validAgent(command.AgentID) != nil || validRevision(command.RevisionID) != nil {
		return CompiledReadAuthorization{}, errors.New("compile Agent specification body reader: invalid scope or target")
	}
	return CompiledReadAuthorization{scope: command.Scope, agentID: command.AgentID, revisionID: command.RevisionID}, nil
}

// CompileAuthorizeInputEnvelopeRead validates a principal-owned metadata reader request.
func (compiler *Compiler) CompileAuthorizeInputEnvelopeRead(command InputEnvelopeReadCommand) (CompiledReadAuthorization, error) {
	if err := validateScope(command.Scope, AuthoritySessionOwner, true); err != nil || validSession(command.SessionID) != nil || validInput(command.InputID) != nil {
		return CompiledReadAuthorization{}, errors.New("compile Input envelope reader: invalid scope or target")
	}
	return CompiledReadAuthorization{scope: command.Scope, sessionID: command.SessionID, inputID: command.InputID}, nil
}

// CompileAuthorizeArtifactRead validates a principal-owned metadata reader request.
func (compiler *Compiler) CompileAuthorizeArtifactRead(command ArtifactReadCommand) (CompiledReadAuthorization, error) {
	if err := validateScope(command.Scope, AuthoritySessionOwner, true); err != nil || validArtifact(command.ArtifactID) != nil {
		return CompiledReadAuthorization{}, errors.New("compile Artifact reader: invalid scope or target")
	}
	return CompiledReadAuthorization{scope: command.Scope, artifactID: command.ArtifactID}, nil
}
func (compiler *Compiler) CompileAuthorizeToolActionDescriptorRead(command ToolActionDescriptorReadCommand) (CompiledReadAuthorization, error) {
	if err := validateScope(command.Scope, AuthorityRuntimeWorker, true); err != nil || validSession(command.SessionID) != nil || validTurn(command.TurnID) != nil || !validOpaque(command.ToolCallID, 128) {
		return CompiledReadAuthorization{}, errors.New("compile tool action descriptor reader: invalid scope or target")
	}
	return CompiledReadAuthorization{scope: command.Scope, sessionID: command.SessionID, turnID: command.TurnID, toolCallID: command.ToolCallID}, nil
}

type compiledRegister struct {
	command    RegisterAgentRevisionCommand
	commitment runtimecontent.AgentSpecificationBodyCommitment
}
type compiledAdmit struct {
	command    AdmitInputCommand
	commitment runtimecontent.InputEnvelopeCommitment
}
type compiledArtifact struct {
	command    RegisterArtifactCommand
	commitment runtimecontent.ArtifactCommitment
}
type compiledConversation struct {
	command    AppendConversationCommand
	commitment runtimecontent.ConversationEntryCommitment
}
type compiledToolIntent struct {
	command    RecordToolIntentCommand
	descriptor runtimecontent.Reference
}

func (compiler *Compiler) compile(kind CommandKind, scope MutationScope, key string, shape any, command any) (CompiledMutation, error) {
	if !validOpaque(key, 256) {
		return CompiledMutation{}, errors.New("compile runtime state command: invalid idempotency key")
	}
	canonical, err := json.Marshal(struct {
		Version string        `json:"version"`
		Kind    CommandKind   `json:"kind"`
		Scope   MutationScope `json:"scope"`
		Key     string        `json:"key"`
		Shape   any           `json:"shape"`
	}{"runtime-state-command/v1", kind, scope, key, shape})
	if err != nil {
		return CompiledMutation{}, fmt.Errorf("canonical runtime state command: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return CompiledMutation{mutation: compiledMutation{kind: kind, receipt: ReceiptBinding{Scope: scope, IdempotencyKey: key, Command: kind, RequestDigest: RequestDigest("sha256:" + hex.EncodeToString(digest[:]))}, command: command}}, nil
}

func validateScope(scope MutationScope, authority Authority, requirePrincipal bool) error {
	if scope.Authority != authority || !validOpaque(string(scope.Tenant), 128) || (requirePrincipal && !validOpaque(string(scope.Principal), 128)) {
		return errors.New("invalid runtime state command scope")
	}
	if !requirePrincipal && scope.Principal != "" && !validOpaque(string(scope.Principal), 128) {
		return errors.New("invalid runtime state command principal")
	}
	return nil
}
func validateWorkerCommand(scope MutationScope, session agentruntime.SessionID, turn agentruntime.TurnID, operation OperationID) error {
	if err := validateScope(scope, AuthorityRuntimeWorker, true); err != nil || validSession(session) != nil || validTurn(turn) != nil || !validOpaque(string(operation), 128) {
		return errors.New("invalid runtime worker command")
	}
	return nil
}
func validOpaque(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value
}
func validDigest(value string) bool {
	return len(value) == 71 && strings.HasPrefix(value, "sha256:") && strings.Trim(value[7:], "0123456789abcdef") == ""
}
func validName(value string) bool { return validOpaque(value, 128) }
func validPolicyRules(rules []agentruntime.PolicyRule) bool {
	if len(rules) == 0 || len(rules) > 64 {
		return false
	}
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if !validName(rule.ToolName) || (rule.Decision != agentruntime.PolicyDenied && rule.Decision != agentruntime.PolicyRequiresApproval) {
			return false
		}
		if _, exists := seen[rule.ToolName]; exists {
			return false
		}
		seen[rule.ToolName] = struct{}{}
	}
	return true
}
func validReference(reference runtimecontent.Reference) bool {
	return reference.SizeBytes > 0 && reference.SizeBytes <= 2<<20+4<<10 && validOpaque(reference.Digest, 128) && validOpaque(reference.MediaType, 256)
}
func validArtifactReference(reference runtimecontent.Reference) bool {
	return reference.SizeBytes > 0 && reference.SizeBytes <= 8<<20 && validOpaque(reference.Digest, 128) && validOpaque(reference.MediaType, 256)
}
func validConversationReference(reference runtimecontent.Reference) bool {
	return reference.MediaType == runtimecontent.ConversationEntryMediaTypeV1 && reference.SizeBytes > 0 && reference.SizeBytes <= 2<<20 && validOpaque(reference.Digest, 128)
}
func validAgent(id agentruntime.AgentID) error {
	_, err := agentruntime.ParseAgentID(id.String())
	return err
}
func validRevision(id agentruntime.AgentRevisionID) error {
	_, err := agentruntime.ParseAgentRevisionID(id.String())
	return err
}
func validSession(id agentruntime.SessionID) error {
	_, err := agentruntime.ParseSessionID(id.String())
	return err
}
func validInput(id agentruntime.InputID) error {
	_, err := agentruntime.ParseInputID(id.String())
	return err
}
func validTurn(id agentruntime.TurnID) error {
	_, err := agentruntime.ParseTurnID(id.String())
	return err
}
func validArtifact(id agentruntime.ArtifactID) error {
	_, err := agentruntime.ParseArtifactID(id.String())
	return err
}
func validOutcome(outcome InvocationState, result *runtimecontent.Reference, failure *agentruntime.Failure) bool {
	return (outcome == InvocationSucceeded && result != nil && failure == nil && validReference(*result)) || ((outcome == InvocationFailed || outcome == InvocationUncertain) && result == nil && failure != nil && validFailure(failure)) || (outcome == InvocationCancelled && result == nil && failure == nil)
}
func validTerminal(outcome TerminalOutcome) bool {
	if outcome.State != agentruntime.TurnSucceeded && outcome.State != agentruntime.TurnFailed && outcome.State != agentruntime.TurnCancelled {
		return false
	}
	if outcome.State == agentruntime.TurnSucceeded {
		return outcome.OperationID == "" && outcome.Ordinal == 0 && outcome.Fence == 0 && outcome.Failure == nil || (validOpaque(string(outcome.OperationID), 128) && outcome.Ordinal > 0 && outcome.Fence > 0 && outcome.Failure == nil)
	}
	return outcome.Failure == nil || validFailure(outcome.Failure)
}
func validFailure(failure *agentruntime.Failure) bool {
	return failure != nil && validOpaque(string(failure.Code), 64) && len(failure.Message) <= 1024 && len(failure.Details) <= 16
}
func outcomeDigestShape(command RecordInvocationOutcomeCommand) any {
	result := runtimecontent.Reference{}
	if command.Result != nil {
		result = *command.Result
	}
	return struct {
		Session, Turn, Operation                    string
		Ordinal, Fence, SessionVersion, TurnVersion uint64
		Outcome                                     InvocationState
		Result                                      runtimecontent.Reference
		Failure                                     *agentruntime.Failure
		Usage                                       *ModelUsage
	}{command.SessionID.String(), command.TurnID.String(), string(command.OperationID), command.Ordinal, command.Fence, command.ExpectedSessionVersion, command.ExpectedTurnVersion, command.Outcome, result, command.Failure, command.Usage}
}
func receiptExpired(receipt MutationReceipt, now time.Time) bool {
	return !receipt.RetentionUntil.IsZero() && !receipt.RetentionUntil.After(now)
}
