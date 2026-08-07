# Agent Runtime

This is the ubiquitous language for the Agent Runtime domain. It defines
product concepts only; implementation technologies, transports and deployment
details belong in the accepted architecture and ADRs.

## Agent and conversation

**Agent specification**:
An immutable, versioned definition of an agent’s intended behavior, model
profile, available tools and governing policy.
_Avoid_: Agent configuration, agent template

**Agent revision**:
The exact version of an Agent specification to which a Session is pinned.
_Avoid_: Mutable agent, live agent configuration

**Session**:
A durable interaction with one Agent revision that contains an ordered sequence
of Inputs and Turns.
_Avoid_: Conversation when the whole application interaction is meant

**Input**:
A caller’s idempotently submitted request to advance a Session.
_Avoid_: Message when the idempotency or admission semantics matter

**Turn**:
One durable progression from an accepted Input to exactly one terminal outcome.
_Avoid_: Request, chat completion

**Model invocation**:
One observable attempt to obtain a model’s contribution to a Turn.
_Avoid_: Turn attempt

**Conversation**:
The versioned semantic context used to construct model work for a Session.
_Avoid_: Transcript when referring to raw chronological observations

**Artifact**:
A durable content item consumed or produced by a Session and identified by
stable metadata and integrity information.
_Avoid_: File when authorization and lifecycle matter

## Tools and authority

**Tool definition**:
The stable name, description and input contract of an action that an Agent may
request.
_Avoid_: Tool execution

**Tool call**:
Model intent to use a Tool definition. A Tool call grants no authority and does
not imply execution.
_Avoid_: Tool execution, authorized action

**Tool execution**:
An authorized, recorded attempt to satisfy one Tool call.
_Avoid_: Tool call

**Policy**:
A versioned rule set that decides whether proposed authority is allowed,
denied, or requires Approval.
_Avoid_: Capability grant

**Capability grant**:
A bounded authorization issued from Policy for a specific allowed action.
_Avoid_: Credential, permission in the abstract

**Capability profile**:
A versioned declaration of authority and guarantees that an execution adapter
can enforce.
_Avoid_: Boolean capability flags

**Approval**:
An authorized human decision on a pending proposed action within its declared
scope and validity period.
_Avoid_: Permission when referring to the Policy rule or Capability grant

## Sandbox

**Sandbox**:
An isolated execution resource controlled through the runtime’s durable
operation model. Its lifetime is defined by the requesting product or policy;
only Workspace Agent requires a session-scoped workspace sandbox.
_Avoid_: Process, virtual machine

**Process**:
One command execution within a Sandbox, with its own lifecycle, output and
terminal result.
_Avoid_: Sandbox

**Operation**:
An idempotent, durable request to mutate or control a Sandbox resource.
_Avoid_: Handle, transient command

**Effective specification**:
The immutable, fully resolved Sandbox request accepted for an Operation.
_Avoid_: Caller options after submission

**Host assignment**:
The current fenced authority to carry an Operation on a particular execution
host.
_Avoid_: Permanent host ownership

## Observation and records

**Product event**:
A bounded, caller-safe, ordered observation of Session progress.
_Avoid_: Command, audit record, transport frame

**Cursor**:
An opaque position from which a caller resumes Product-event observation.
_Avoid_: Offset when exposing an implementation transport position

**Gap**:
An explicit Product-event outcome saying that a bounded portion cannot be
replayed and that the caller must inspect current state.
_Avoid_: Silent loss

**Audit record**:
An append-only security record of an actor, decision, authority use or
administrative action.
_Avoid_: Application log

**Outbox record**:
A durable record that coordinates a committed domain effect with later
publication or reconciliation.
_Avoid_: Guaranteed exactly-once delivery

**Status estimate**:
A labelled, evidence-derived estimate of overall project completion; it is not
a claim that every blocked or unverified requirement passed.
_Avoid_: Completion proof
