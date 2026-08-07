# Agent Runtime system architecture

Status: accepted M0 architecture

This document, the master requirements, `CONTEXT.md`, and accepted ADRs are the
only binding implementation contract. The supplied external discussion draft
`outputs/agent-runtime-architecture.md` is **superseded** by this document and
the ADRs. It is historical input only; its optional PostgreSQL, shared external
codec module, later approval, optional active-input queue, and Workflow-Streams
event-authority proposals are not accepted architecture.

## System boundary

Agent Runtime is one public MIT monorepo and one root Go module. It ships the
runtime service, public HTTP contract and Go SDK, reusable Temporal payload and
blob package, sandbox library/control plane, declarative deployment assets,
documentation and three public-contract examples. No part moves to another
repository or relies on copied source to work.

```text
Applications and examples
        │ public HTTP / Go SDK
        ▼
Runtime API ───────► agent kernel ◄──── policy and approval
        │                  │
        │                  ├── Temporal orchestration
        │                  ├── model and tool adapters
        │                  ├── PostgreSQL authority
        │                  ├── immutable blob content
        │                  └── sandbox control plane ─► enrolled host agents
        ▼
product-event cursor and authorized inspection
```

Application callers never need Temporal identifiers, task queues, database
URLs, blob keys, sandbox backend types or provider credentials. Operators own
the explicit declarative deployment configuration for those dependencies.

## Domain and orchestration

An Agent specification is immutable and a Session remains pinned to one Agent
revision. A Session serializes Turns. Input admitted while a Turn is active
enters a durable ordered queue; it is neither rejected as a hidden default nor
allowed to race the active Turn. Each accepted Input has idempotency semantics,
and each Turn reaches exactly one terminal outcome.

Model invocation and Tool call are distinct from Tool execution. Policy creates
bounded Capability grants. Human Approval is first-release functionality: a
policy may durably pause a non-terminal Turn for an authorized approve, deny,
expiry or cancellation decision. Restart, replay and reconnect preserve the
pending decision exactly once.

Temporal is an internal durable orchestrator. A Session maps to a workflow
chain, effects map to activities, and history rollover preserves the public
Session and Product-event contract. Workflow state remains bounded and holds
stable references rather than raw content, secrets, handles or backend
configuration. The same local payload converter is installed by every owned
Temporal client and worker; the HTTP codec is a Temporal UI inspection adapter,
never a runtime decode dependency.

## Data, events and audit

PostgreSQL is required for v1 and is the authoritative store for runtime
tenancy/identity, idempotency, Session/Turn projections, conversation/artifact
indexes, public Product-event sequence and Cursor state, audit/outbox records,
and sandbox desired/actual operation ledgers. Its schemas, migrations,
transactions, retention, tenant erasure and backup/restore are declarative
operator concerns. Temporal persistence uses separately declared storage,
credentials and lifecycle.

Object storage is the immutable authority for large content. Artifact and
payload references carry stable identity, metadata and integrity information,
not storage URLs. No unbounded content belongs in PostgreSQL, workflow state,
audit records or public events.

The Product-event state machine is:

```text
producer intent → durable ordered runtime event → delivery/replay → terminal or explicit gap
```

A public Cursor is a runtime-owned PostgreSQL event-store cursor. Temporal
Workflow Streams may produce or transport internal observations but are never
the public event source of truth, cursor or retention contract. Audit records
are independently append-only; cross-store effects specify an atomic transaction
or a durable at-least-once outbox/reconciliation protocol.

## Sandbox control

The sandbox is a durable in-repo control plane, not an activity-local process
handle. Public callers use tenant-scoped opaque IDs and durable Operations to
submit, inspect, reconnect, observe output, wait, signal, close and reconcile.
The core freezes an immutable Effective specification before authorization and
dispatch.

Host agents enroll with durable identity and mutually authenticated control
transport. A host receives a versioned authenticated envelope binding
tenant/principal, Operation ID, Effective-Spec digest, Capability profile,
expiry, assignment and lease/fencing token. The control plane owns host
assignment, renewal, stale-result rejection, output sequence integrity, loss,
quarantine, reassignment and reconciliation. Control plane, core, host agent
and Jailer have non-overlapping authority for cgroups, network, image admission,
mounts, output limits and cleanup.

The `local-unsafe` adapter implements compatible refusal/recovery semantics for
development but never proves an isolation boundary. The production foundation
uses Firecracker on a separately verified Linux/KVM path. Additional authority
profiles—transfer, host mounts, volumes, snapshots, mediated egress and
command-scoped secrets—remain unavailable until their individual conformance
and security gates pass.

## Declarative infrastructure and release operations

Every owned Kubernetes object, Temporal declaration, database migration, object
storage resource/prefix, identity/RBAC/NetworkPolicy/Secret reference, port,
persistence policy, resource bound and telemetry resource is typed, versioned
desired state with explicit owner and lifecycle. One Stack specification renders
local, CI and production profiles. Tilt applies local rendered state; no runtime
binary, workflow or ad-hoc helper invents infrastructure, while a declared
migration job applies only a reviewed versioned schema change. Render/check/diff
rejects implicit or unsafe state; reconciliation is an audited operator action.

The planned canonical local-stack input is `tilt up -- --stack=<name>`. It is a
contract to implement and test, not a claim that the command works today. Any
later convenience wrapper must use the same Stack identity and desired state.

Milestone status is evidence-derived. A retained completion record precedes a
secret-safe notification to the typed operator-configured ntfy topic. It names
the milestone, estimated overall percentage, evidence summary, next milestone,
immutable revision, UTC time and status; notification failure stays visibly
failed/retryable. The corrected topic reachability test (`GCXy4IYjJp96`) is
operational evidence, not a completed milestone.

## Evidence boundaries

Local Tilt proves development composition and public-path behavior; it does not
prove Firecracker isolation. Linux/KVM evidence proves only the tested
Firecracker profile. Operator assertions, fake-adapter tests and planned work
are labelled separately. A release is complete only when every ledger row and
every milestone completion notification has retained evidence.
