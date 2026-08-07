# Agent Runtime — seams and invariants

Status: binding proposed test surface. This document turns the architecture
into small, deep Modules whose Interfaces are the only places callers and
tests cross. It is the seam agreement required before feature tests are
written.

The terms Module, Interface, Seam, Adapter, Depth, Leverage, and Locality have
the meanings in the repository’s engineering guide. In particular, tests prove
behavior through the same Interface used by callers; they do not query private
databases, Temporal histories, VM sockets, or package internals as a shortcut.

## Monorepo module map

```text
public Go SDK / public HTTP / examples
                 │
                 ▼
            runtime interface
                 │
      ┌──────────┼───────────────────┐
      ▼          ▼                   ▼
  agent kernel  tool + approval   event/artifact interface
      │          │                   │
      ▼          ▼                   ▼
Temporal adapter Model adapter       storage adapters
      │          │
      ▼          ▼
 temporalpayload sandbox-control client
                         │
                    sandbox control plane
                         │
                 Firecracker host agent

`temporalpayload`, sandbox core/control and the Go SDK are public packages in
the one root Go module. Their production implementations are still assembled
by one composition root, not reimplemented in each example.
```

| Module | Small Interface / seam | Adapters behind it | Public test client |
|---|---|---|---|
| Runtime client | HTTP/OpenAPI and `sdk/go` commands/events | API server; SDK transport | Real SDK and HTTP test client |
| Agent kernel | Deterministic command/state transition functions | Temporal orchestration adapter | Domain command/result fixture |
| Orchestration | Runtime-owned workflow gateway | Temporal production gateway; Temporal test environment | Runtime API; test-environment only for adapter suite |
| Model | Internal normalized `Turn` invocation/event sink | Codex; scripted model | Tool/kernel integration harness |
| Tool broker | Register/authorize/execute normalized tool calls | Builtin, sandbox, MCP | Broker command interface |
| Approval | Request, inspect, decide | API/Temporal persistence adapters | Public approval HTTP/SDK interface |
| Conversation/artifact/event/audit | Versioned store/publish/read interfaces | PostgreSQL authority, blob store and deterministic fakes; Workflow Streams only as an internal producer adapter | Store interface / public runtime client |
| Temporal payload | `DataConverter` and codec handler | Blob stores and HTTP serving adapter | Codec conformance harness |
| Sandbox client | Authenticated durable sandbox control client | Control-plane API transport | Public sandbox client |
| Sandbox control | Desired operation submission/status/reconciliation | Persistent control store; host routing | Control API/client, never a host-agent handle |
| Sandbox core | Normalization, grant evaluation, lifecycle/output semantics | Expert-only Firecracker/local/fake backend SPI | Public control/client conformance suite |
| Sandbox execution | Authenticated, fenced host-operation envelope | Firecracker; local unsafe; deterministic fake | Capability-driven black-box runner |
| Configuration/composition | Typed config -> role-specific application | Declarative Stack specification, local Tilt and production Kubernetes rendering | Startup/integration harness |
| Milestone reporting | Evidence-derived status record -> configured notifier | Deterministic fake, allowlisted transport fixture | Release-operations harness |

## Required public test seams

### S1 — Runtime SDK and HTTP contract

Tests create authenticated principals, call the public HTTP API or public Go
SDK, and observe only documented Session, Turn, Approval, Artifact and Event
models. This seam proves client-visible behavior, authorization, cursors,
idempotency and error contracts. It is used by all three examples.

Tests at S1 may inject a model/tool implementation only through an
operator/test configuration fixture. They may not reach into a workflow or
manipulate a database to make a Session appear complete.

### S2 — Agent kernel state transition interface

The kernel accepts fully normalized domain commands and prior state and returns
new state plus domain effects. It is deterministic under an injected Clock and
ID source. This deep Module owns Session/Turn transitions, admission ordering,
terminality, and effect intent; it does not call Temporal, storage, models or
sandboxes.

Kernel tests use literal worked examples and state-transition/property tables,
not mocks of private helper functions. The Temporal adapter has its own tests
that prove it faithfully carries kernel effects to durable operations.

### S3 — Runtime orchestration interface

The Temporal adapter implements the runtime’s durable command/query interface.
It is tested with Temporal’s test environment and replay histories via runtime
commands, public domain outcomes and explicit adapter diagnostic fixtures.
Normal application tests remain at S1; Temporal types and workflow IDs never
enter their assertions.

### S4 — Model adapter interface

The internal Model Interface accepts a normalized model request, reports
normalized events to a bounded sink, and produces a normalized response or
runtime Failure. A scripted adapter drives deterministic provider success,
delta, disconnect, retry and malformed-result cases. Only the model adapter
suite exercises Codex-specific protocol/auth semantics.

### S5 — Tool broker interface

The broker receives a Tool call plus immutable policy context and returns one
of denied, pending approval, authorized execution, or normalized result. Its
test Interface includes a recording audit sink and deterministic tool adapters,
because audit/event effects are part of its public contract. Tests do not call
a sandbox adapter directly to claim broker authorization worked.

### S6 — Human approval interface

The public runtime approval command (`inspect`, `approve`, `deny`) is the
seam. Tests prove the decision can be made exactly once by a permitted actor,
is durable through restart, and causes a previously pending broker operation to
advance only when still valid. Approval timeout advances the injected Clock.

### S7 — Conversation, artifact, event and audit interfaces

Each durable store has a small domain-owned Interface and an in-memory,
deterministic Adapter used for focused tests. PostgreSQL is the required v1
production authority for metadata/control/event records; object storage is the
immutable-content authority and Temporal is the orchestrator. Its production
adapter suite proves persistence semantics. Product event tests subscribe/read
at the public cursor interface, which is a PostgreSQL event-store cursor;
Workflow Stream offsets are never exposed. Audit tests query only an authorized
audit reader interface, not underlying tables.

### S8 — Temporal payload codec conformance

Tests input known Temporal payloads into the reusable DataConverter and the
remote codec handler, assert byte-level/golden behavior, and read from a
black-box BlobStore fixture. The runtime proves it installs this converter;
codec tests do not know runtime Session semantics.

### S9 — Sandbox durable control interface

The supported sandbox seam is a principal-bound client with durable operations:

```text
submit immutable operation → inspect/reconnect by opaque ID
                            → observe ordered operation/output records
                            → wait/result, signal/kill, close, or reconcile
```

This Interface is available after client, worker, control-plane and host-agent
restart. It is the seam for runtime integration and all sandbox conformance
tests. A live Go process/stream handle is never the recovery Interface.

The control plane sends an authenticated, versioned envelope to a durably
assigned host agent. The envelope binds tenant/principal, operation ID,
Effective-Spec digest, capability snapshot, expiry, lease/fencing token and
protocol version. Tests exercise refusal and stale-result behavior through the
same control interface; they do not call host-agent internals.

### S10 — Sandbox capability profile interface

Each capability is requested declaratively and returns a negotiated,
versioned capability snapshot bound to the accepted Effective Spec. The
conformance runner reads that snapshot and executes the corresponding
black-box profile. An Adapter that cannot enforce a profile refuses it; a test
does not branch on backend identity to waive behavior.

### S11 — Configuration and role startup

Tests start a named runtime role from a typed Config fixture, inspect only
health/readiness and authorized diagnostics, and assert required dependencies
and forbidden credentials. This is the seam for Tilt/Kubernetes composition
and prevents tests from creating an undocumented alternate architecture.

The typed, versioned Stack specification is rendered for local, CI and
production profiles at this seam. Tests inspect desired and rendered state,
ownership/lifecycle metadata and role RBAC. They prove that startup does not
create infrastructure and that a foreground OS-selected port-forward is only
connection state.

### S12 — Milestone status and notification

The release-operations harness accepts a weighted ledger-evidence snapshot,
creates a bounded redacted status record and submits it through a typed,
operator-configured notifier. It proves completion ordering, payload schema,
redaction and retained failure/retry behavior without sending user-controlled
URLs or querying a notifier’s private state.

## Explicitly rejected test seams

- Tests must not query Temporal workflow histories, internal task queues, run
  IDs, or activity types to prove application behavior.
- Tests must not inspect a database/blob bucket/control-store table as a proxy
  for a public command’s result. Those are only adapter-storage tests at S7/S9.
- Tests must not mock the private collaborators of the kernel, tool broker,
  redactor, or sandbox core merely to assert call order.
- Examples must not use direct Temporal, BlobStore, sandbox backend, internal
  package imports, seeded database data, or hidden test routes.
- A local unsafe sandbox test must not be cited as proof of Firecracker
  isolation, egress mediation, command-scoped secret isolation, or host mount
  safety.

## Cross-system invariants

Each invariant is a behavior to be tested at one or more seams, not merely a
comment in an implementation.

### Identity, tenancy, and time

| ID | Invariant | Primary seam |
|---|---|---|
| INV-ID-001 | Every externally visible runtime/sandbox object has an opaque typed ID; callers cannot derive topology, parse ownership, or treat an ID as authorization. | S1, S9 |
| INV-ID-002 | Every Session, Turn, Event, Artifact, Approval, Sandbox, Process, Operation, Volume and Snapshot is principal/tenant-scoped and cross-tenant access is denied without revealing existence. | S1, S7, S9 |
| INV-ID-003 | Mutation idempotency and sandbox Operation IDs are scoped to the authenticated principal and canonical immutable request; reuse with different input always conflicts. | S1, S9 |
| INV-ID-004 | Domain and control decisions use injected time; no test requires nondeterministic wall-clock waiting to prove expiry/retry/lease behavior. | S2, S6, S9 |

### Agent runtime lifecycle

| ID | Invariant | Primary seam |
|---|---|---|
| INV-RT-001 | A Session is pinned to exactly one Agent revision and has only documented state transitions. | S1, S2 |
| INV-RT-002 | One accepted Input corresponds to one ordered Turn; one Turn has exactly one terminal outcome. | S1, S2, S3 |
| INV-RT-003 | A new Input during active work enters the durable queue and cannot silently race/reorder the active Turn. | S1, S2, S3 |
| INV-RT-004 | Retrying a model invocation or activity never creates an extra Turn or re-accepts Input. | S2, S3, S4 |
| INV-RT-005 | Transport/client loss changes observation only, never durable work; explicit cancellation is a durable authorized command with cleanup tracking. | S1, S3 |
| INV-RT-006 | Public models/events/errors contain no Temporal/provider/sandbox-backend control types or identifiers. | S1, S4, S9 |
| INV-RT-007 | Workflows contain only bounded deterministic references/effects, never secret values, live interfaces, stream readers, raw command output or backend configuration. | S3 |

### Tool and approval lifecycle

| ID | Invariant | Primary seam |
|---|---|---|
| INV-TOL-001 | Model Tool call intent alone has no authority and cannot execute an Adapter. | S5 |
| INV-TOL-002 | Every execution has exactly one immutable policy decision, bounded grant, operation identity, audit chain and terminal normalized result. | S5, S7, S9 |
| INV-TOL-003 | A grant can only narrow pre-approved authority, has finite scope/uses/expiry, and is revoked on completion/cancel/timeout. | S5, S9, S10 |
| INV-TOL-004 | Pending approval pauses durable execution without making the Turn terminal; only the permitted approver can decide once while it remains valid. | S1, S5, S6 |
| INV-TOL-005 | Denial, expiry, cancellation, stale decision and policy invalidation can never execute the requested Tool. | S5, S6 |
| INV-TOL-006 | External effects may be uncertain after failure; runtime and sandbox reconcile their own operation but do not falsely claim external exactly-once behavior. | S5, S9 |

### Content, events, audit, and payloads

| ID | Invariant | Primary seam |
|---|---|---|
| INV-DAT-001 | Large content is immutable/blob-backed and referenced with digest/metadata; no large binary is placed in workflow history or public event body. | S1, S7, S8 |
| INV-DAT-002 | Conversation appends are expected-version/idempotent and never silently lose one writer. | S7 |
| INV-DAT-003 | Events are ordered per Session, at-least-once/deduplicable, cursor-resumable and explicitly signal expired retention or producer gaps. | S1, S7 |
| INV-DAT-004 | A source disconnect cannot silently omit or duplicate terminal model/tool/sandbox output: it is replayed, bounded with a gap, or finalized with an explicit outcome. | S4, S5, S7, S9 |
| INV-DAT-005 | Audit records are append-only, independent from transient logs, operation-deduplicated and distinguish attempted, authorized, committed, terminal and reconciled facts. | S5, S7, S9 |
| INV-DAT-006 | Runtime workers and Temporal UI use the same payload codec chain; inline, compressed and remote forms are mutually decodable subject to declared compatibility. | S3, S8 |
| INV-DAT-007 | Every safe/public data plane applies secret/content/unsafe-argv redaction and bounded metadata rules; private operator diagnostics are separately authorized. | S1, S4, S5, S7, S9 |
| INV-DAT-008 | PostgreSQL is the authoritative metadata, control, audit/outbox and product-event store; Temporal orchestrates and object storage holds immutable large content. No plane silently substitutes another authority. | S3, S7, S11 |
| INV-DAT-009 | A public Cursor denotes ordered PostgreSQL event-store position with documented replay, expiry and gap semantics. A Temporal Workflow Stream offset is never a public Cursor or retention authority. | S1, S7 |
| INV-DAT-010 | Every cross-store effect has a recorded atomic boundary or explicit durable outbox/reconciliation protocol. Process loss cannot turn an unknown effect into an unrecorded success. | S3, S5, S7, S9 |

### Declarative infrastructure and release operations

| ID | Invariant | Primary seam |
|---|---|---|
| INV-INF-001 | Every owned infrastructure resource and Secret reference is represented by reviewed typed desired state with owner, scope, dependencies, lifecycle and finite limits; runtime startup never creates or infers it. | S11 |
| INV-INF-002 | A single typed Stack specification deterministically renders local, CI and production profiles. Tilt and convenience tooling may apply it but cannot create an alternate topology. | S11 |
| INV-INF-003 | Reconciliation is an audited operator action. Render/check/diff reject drift, mutable image tags, implicit namespaces, undeclared ports/storage/defaults, ambient credentials and unsafe teardown ownership. | S11 |
| INV-OPS-001 | Milestone completion is first a retained evidence state, then an idempotent secret-safe notifier delivery. A failed delivery remains visibly failed/retryable and never becomes a false sent claim. | S12 |
| INV-OPS-002 | Every public status percentage is a labelled weighted-ledger estimate with completed, in-progress, blocked, uncertainty and next-checkpoint context; it is not a claim that blocked requirements passed. | S12 |

### Sandbox control and lifecycle

| ID | Invariant | Primary seam |
|---|---|---|
| INV-SBX-001 | A Sandbox/Process/Operation remains addressable and controllable by authorized ID after activity, worker or client restart; stale live handles are not relied on. | S9 |
| INV-SBX-002 | Accepted operations persist a tenant-scoped Effective Spec/request, state sequence, retention/tombstone and host routing before an ambiguous result can be reported. | S9 |
| INV-SBX-003 | Every mutable public input is canonicalized/deep-copied/frozen before authorization and backend dispatch; mutation after invocation cannot change authority or hash. | S9, S10 |
| INV-SBX-004 | Lifecycle convergence is durable: create/restore either returns/reconciles one resource or cleans up; Close/reaper eventually converges to documented terminal/tombstone state. | S9, S10 |
| INV-SBX-005 | Concurrent Close, snapshot, exec, wait, copy and process-control races have a state-table result; snapshot/close exclusive actions do not guess. | S9, S10 |
| INV-SBX-006 | Process execution has separated startup/lifetime/wait cancellation and a typed terminal reason; an unresolved side effect remains visibly uncertain. | S9, S10 |
| INV-SBX-007 | Core owns validation/lifecycle/grant/stream/error semantics; an Adapter receives only normalized internal requests and cannot be called by ordinary consumers. | S9, S10 |
| INV-SBX-008 | Adapter capabilities are versioned, negotiated, persisted with the Effective Spec and rechecked on use/restore; regression/unsupported behavior fails closed. | S9, S10 |
| INV-SBX-009 | The reaper owns durable cleanup after runtime/control/host failures and records cleanup-pending versus cleanup-confirmed; a `defer` is only best effort. | S9, S11 |
| INV-SBX-010 | Only a durably enrolled, mutually authenticated host with a current assignment may act on a versioned operation envelope. Revoked, wrong-tenant, expired, replayed, stale-fenced or incompatible requests and results fail closed. | S9, S10 |
| INV-SBX-011 | The control plane, core, host agent and Jailer each have explicit authority. A host cannot widen tenant, Effective Spec, capability, cgroup, network, image, mount, output or cleanup authority. | S9, S10, S11 |

### Sandbox authority and security

| ID | Invariant | Primary seam |
|---|---|---|
| INV-SEC-001 | Production foundation begins deny-all: no host mount, volume, secret, network, host environment/device/socket, root user, unbounded resource or mutable image authority without a named approved profile. | S9, S10 |
| INV-SEC-002 | Omitted sensitive command grant means none. Explicit inheritance is distinguishable, policy-approved and never broadens an Effective Spec. | S5, S9, S10 |
| INV-SEC-003 | The local adapter is mechanically unsafe/refusing for unprovable authority. It is unavailable as security evidence. | S9, S10 |
| INV-SEC-004 | The Firecracker profile has documented Linux/KVM boundary, jailed VMM/host agent, non-root guest, bounded control protocol and no ambient host credentials. | S10, K lane |
| INV-SEC-005 | Portable workspace transfer resolves paths below permitted roots, is bounded/checksummed/cancellable, and is the portable route before mount authority. | S9, S10 |
| INV-SEC-006 | Host mount, volume, snapshot, egress and command-secret authority each require its own capability declaration and passing conformance/security profile. | S10, K lane |
| INV-SEC-007 | SDK-known secret delivery is contextual, bounded, ephemeral and redacted; its taint provenance follows volumes and restricts snapshots. It makes no claim about arbitrary secret-derived bytes. | S9, S10 |
| INV-SEC-008 | High-value credential execution is outside an arbitrary writable guest process tree through a broker or verified trusted-exec capability; a helper pathname alone is not trust. | S5, S9, S10 |
| INV-SEC-009 | The only guest egress path is the documented mandatory proxy; policy asserts allowed proxy destination domain+port, blocks bypass/private metadata routes, and makes no DLP/TLS semantic claim. | S10, K lane |
| INV-SEC-010 | Sandbox enforcement limits and system admission quotas bound all declared hostile-resource paths; every breach yields an observable typed outcome. | S9, S10, K lane |

## Test-time rules

1. Each implementation ticket starts by naming its one or more seams from this
   document. A genuinely new seam requires an update/review of this file before
   tests are added.
2. Use a small pre-implementation behavior matrix for the vertical slice. It
   must include happy path, most dangerous negative path, retry/cancel or
   lifecycle path, and a known literal expected outcome where applicable.
3. Fakes are purpose-built Adapters at a real seam. They are never a mock of a
   private method or a shortcut to mutate hidden runtime state.
4. Time moves through injected fake clocks and deterministic schedulers. Polls
   have bounded logical deadlines and expose progress; sleep-based tests are
   rejected.
5. Linux/KVM profile evidence runs through the same public sandbox control
   Interface used by the runtime. Test-only host escape hatches are forbidden.
6. A test failing only because external credentials or a KVM host are absent is
   classified as blocked infrastructure, not rewritten to a weaker assertion.

## First test matrices to approve before implementation

These are the initial vertical slices; later tickets extend them rather than
starting with a horizontal inventory of imagined behavior.

| Slice | Seam | Initial behavior matrix |
|---|---|---|
| Session admission | S1/S2/S3 | create pinned Session; idempotent Input; second Input queues; restart retains order; explicit cancel settles once. |
| Event resume | S1/S7 | ordered events; duplicate replay accepted; cursor resume; cursor expired; producer loss returns explicit gap/final state. |
| Approval | S1/S5/S6 | pending request; authorized approval executes once; denial; fake-clock expiry; duplicate/late decision cannot execute. |
| Payload chain | S8 | inline remains inline; zstd wins; remote reference wins; corrupted remote payload is safe failure; UI handler decodes same data. |
| Sandbox operation ledger | S9 | submit create; same ID reconnects; different canonical request conflicts; control restart reconciles; cross-tenant lookup denied. |
| Sandbox exec recovery | S9/S10 | accepted/not-started retry; started/result retrieval; worker loss; kill/close; external effect marked uncertain. |
| Sandbox foundation | S9/S10 | deny-all default; non-root argv process; bounded output/termination reason; resource limit; local adapter rejects secure request. |
| Egress profile | S10 | allowed proxy destination; deny-all; direct-IP/metadata bypass blocked; proxy outage fails closed; capability regression rejected. |
| Workspace Agent | S1/S9 | write/copy workspace; process output to event/artifact; elevated operation asks approval; approve/deny; cleanup after cancellation. |
