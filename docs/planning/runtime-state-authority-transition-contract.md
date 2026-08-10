# Runtime state-authority transition contract

Status: accepted M5 implementation contract under
[ADR-0011](../adr/0011-runtime-state-authority-and-content-boundary.md).
The complete initial command/query slice is now composed by the durable public
runtime. This document remains a contract and design explanation, not terminal
requirement-acceptance or production-rollout evidence.

## Scope and authority

`RuntimeStateStore` is one internal command/query interface. Its production
adapter is PostgreSQL. It owns bounded Agent revision metadata, Sessions,
Inputs, Turns and invocation attempts, ownership-scoped idempotency receipts,
Product-event sequence/Cursors, Audit facts, and Outbox records. Its methods
return domain records and safe runtime results, never rows, SQL errors, object
keys, Temporal identifiers, or storage configuration.

`runtimecontent` is the immutable-byte authority. A caller stages a canonical
identity-free Agent-specification body or Input envelope through an authorized
content capability before issuing a state command. The command carries a
typed, tenant-bound `ContentHandoff`, not a caller-forgeable reference:

```text
content writer → immutable conditional write/reference
               → RuntimeStateStore command transaction
               → metadata + Product events + Audit + Outbox
```

The handoff is created only after `runtimecontent` conditionally writes and
reads back the exact bytes, verifies the digest/size/media type, and binds the
result to its tenant and declared descriptor. The runtime application validates
that opaque capability immediately before submitting the command. The state
store receives a `ContentHandoffValidator` that verifies the capability's
tenant, reference, and descriptor commitment without reading bytes; the
capability is not persisted or exposed publicly. A failed command can leave an
unreferenced immutable object for declared content GC/reconciliation; it must
never be reported as a successful mutation. This is an at-least-once handoff,
not cross-store atomicity.

The deterministic kernel remains the S2 transition interpreter. It accepts a
normalized command and prior metadata state, decides legality and derived
effects, and returns a normalized mutation plan. It imports no PostgreSQL,
object-store, Temporal, HTTP, model, tool, sandbox, or telemetry dependency.
The store atomically persists a legal plan or returns safe conflict,
not-found-or-denied, unavailable, or integrity results. It does not recreate
domain decisions in a database adapter.

The sole digest authority is a canonical command engine: it owns command kind,
authenticated scope, idempotency key, and ordered metadata fields. The pure
planner consumes that canonical command, bounded prior state, and injected
clock/ID/retention policy and returns an exact transition plan. Adapters only
persist the plan; they do not allocate IDs, choose retention, advance fences,
or derive effects.

## Shared records

All records are bounded, UTC-normalized, deep-copied at their boundary, and
scoped by an authenticated `Tenant` plus a `Principal` where user-owned.

| Record | Required metadata | Prohibited data |
| --- | --- | --- |
| `AgentRevisionRecord` | tenant, Agent/Revision IDs, revision number, name, logical model profile, identity-free specification-body reference, created time, retention | instructions, Tool descriptions, credentials, provider types |
| `SessionRecord` | tenant/principal, Session ID, pinned Agent/Revision IDs, state, version, times, retention | Temporal execution/run ID, backend handles |
| `InputRecord` | tenant/principal/session, Input ID, idempotency receipt, content reference, accepted time | Input parts or raw text |
| `TurnRecord` | tenant/principal/session, Turn/Input IDs, position, state, persisted current fence, invocation count, safe terminal failure, times | model reasoning, provider error, raw output |
| `InvocationRecord` | tenant/principal/session/turn, runtime operation ID, ordinal, current fence, intent/outcome state, bounded usage references, times | provider credential, raw request/response |
| `ProductEventRecord` | tenant/principal/session, sequence, opaque Cursor, Event ID/kind, referenced IDs, occurred/retention times | event body, database position, Temporal offset |
| `AuditFactRecord` | tenant, audit/operation IDs, actor, fact kind, subject reference, time, retention | secret, raw content, unbounded diagnostics |
| `OutboxRecord` | tenant/principal plus exact Session/Turn/invocation/operation/ordinal/fence and Session/Turn version route; aggregate/version/event reference; commit/publication/reconciliation state; retention | arbitrary event payload or exactly-once claim |
| `MutationReceipt` | owner, runtime operation ID, command kind, canonical request digest, result references, accepted/retention times | raw request, authorization header, backend identifier |

An identity-free Agent-specification body contains the immutable name, logical
model profile, instructions, and Tool definitions but not allocated Agent or
Revision IDs. After idempotency is resolved, `RegisterAgentRevision` allocates
the IDs and binds the body descriptor to the stored metadata. The authorized
reader synthesizes the public Agent specification only after verifying that
body and metadata agree. `ContentReference` is a versioned media type, digest,
and finite size. Only `runtimecontent` can turn an authorized reference into
bytes.

## Commands

Commands contain normalized owned metadata and an authenticated actor/owner
context supplied by the application boundary. Every mutation has a canonical
request digest and idempotency receipt in its ownership scope: the tenant
catalog for Agent-revision administration, or tenant plus Principal for
Session-owned work. The command interface is closed: there is no generic
append-event, write-audit, or run-SQL operation.

| Command | Preconditions | Atomic store result and derived effects |
| --- | --- | --- |
| `RegisterAgentRevision` | tenant administrator; valid identity-free specification-body handoff | resolves idempotency before allocating IDs, then creates immutable metadata bound to the body descriptor or returns the prior result; emits revision audit/outbox fact |
| `CreateSession` | authorized tenant catalog revision; valid principal; exact revision metadata exists | creates one revision-pinned Session, initial `session.created` event, audit fact, and Outbox record |
| `AdmitInput` | Session is open; exact authorized Input handoff exists; caller owns Session | creates one Input and one ordered Turn; emits `input.accepted` and either `turn.started` or `turn.queued`, audit, and Outbox records |
| `BeginInvocationAttempt` | Turn is current/running; runtime operation ID is new or exact replay; expected Session/Turn version and current fence agree | records durable provider intent and a new ordinal without creating Input/Turn; emits safe invocation-intent event, audit, and Outbox work before dispatch |
| `RecordInvocationOutcome` | exact accepted runtime operation ID, ordinal, and current fence; safe bounded outcome reference | records exact replay or one outcome; emits safe outcome event, audit, and Outbox work; stale/cancelled fences conflict without changing Turn |
| `SettleTurn` | Turn is current/running; terminal result is valid, safe, and bound to the accepted invocation outcome or explicit non-model failure | records one terminal outcome, terminal event, audit/outbox fact, starts one queued Turn when present, and completes a drained closing Session |
| `CancelTurn` | caller owns Session/Turn; Turn is running or queued | records one cancelled outcome, derives cancellation/audit/outbox effects, then promotes work or completes a drained closing Session |
| `CloseSession` | caller owns an open Session | transitions to closing, emits `session.closing`, rejects future admission, and emits `session.completed` only after drain |

Idempotent replay precedes allocation of a new ID, sequence, Cursor, event,
audit fact, or Outbox record. Reusing a key with another command kind, owner,
or canonical digest returns conflict. A retained expired receipt returns its
documented safe expiration outcome rather than allocating new work. Worker
commands additionally carry a runtime-owned operation ID plus expected Session
and Turn versions and an invocation fence. Exact operation replay returns the
prior record; a changed digest, stale version, superseded fence, or post-cancel
result conflicts. Cancellation and settlement race once: the first committed
terminal transition wins, and the loser observes that immutable outcome.

The model dispatcher reads only committed invocation-intent Outbox work and
passes the runtime operation ID to an adapter as its external-effect key. A
recovery worker never blindly repeats an intent with unknown external effect:
it reconciles through an adapter that supports that key or records a safe
uncertain/finalized outcome and an explicit Product-event gap. It then uses
`RecordInvocationOutcome` and `SettleTurn` under the same fence. This makes
producer loss visible rather than an unrecorded success.

## Queries and operational reads

Queries are authorization-scoped and have no mutation side effect.

| Query | Result | Required behavior |
| --- | --- | --- |
| `GetAgentRevision` | immutable `AgentRevisionRecord` | tenant authorization; metadata reference only; bytes require a separate `runtimecontent` capability |
| `GetSessionView` | Session, active Turn, bounded queued Turns/count, recent safe events | principal-scoped non-enumerating absence; no backend IDs |
| `GetTurn` | immutable Turn snapshot | principal/session/turn ownership agrees |
| `ReadEvents` | bounded ordered page, next opaque Cursor, or explicit Gap | duplicate-tolerant replay; unknown/expired Cursor never silently skips; Temporal offsets are refused |
| `GetMutationReceipt` | safe idempotency status/result reference | exact owner/key only; retention expiry is explicit |
| `ReadAudit` | authorized bounded Audit page | audit authorization is separate from ordinary Session ownership |
| `ReadOutbox`, `ClaimOutbox`, `AcknowledgeOutbox` | ordered publication/reconciliation work | durable at-least-once claim/ack, ownership-scoped idempotency receipt, and enough exact route/fence/version metadata for recovery to form a fenced invocation outcome/settlement command; publisher failure cannot erase the committed fact |
| `AuthorizeAgentSpecificationBodyRead`, `AuthorizeInputEnvelopeRead` | runtimecontent reader authorization | state-scoped only; content composition does not authorize with raw tenant/principal input outside this authority |

The application expands metadata results into public `agentruntime` models
only through authorized content reads. A public `SendInputResult` may hydrate
the accepted Input from its immutable reference, but events and inspection
responses remain reference-only and bounded.

## Transition and invariant matrix

| Transition | Required invariant/effect | Requirement IDs |
| --- | --- | --- |
| initial Agent → immutable revision | new revision ID/number; equal replay returns prior; changed replay conflicts | DOM-001, API-004, API-010 |
| revision → Session | exact revision pin; no implicit migration | DOM-002, INV-RT-001 |
| open Session + Input → running/queued Turn | one Input/Turn; ordered position; one active Turn | DOM-004–006, INV-RT-002–004 |
| running Turn → durable invocation intent | new runtime operation/ordinal/fence within same Turn; intent event/audit/outbox precedes dispatch | DOM-007, DAT-004, DAT-006–007, DAT-012 |
| invocation intent → outcome/recovery | exact operation replay only; unknown external effect reconciles or becomes explicit uncertain/gap outcome | DOM-005, DOM-007, DAT-004, DAT-012 |
| running Turn → terminal | exactly one fenced outcome; cancellation/settlement loser observes prior; advance one queued Turn | DOM-005–006, API-008, DAT-012 |
| open → closing → completed | no new Input after closing; complete only after drain | DOM-003, API-008 |
| committed state mutation → declared effects | same transaction creates each command's required safe ordered event(s), append-only audit fact(s), and publication/reconciliation record(s) | DAT-003, DAT-006–007, DAT-011–012 |
| Cursor read after retention | explicit Gap/current-inspection path, never Temporal offset or silent loss | API-007, DAT-003–005, DAT-011 |
| cross-tenant/principal access | exact authorized scope or indistinguishable not-found/denied result | API-005, INV-ID-002–003 |
| content handoff failure | no command success without a tenant-bound verified handoff; later missing/tampered content has integrity/not-found-or-denied read result | DOM-004, DAT-001–002, INV-DAT-001, INV-DAT-010 |

`RegisterAgentRevision`, `CreateSession`, `AdmitInput`,
`BeginInvocationAttempt`, `RecordInvocationOutcome`, `SettleTurn`,
`CancelTurn`, `CloseSession`, `RegisterArtifact`, and `AppendConversation`
share the closed compiler/planner interface. The latter two retain only
immutable content references, receipts, audit facts and outbox work;
conversation appends additionally require the current durable version. Tool
and Approval commands must use the same interface rather than bypassing it
with direct tables or event writes. This remains not a claim that DOM-008–013,
HITL-001–006, DAT-001–002, or the complete DAT-003–013 release evidence is
implemented or satisfied.

## Migration without split authority

1. Define complete command/query, mutation-plan, and effect records in a new
   internal runtime-state package plus an adapter conformance suite. Do not
   expose them through public SDK or HTTP packages.
2. Split `runtimecontent` Agent specifications into an identity-free canonical
   body plus metadata-bound reader, then add canonical Input-envelope
   writer/read capability and tenant-bound verified `ContentHandoff` tests.
   Conditional write, read-back integrity, cancellation, tenant isolation, and
   descriptor mismatch are required before a state command accepts either.
3. M5 replaced the aggregate closure in the durable composition with the pure
   transition interpreter and complete deterministic `MemoryRuntimeStateStore`.
   The legacy kernel remains only as the explicit local `memory-unsafe` mode.
4. M5 implements `RuntimeStateStore` against the declared PostgreSQL
   migrations. Its transaction writes normalized metadata, events, Audit, and
   Outbox rows together; it never stores or fetches content bytes. Named real
   PostgreSQL tests and the durable API process exercise that path.
5. M5 adds state-outbox publication/recovery for the private Session workflow.
   Content GC/reconciliation, RLS/role grants, full retention/erasure, and a
   backup/PITR drill remain separate operator/release work.
6. The durable API and Temporal composition roots now use this authority.
   `memory-unsafe` remains available only as an explicitly labelled local
   configuration, never as a durable fallback.

No intermediate public configuration may send one route to PostgreSQL or read
Events from another authority. A PostgreSQL table, content object, or
adapter-level test is not public-command proof by itself.

### Contract implementation checkpoint

`internal/runtimestate` declares this complete initial lifecycle command/query
matrix and its metadata-only records. Its deterministic memory and PostgreSQL
adapters are wired through the M5 state runtime; boundary tests keep raw
Agent/Input content out of state records, require opaque
`runtimecontent.ContentHandoff` values at the two content-entry commands, and
require every listed lifecycle and Outbox operation to remain in the closed
interface.

### Implemented planner replacement split

The aggregate kernel cannot be adapted incrementally: it owns raw Agent/Input
bytes and exposes closure transactions, while the durable authority needs typed
canonical commands and metadata-only plans. M5 implemented the following
non-separable replacement:

1. One complete internal contract: ten typed
   canonical command inputs—`RegisterAgentRevision`, `CreateSession`,
   `AdmitInput`, `BeginInvocationAttempt`, `RecordInvocationOutcome`,
   `SettleTurn`, `CancelTurn`, `CloseSession`, `ClaimOutbox`, and
   `AcknowledgeOutbox`—plus the state-scoped
   `AuthorizeAgentSpecificationBodyRead` and `AuthorizeInputEnvelopeRead`
   content-reader authorizers. A compiler validates scope, authority,
   idempotency and bounded metadata, validates content handoffs into
   references, and is the only component that creates a `Mutation` receipt
   binding. No adapter may accept, construct, or use a generic `Mutation` in
   parallel with this compiler; it persists only compiler-produced plans.
2. One concrete pure lifecycle planner for all ten mutations. Its
   prior state includes Agent revision series, Session, ordered active/queued
   Turns, invocation/fence, receipt, cursor/sequence and Outbox lease state.
   Its plan contains every allocated ID, atomic session/turn/invocation write,
   promotion/terminal write, and ordered Product-event/Audit/Outbox effect.
   The plan is opaque or centrally validated before an adapter can persist it.
3. The durable composition replaces `kernel.Repository` with a complete deterministic
   MemoryRuntimeStateStore that supplies that prior state and persists only
   planner output. The same conformance suite then becomes the PostgreSQL
   adapter target. The explicit local `memory-unsafe` mode remains isolated
   from this durable composition.

This is deliberately not an adapter ABI. The M5 compiler and planner are in
`internal/runtimestate`: command
callers cannot supply a digest or receipt, content handoffs are validated
before a sealed command is produced, and adapters receive only a centrally
validated transition plan. Focused lifecycle/race tests exercise all ten
commands; durable API and Temporal worker integration are separately retained
evidence rather than a claim of broader model, tool, approval, or sandbox
execution.

## First executable vertical

M5 implements the `runtimecontent` identity-free Agent-specification body and
tenant-bound verified `ContentHandoff`, then uses the same capability for the
canonical Input envelope. Conditional immutable write, exact read-back,
descriptor binding, digest/size verification, cancellation fencing, tenant
isolation, and unreferenced-object reconciliation classification are exercised
at that boundary. The durable public `SendInput` now uses this handoff before
the complete `RuntimeStateStore` transition; this creates the mandatory
content-reference boundary without a second Session/Turn authority.
