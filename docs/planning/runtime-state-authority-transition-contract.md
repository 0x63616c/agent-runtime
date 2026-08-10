# Runtime state-authority transition contract

Status: accepted implementation design under
[ADR-0011](../adr/0011-runtime-state-authority-and-content-boundary.md).
This document specifies the internal S2/S7 contract required before a
PostgreSQL-backed public runtime can replace the explicitly labelled
`memory-unsafe` composition. It is a design, not implementation or acceptance
evidence.

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

## Shared records

All records are bounded, UTC-normalized, deep-copied at their boundary, and
scoped by an authenticated `Tenant` plus a `Principal` where user-owned.

| Record | Required metadata | Prohibited data |
| --- | --- | --- |
| `AgentRevisionRecord` | tenant, Agent/Revision IDs, revision number, name, logical model profile, identity-free specification-body reference, created time, retention | instructions, Tool descriptions, credentials, provider types |
| `SessionRecord` | tenant/principal, Session ID, pinned Agent/Revision IDs, state, version, times, retention | Temporal execution/run ID, backend handles |
| `InputRecord` | tenant/principal/session, Input ID, idempotency receipt, content reference, accepted time | Input parts or raw text |
| `TurnRecord` | tenant/principal/session, Turn/Input IDs, position, state, invocation count, safe terminal failure, times | model reasoning, provider error, raw output |
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
`CancelTurn`, and `CloseSession` are the first complete Agent/Session/Turn
lifecycle command set. Conversation, Artifact, Tool, and Approval commands
must extend the same closed interface; they may not bypass it with direct
tables or event writes. This first set is not a claim that DOM-008–013,
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
3. Replace `kernel.Repository` aggregate closures in one migration with the
   pure transition interpreter plus complete deterministic
   `MemoryRuntimeStateStore`. All listed commands and queries move together;
   delete the legacy aggregate rather than retaining a fallback.
4. Implement `PostgresRuntimeStateStore` against that full contract and the
   declared migrations. Its transaction writes normalized metadata, events,
   Audit, and Outbox rows together; it never stores or fetches content bytes.
   Run shared adapter conformance plus named real PostgreSQL tests.
5. Add content-GC/reconciliation, Outbox publisher/recovery, RLS/role grants,
   retention/erasure, migration, and backup/restore evidence before accepting
   durable public process configuration.
6. Switch API and Temporal composition roots together. Remove `memory-unsafe`
   only after every public command/query route uses this authority and
   real-path evidence is retained.

No intermediate public configuration may send one route to PostgreSQL or read
Events from another authority. A PostgreSQL table, content object, or
adapter-level test is not public-command proof by itself.

### Contract implementation checkpoint

`internal/runtimestate` declares this complete initial lifecycle command/query
matrix and its metadata-only records. It intentionally supplies no memory or
PostgreSQL adapter and is not wired to a public route. Its boundary tests keep
raw Agent/Input content out of runtime-state records, require the opaque
`runtimecontent.ContentHandoff` at the two current content-entry commands, and
require every listed lifecycle and Outbox operation to remain in the closed
interface. The next migration step is a complete deterministic memory
conformance implementation, not an incremental route migration.

## First executable vertical

Implement the `runtimecontent` identity-free Agent-specification body and
tenant-bound verified `ContentHandoff` first, then use that same capability for
the canonical Input envelope. This is production-aligned and testable without
PostgreSQL: conditional immutable write, exact read-back, descriptor binding,
digest/size verification, cancellation fencing, tenant isolation, and
unreferenced-object reconciliation classification. It remains internal and
unused by public `SendInput` until the complete `RuntimeStateStore` migration
can switch the lifecycle together. This creates the mandatory content-reference
handoff without a second Session/Turn authority.
