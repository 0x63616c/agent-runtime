---
status: accepted
---

# Runtime state authority and immutable content boundary

One internal S1/S7 runtime state store is the authority for Agent revision
metadata, Sessions, Turns, mutation idempotency, Product events and Cursors,
Audit records, and Outbox records. Its command and query operations return
runtime-owned models, not database rows. PostgreSQL is that store's required
v1 implementation. `runtimecontent` is the separate immutable-content
authority: it stores and reads bounded Agent specification and Input bytes by
authorized capability, while the runtime state store retains only their
integrity-checked references and bounded metadata.

The public HTTP API, Go SDK, and private Temporal adapter use the same runtime
state command/query boundary. They do not receive a Temporal identifier,
database row, object key, or storage configuration. The state store records
the atomic metadata/event/audit/outbox portion of an effect; storing an
immutable object before that transaction is an explicitly reconciled
at-least-once boundary, not a claim of cross-store atomicity.

## Considered options

- Keep `kernel.Repository` as a closure over an opaque `TenantState` and add a
  PostgreSQL implementation later.
- Wire `runtimeadmission.PostgresRepository` into only `SendInput` while the
  rest of the public API continues to use the in-memory kernel.
- Persist a serialized kernel aggregate in PostgreSQL as a durable snapshot.

## Consequences

`TenantState` currently contains raw Agent specification and Input content, so
a durable closure repository or serialized aggregate would put content in the
metadata authority and violate the declared data boundary. It also cannot be
implemented in a separate PostgreSQL adapter without exposing kernel internals
or importing database dependencies into the deterministic kernel.

The legacy PostgreSQL admission seam remains a foundation only and is not used
by the M5 API composition. The composed `RuntimeStateStore` owns the complete
initial public command/query slice: Agent metadata, Sessions, Inputs, Turns,
events, audit, receipts, and outbox. The standalone `memory-unsafe` mode
remains explicitly local-only; it is not a durable fallback.

The implementation replaces the closure repository with typed internal
commands and queries that preserve the kernel's domain-transition rules while
allowing PostgreSQL to atomically persist the normalized projections, ordered
events, audit facts, and outbox records. Immutable content is written and read
only through `runtimecontent` authorization capabilities; an unreferenced
immutable object is a reconciliation/GC concern, never a successful public
mutation. The resulting production adapter also requires declared
least-privilege PostgreSQL roles and tenant isolation before public use.
