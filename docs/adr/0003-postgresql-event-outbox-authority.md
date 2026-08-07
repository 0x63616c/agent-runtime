---
status: accepted
---

# PostgreSQL, product-event and outbox authority

PostgreSQL is required for v1 and is the authoritative store for runtime
metadata/control state, tenancy, idempotency, Session/Turn projections,
conversation/artifact indexes, product-event sequence/cursors, audit/outbox
records and sandbox operation ledgers. Temporal durably orchestrates work;
object storage holds immutable large content. Temporal persistence is a
separately declared deployment with separate credentials, schema/database and
retention.

## Considered options

- Make PostgreSQL optional or delegate public event authority to Temporal.
- Use Temporal Workflow Streams as public event cursor and retention authority.

## Consequences

Product events use the state machine `producer intent -> durable ordered runtime
event -> delivery/replay -> terminal or explicit gap`. A public Cursor is a
PostgreSQL event-store cursor. Cross-store effects record either an atomic
transaction boundary or a durable at-least-once outbox/reconciliation protocol;
they never claim stronger semantics.
