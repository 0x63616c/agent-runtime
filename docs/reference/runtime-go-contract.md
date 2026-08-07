# Runtime Go contract and deterministic kernel

The public Go contract is package
`github.com/0x63616c/agent-runtime/sdk/go` (package name `agentruntime`). It is
part of the repository's one root module and has no Temporal, PostgreSQL,
provider, sandbox-backend, blob-client, or telemetry dependency in its
transitive import graph.

## Implemented contract

The package currently defines:

- opaque typed Agent, Agent revision, Session, Input, Turn, Product-event,
  Cursor, Artifact identifiers with strict parsing, JSON validation, and safe
  redaction;
- immutable Agent revision and revision-pinned Session snapshots;
- bounded text and Artifact-reference Input parts;
- explicit Session (`open`, `closing`, `completed`, `cancelled`, `failed`) and
  Turn (`queued`, `running`, `succeeded`, `failed`, `cancelled`) states;
- stable safe Failure codes and an `errors.As`-compatible public Error;
- ordered bounded Product events, opaque replay cursors, and explicit Gap
  results requiring Session inspection;
- requests for Agent creation/revision, Session creation, idempotent Input,
  explicit Turn cancellation, and draining Session close; and
- the small `Client` interface that future HTTP transport code must implement.

The deterministic internal kernel implements the first S2 transition slice
through an atomic, context-aware repository port. It creates immutable Agent
revisions, pins Sessions, compares canonical mutation content for idempotency,
serializes concurrent Input into one active Turn plus an ordered queue, records
one terminal outcome, advances queued work, cancels explicitly, drains closing
Sessions, and reads cursor-addressed events. Its in-memory repository is a
deterministic test/composition adapter. It is not process-restart durability
evidence and is not a production state authority.

## Safety and observation semantics

Input content is deep-copied on admission and when returned. Product events
contain only typed runtime references and bounded state vocabulary; they do
not contain raw Input content, provider errors, Temporal workflow identifiers,
database positions, or backend configuration. A caller disconnect or cancelled
read context does not become a durable cancellation command. `CancelTurn` is
an explicit idempotent mutation.

Repository transactions isolate each ownership scope and recheck context
cancellation before commit. A guessed ID in another ownership scope produces
the same safe not-found result as an absent ID. Public Cursor values are opaque;
when retention removes a requested position, event replay returns a Gap rather
than silently skipping records.

## Deliberately not claimed

This slice does not provide an HTTP server/client implementation, OpenAPI
description, authentication transport, PostgreSQL adapter, outbox, live event
stream, Temporal workflow, model invocation, tool/approval execution,
Artifact download, admin policy surface, or a runnable example. Those remain
required by issues #23–#25 and their acceptance-ledger rows. No M5 requirement
is promoted by this partial slice.
