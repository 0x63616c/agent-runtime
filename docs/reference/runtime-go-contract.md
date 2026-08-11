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
  Turn (`queued`, `running`, `waiting_for_approval`, `succeeded`, `failed`,
  `cancelled`) states; `waiting_for_approval` is non-terminal and cancellable;
- stable safe Failure codes and an `errors.As`-compatible public Error;
- optional provider-neutral token usage on an inspected Turn; a missing token
  value remains unknown rather than becoming zero, and provider diagnostics are
  never public data;
- bounded owner-scoped Tool-call inspection projections: model intent name and
  lifecycle, Approval (including opaque Tool-call linkage), grant use
  counters/expiry, and safe execution failure;
  an Approval admitted through the broker additionally exposes only its fixed
  action verb/target and maximum-use bound, never raw arguments or capability
  material;
  action descriptors, policy/capability digests, grant identities, backend
  handles, raw results, and credentials are never exposed;
- ordered bounded Product events, opaque replay cursors, and explicit Gap
  results requiring Session inspection;
- requests for Agent creation/revision, Session creation, idempotent Input,
  explicit Turn cancellation, and draining Session close; the concrete HTTP
  Client additionally cancels a drained Session; and
- the narrow `RuntimeClient` interface and its strict concrete HTTP `Client`.

The additive `ArtifactStreamer` capability exposes a closable
`Client.OpenArtifact` stream without widening `RuntimeClient`. It carries the
authorized immutable Artifact metadata, reads without buffering the complete
body, and verifies the declared byte count and HTTP `Digest` trailer at EOF.
Closing before EOF cancels only the transfer observation.

The additive `SessionCanceller` capability exposes `Client.CancelSession` for
caller-owned cancellation after all accepted Turns have reached a terminal
state. It does not widen `RuntimeClient`, so existing v1 implementations keep
their source compatibility. Runtime-owned Session failure is not a caller API:
it is visible only as the safe `failed` Session state and `session.failed`
Product event.

The deterministic internal kernel implements the first S2 transition slice
through an atomic, context-aware repository port. It creates immutable Agent
revisions, pins Sessions, compares canonical mutation content for idempotency,
serializes concurrent Input into one active Turn plus an ordered queue, records
one terminal outcome, advances queued work, cancels explicitly, drains closing
Sessions, terminally cancels a drained caller Session, and reads
cursor-addressed events. Its in-memory repository is a
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

The HTTP client requires an explicit HTTP implementation, credential source,
request-ID source, finite response bound, and HTTPS origin (loopback HTTP is
allowed for local development). It performs no hidden retries and rejects
unknown or trailing JSON, oversized responses, unsafe failure envelopes, and
mismatched request IDs.

The explicitly labelled `memory-unsafe` configuration remains available for
local transport work only. The durable configuration composes PostgreSQL state
with immutable runtime content, and the private `orchestration-codec` role
drains its state-owned outbox into Session workflows without exposing Temporal
to callers. Live push streaming and model/tool/approval execution remain later
milestones. Artifact transfer has a bounded authorized HTTP/SDK and
PostgreSQL/MinIO integration path, but lifecycle/retention and production
rollout evidence are separate M5 requirements. M5 implementation evidence does
not by itself promote a requirement ledger row or production rollout.
