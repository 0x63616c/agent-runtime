# M5 Temporal worker composition evidence

Status: accepted implementation seam (ADR 0015).

`orchestration-codec` is the only M5 role that owns a Temporal worker. It is
private to `internal/runtimeorchestration`; neither `sdk/go` nor the public API
imports Temporal. Its config includes a finite task queue and a dedicated
payload-codec object-store bucket/prefix. Runtime-content is absent by design.

The process constructs PostgreSQL runtime state, a payload-only MinIO/S3 blob
adapter, one `temporalpayload.Codec`, and the owned Temporal factory. It
starts the private Session workflow/activity set, then polls durable outbox
records. The flow is:

```
state outbox -> compiler/planner/CAS claim -> Temporal start/signal
             -> worker activity rechecks state route -> CAS acknowledgement
```

The persisted command contains tenant, outbox ID, Session ID, event sequence,
and closed route kind only. It contains neither public credentials nor content
bytes/keys. Session workflows record a `GetVersion` marker, accept duplicate
at-least-once routes as no-ops, and Continue-As-New after a bounded command
count while retaining only Session ID, the last durable sequence, and the
small in-chain command count.

`session.created` starts a chain. `input.accepted`, `turn.cancelled`,
`turn.succeeded`, `turn.failed`, `approval.resolved`,
`sandbox_operation.finalized`, `session.closing`, and `session.completed` are
rechecked signals; the final completed route ends the private workflow only
after its durable outbox record is accepted. Other safe outbox events are
acknowledged without inventing a new effect.

The M5 activity performs only this reversible state-route verification. Its
retry decision is deliberately closed and covered by
`TestDispatchStateCommandClassifiesRetrySafetyWithoutRepeatingUnknownEffects`:

| Condition | Activity outcome | Automatic retry |
| --- | --- | --- |
| Caller/workflow cancellation | Propagate cancellation unchanged. | No replacement activity. |
| Invalid, absent, or integrity-rejected durable route | Non-retryable `runtime.deterministic_outbox_route`. | No. |
| State backend unavailable | Preserve a storage-neutral transient error. | Yes, within Temporal's bounded policy. |
| Unknown external-effect result | Non-retryable `runtime.uncertain_external_effect`; reconciliation owns the next decision. | No. |
| Incompatible persisted policy | Non-retryable `runtime.incompatible_persisted_policy`. | No. |

The orchestration dispatcher has no model, tool, approval service, or sandbox
credential, so the latter two cases are classification guards rather than a
claim that it executes those effects. The separate `internal/runtimemodel`
worker owns only invocation-intent Outbox records: a new record calls its
provider-neutral adapter once, while an expired claim calls `Reconcile` with
the same operation ID and never blindly invokes again. The concrete
`HTTPAdapter` consumes only a bounded `application/x-ndjson` normalized stream:
ordered nonempty `delta` records followed by exactly one `completed` or safe
`failed` record. It rejects an oversized line/output, missing terminal record,
or post-terminal data. Its reconciliation request is a GET of the exact
operation ID, never a second POST. A successful stream is finalized as an
owner-readable immutable Artifact before the exact fenced outcome is recorded;
public Turn inspection then carries only that Artifact metadata and optional
provider-neutral usage, so a reconnecting caller uses the durable Artifact
route rather than a live provider connection. An uncertain outcome
records ordered `producer.gap` then `turn.failed` Events, making a missing
producer segment visible to public cursor replay. Provider-neutral model usage
retains optional input/output token counts, preserving unknown values as
unknown rather than zero. Unit tests prove bounded protocol parsing and the
fresh/recovered fence behavior. `TestDurableModelNormalizedStreamFinalizesOwnerReadableOutput`
runs the concrete HTTP adapter through disposable PostgreSQL/MinIO and then
reads its finalized output through StateRuntime. The local HTTP server is a
protocol fixture, not a supported production provider. No model role process
is yet composed with an approved provider or credential source. The
capability-bound `internal/runtimetool` worker reads an exact
state-authorized immutable sandbox-control descriptor before it can call its
adapter. A missing, corrupt, cancelled, or cross-scope descriptor never reaches
the adapter; an expired tool-worker claim calls `Reconcile` by that same
operation ID. Every terminal tool outcome creates a correlated
`sandbox_operation.finalized` product Event and durable outbox route. The
publisher sends that route only after a lease claim, and the state dispatcher
rechecks it before the private Workflow accepts it. The concrete sandbox
adapter strictly decodes the descriptor, requires the descriptor operation ID
to equal the durable operation ID, submits once, and uses `GetOperation` rather
than resubmitting during recovery. Its unit evidence uses the sandbox client
contract fake and an HTTPS sandbox control-handler composition; the latter uses
the handler's deterministic in-memory control ledger and is not production
durability evidence. The owned Temporal development-server test now captures
and replays the private Input → Approval → sandbox-finalization →
Session-complete route vocabulary. The
publisher test follows
the actual state transition from persisted tool intent through a principal
approval decision, then through a fenced `uncertain` model invocation caused
by producer loss and a terminal `turn.failed` outbox route. It verifies that
both routes are accepted only after their durable records are claimed and
published. The Temporal test environment separately retains an ordered Input
→ Approval → sandbox-finalization → Session-complete scenario as a checked-in
binary history corpus with its bounded payload blobs. The disposable
PostgreSQL/MinIO integration also loses the acknowledgement after Temporal
accepts one exact input route, recreates the publisher client, reclaims the
expired lease, and records `published` without a second state dispatch.
Sandbox finalization is still a safe vocabulary/worker-lifecycle test, not
external sandbox-execution evidence. M6/M7 consume these foundations later
but do not own their acceptance rows.

Required retained evidence:

- `go test ./internal/runtimeorchestration` covers state-derived route,
  forged-route refusal, acknowledgement/restart idempotence, workflow version,
  ordered dispatch, and Continue-As-New.
- `go test -tags=integration ./internal/runtimeorchestration` starts Temporal
  dev server through the owned factory. The durable role integration uses the
  PostgreSQL/MinIO harness and a separate payload bucket.
- `internal/runtimeorchestration/testdata/session-workflow-v1-history.json`
  is the checked-in historic v1 corpus. CI decodes its serialized Temporal
  history and bounded codec blobs, then replays it with the registered private
  workflow. A replay test is not a claim that a runtime-content object was
  available to the worker.
- `deploy/runtimeapi/run-durable-integration.sh` starts disposable PostgreSQL
  and MinIO, runs the migration/rollback-negative and state-store integration
  suite, then proves durable API restart, codec-worker outbox drain/restart,
  PostgreSQL-to-Temporal lost-ack/restart recovery, and historic replay against
  a Temporal development server.
