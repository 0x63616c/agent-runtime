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
`session.closing`, and `session.completed` are rechecked signals; the final
completed route ends the private workflow only after its durable outbox record
is accepted. Other safe outbox events are acknowledged without inventing a
new effect.

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

The current dispatcher has no model, tool, approval service, or sandbox
credential, so the latter two cases are classification guards rather than a
claim that the dispatcher executes those effects. Approval resolution now
produces a safe `approval.resolved` event/outbox route; terminal operation
routes include `turn.succeeded`, `turn.failed`, and the safe
`sandbox_operation.finalized` vocabulary. The Temporal test environment
retains an ordered Input → Approval → sandbox-finalization → Session-complete
scenario. TMP-010 still needs its full durable-state and retained-history
evidence bundle; M6/M7 consume these foundations later but do not own their
acceptance rows.

Required retained evidence:

- `go test ./internal/runtimeorchestration` covers state-derived route,
  forged-route refusal, acknowledgement/restart idempotence, workflow version,
  ordered dispatch, and Continue-As-New.
- `go test -tags=integration ./internal/runtimeorchestration` starts Temporal
  dev server through the owned factory. The durable role integration uses the
  PostgreSQL/MinIO harness and a separate payload bucket.
- replay evidence must replay captured Session history using the registered
  private workflow before promotion. A replay test is not a claim that a
  runtime-content object was available to the worker.
- `deploy/runtimeapi/run-durable-integration.sh` starts disposable PostgreSQL
  and MinIO, runs the migration/rollback-negative and state-store integration
  suite, then proves durable API restart plus codec-worker outbox drain/restart
  against a Temporal development server.
