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

The M5 activity performs only this reversible state-route verification. It
propagates cancellation, treats invalid or rejected durable routes as
non-retryable, and permits transient state-backend errors to retry under the
bounded Temporal policy. It does not call a model, tool, approval service, or
sandbox, so it cannot yet classify an unknown external effect or an
incompatible persisted policy. TMP-009 nevertheless remains M5 terminal work:
it requires an explicit retry decision table and proof for those cases before
this implementation seam can be accepted. TMP-010 likewise remains M5
terminal work for the approval and sandbox-operation scenarios; M6/M7 consume
those foundations later but do not own their acceptance rows.

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
