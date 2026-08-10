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
