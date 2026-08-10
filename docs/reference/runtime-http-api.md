# Runtime HTTP API

[`api/openapi/openapi.yaml`](../../api/openapi/openapi.yaml) is the canonical
versioned public transport contract. Generated route constants used by the Go
SDK and HTTP adapter are checked against its twelve operations by `just check`.
Neither surface exposes Temporal workflow IDs, task queues, payloads, database
positions, or backend configuration.

The implemented `/v1` routes create and read immutable Agent revisions, create
and inspect Sessions, idempotently send Input, inspect Turns, page Product
events after an opaque Cursor, explicitly cancel a Turn, and drain-close a
Session, and download caller-authorized immutable Artifacts. Agent catalog operations require a tenant administrator. Sessions are
owned by the authenticated tenant and principal; absent and unauthorized
resources return the same safe `not_found` classification.

`GET /v1/idempotency` requires an `Idempotency-Key` header and returns only the
caller-scoped retained receipt status. It never replays a command or exposes
the canonical request body.

Every `/v1` request is authenticated with a bearer credential and correlated by a
typed `X-Request-ID`. Mutations require `Idempotency-Key`. Request and response
JSON is strict and size-bounded. Cursor pagination is the current reconnect
mechanism: connection loss affects the read only, and the caller resumes after
the last accepted Cursor.

`GET /healthz` and `GET /readyz` are deliberately unauthenticated, contain only
the role and readiness state, and expose no runtime resource data.

## Standalone local role

```sh
export AGENT_RUNTIME_ADMIN_TOKEN='replace-with-at-least-16-bytes'
export AGENT_RUNTIME_DEVELOPER_TOKEN='replace-with-at-least-16-bytes'
go run ./cmd/agent-runtime-api --config "$PWD/deploy/runtimeapi/api.example.json"
```

The checked-in example names credential environment sources but contains no
credential values. It deliberately uses `{"mode":"memory-unsafe"}`, so state
is lost on process exit and it is suitable only for local transport work. A
durable operator configuration instead selects `postgres` and explicitly names
the PostgreSQL DSN and immutable-content endpoint, bucket, and credential
environment keys; the integration harness exercises that process path against
PostgreSQL and MinIO.
`max_request_bytes` must be between 3 MiB and 16 MiB so every request allowed
by the canonical content limits remains transport-admissible; the example uses
4 MiB.
Plain HTTP is suitable only on loopback or behind an operator-owned protected
transport boundary.

## Optional request-completion logs

The standalone role emits no public `/v1` API completion record by default. To
opt into one JSON `slog` record per public API completion, add this strict
configuration block and inject the named environment value at process start:

```json
"observability": {
  "identity_correlation_key_environment": "AGENT_RUNTIME_OBSERVABILITY_KEY"
}
```

The key is an explicit secret of 32 to 4096 bytes. Each record contains only a
canonical operation name, request ID, HTTP status, safe outcome/failure code,
duration, and keyed HMAC tenant/principal correlations. It never contains the
key, bearer token, idempotency key, request body, raw identity, raw URL, or
backend identifier. This is a bounded process-log seam only: it is not an OTel
exporter, dashboard, durable audit record, or cross-service correlation proof.
Unauthenticated `/healthz` and `/readyz` probes intentionally remain outside
this request-observation stream.
