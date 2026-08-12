# Runtime HTTP API

[`api/openapi/openapi.yaml`](../../api/openapi/openapi.yaml) is the canonical
versioned public transport contract. Generated route constants used by the Go
SDK and HTTP adapter are checked against its ten operations by `just check`.
Neither surface exposes Temporal workflow IDs, task queues, payloads, database
positions, or backend configuration.

The implemented `/v1` routes create and read immutable Agent revisions, create
and inspect Sessions, idempotently send Input, inspect Turns, page Product
events after an opaque Cursor, explicitly cancel a Turn, and drain-close a
Session. Agent catalog operations require a tenant administrator. Sessions are
owned by the authenticated tenant and principal; absent and unauthorized
resources return the same safe `not_found` classification.

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
credential values. Its storage declaration must literally be
`{"mode":"memory-unsafe"}`. State is lost on process exit; this role is for
local transport integration until issue #24 supplies PostgreSQL authority.
`max_request_bytes` must be between 3 MiB and 16 MiB so every request allowed
by the canonical content limits remains transport-admissible; the example uses
4 MiB.
Plain HTTP is suitable only on loopback or behind an operator-owned protected
transport boundary.
