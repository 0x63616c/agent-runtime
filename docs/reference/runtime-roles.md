# Runtime roles reference

`runtime` is one versioned binary with a trust-scoped composition mode:

```text
runtime serve --config <operator-role.json> --role <declared-role> [--check]
```

The configuration is operator-owned, strict JSON. It contains a schema
version, one role, an explicit non-default namespace, health bind address, and
the exact non-secret endpoints plus Secret environment-key references required
by that role. Unknown fields are rejected. It does not accept application
concepts such as Agents, Sessions, Inputs, Policies, or Tools.

`--role` must equal the role in the document. `all` is intentionally not a
valid deployable role: the runtime must be composed as separate processes so
that one process cannot read another process's credentials. This is true even
when local development would find a convenience all-in-one process useful.

The configuration schema is version `1`. `--check` runs startup validation and
credential-presence validation but does not listen or mutate infrastructure.
Without `--check`, ordinary roles expose `GET /healthz` and `GET /readyz`;
their response contains only `role`, `namespace`, and `status`.
`orchestration-codec` additionally starts the private state/outbox-derived
Temporal Session worker from its explicit task queue and dedicated payload
bucket/prefix. It receives no public API or runtime-content credential.

An `orchestration-codec` worker may additionally declare an `audit_sink` with
an explicit `https` endpoint and a `timeout_seconds` value from 1 through 60.
It delivers only an already-committed, bounded audit fact through the durable
outbox. The field contains no credential and cannot make the state transition
fail closed: a sink outage leaves the route lease-reclaimable for at-least-once
delivery. Omitting the field leaves external audit export disabled; no current
reference Stack declares a production sink.

`egress-proxy` is a separately deployed infrastructure process, not a runtime
role. It takes an explicit bind address and one or more exact
`--allowed-target host:port` values. `--check` validates its finite inventory
without opening a listener. It handles ordinary HTTP forwarding and HTTPS
CONNECT only after it has checked the target. The model role is configured to
use this proxy rather than receiving a broad outbound network exception.

See [the self-hosted deployment contract](../operations/self-hosted-deployment.md)
for deployment ownership, secret matrix, Temporal responsibilities, and the
honest scope of this early implementation.
