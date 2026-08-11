---
status: accepted
---

# Codec-enabled orchestration worker capability

## Context

M5 requires a private Temporal worker that uses the runtime payload codec.
The generic `orchestration` role deliberately has state and Temporal authority
but no blob credential, while the `codec` role has a UI inspection blob
credential but is not allowed to schedule runtime work. Combining either role
with runtime-content storage would collapse the content boundary established by
ADR 0011.

## Decision

`orchestration-codec` is a distinct private process role. It receives exactly:

- state metadata DSN (`STATE_DATABASE_DSN`) for compiler/planner/CAS and the
  publisher-authorized outbox;
- Temporal client credential (`TEMPORAL_AUTH_TOKEN`);
- a dedicated payload-object-store access/secret pair
  (`ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY` and
  `ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY`) restricted by operator policy to
  one `payload_blob_bucket` and `payload_blob_prefix`; and
- an explicit private task queue.

It does not receive a public bearer credential, model/tool credential, a
runtime-content bucket/prefix, or a runtime-content reader. The role config
rejects unapproved credential environment names and requires the exact two
payload credential names. The composition opens only the configured payload
bucket/prefix through the local Temporal codec and starts its client and worker
through the owned Temporal factory.

The scheduler enumerates state partitions, performs publisher-authorized
outbox reads, claims each record through compiler -> planner -> CAS, invokes
the private Temporal start/signal port, and acknowledges only after that call.
Expired leases are reclaimable, so delivery is at-least-once. A Session
workflow accepts only a command naming a durable outbox route; its activity
rechecks that route against state and treats a replayed sequence as a
deterministic no-op. A Temporal credential cannot manufacture a content read
or an arbitrary runtime command.

## Consequences

The operator must provision a separate S3/MinIO identity and policy such as
`s3:GetObject` and conditional `s3:PutObject` limited to
`temporal-payload/temporal-payload/*` in the dedicated payload bucket. It must
not grant `runtime-content/*`, list/write access to other buckets, or reuse
the API content identity. The current S3 adapter preserves immutable,
content-addressed writes; prefix restriction is an operator IAM capability,
not a client-side convention.

The public Go SDK and HTTP API remain Temporal-free. Temporal types occur only
in private runtime-orchestration and temporal-payload-runtime packages. The
generic `orchestration` and UI `codec` roles remain separately deployable.

## Rejected alternatives

- Give generic orchestration broad blob or runtime-content access.
- Reuse the UI codec service as a worker codec dependency.
- Store raw runtime content in Temporal payload blobs.
- Let a workflow signal itself authorize work without a durable outbox record.
- Use an in-memory blob store as the durable role fallback.
