# Durable data lifecycle and retention classes

M5 treats retention as an authority decision for each durable data class, not
as one global TTL. `internal/runtimestate` accepts a `ClassRetentionPolicy`:
an operator can independently retain Agent revisions, Policies, Sessions,
Inputs, Turns, Artifacts, Conversation entries, authorization records,
invocation attempts, Product events, audit facts, outbox records, and
idempotency receipts. A legacy `RetentionPolicy` remains a fallback only; it
does not erase the class boundary.

| Data class | Planner class | Authority and classification | Retention/GC contract |
| --- | --- | --- | --- |
| Agent revisions and Policies | `agent_revision`, `policy` | Tenant configuration metadata; immutable revision/digest history. | Retained by their independent state classes. Revision removal is never an implicit Session migration. |
| Sessions, Inputs, Turns, Conversation, Artifacts | `session`, `input`, `turn`, `conversation`, `artifact` | Tenant/principal-scoped runtime metadata; content is an immutable reference, never a database body. | State metadata retains class-specific horizons. Authoritative tenant erasure composes state metadata removal with the exact referenced objects; it does not list-delete a bucket. |
| Tool intent, Approval, capability grant, tool execution | `authorization` | Authorization metadata; secret capability bytes are absent. | One independent authorization class. Grant expiry and maximum-use enforcement occur before an external effect. |
| Invocation attempts | `invocation` | Fenced provider-effect identity and safe outcome metadata. | Its own class; an uncertain result is retained as uncertain rather than retried as success. |
| Product events | `product_event` | Caller-safe ordered PostgreSQL cursor metadata. | Event replay retention is independent. An expired cursor returns an explicit gap/current-inspection path. |
| Audit facts | `audit` | Tenant-scoped append-only redacted facts. | Independent audit retention; it is not shortened because a related event or approval expires. External delivery is at-least-once through durable outbox/reconciliation, not claimed transactional fail-closed. |
| Outbox records | `outbox` | Durable publication/reconciliation lease metadata. | Independent outbox retention. A route delivered before its acknowledgement is lease-reclaimed and repeated at least once; the workflow deduplicates the durable sequence. |
| Idempotency receipts | `idempotency_receipt` | Canonical request equality and safe status metadata. | Independent receipt retention. Expiry produces safe conflict, never a hidden replay. |
| Temporal payload blobs | not a runtime-state class | Codec-owned immutable payload objects with no public cursor authority. | The payload `RetentionCoordinator` fences reference creation and conditional deletion; it retains a reconciliation record on ambiguity. |
| Sandbox operations, volume manifests, snapshots | not a runtime-state class | Sandbox-control authority, outside the runtime-state metadata package. | Their independent lifecycle contracts remain owned by the sandbox control ledger. M5 does not delete or reclassify them through a generic runtime sweep. |

The state planner assigns every record and effect its class-specific retention
horizon atomically with the transition. The class-selection test proves that
event, audit, outbox, and receipt horizons diverge from the Agent/Session/Input
records they accompany. The PostgreSQL lifecycle authority also executes an
operator-authorized physical collection for expired, unpinned Agent/Input,
Artifact, and Conversation metadata: it holds a tenant advisory lock, removes
only exact objects absent from the surviving metadata set, and leaves metadata
intact if content deletion fails. The disposable PostgreSQL/MinIO harness
proves both its non-enumerating authorization refusal and successful exact
collection. The same real PostgreSQL/MinIO test proves that the isolated
operator capability deletes an expired unreferenced Artifact object only after
the state authority accepts the exact tenant/action request; a denial leaves
both the object and metadata intact, while the Session and Input remain.
Other physical collectors remain separately operator-owned and must leave an
explicit reconciliation outcome rather than guessing.
