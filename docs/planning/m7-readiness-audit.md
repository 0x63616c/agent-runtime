# M7 readiness audit

This audit records the M7 implementation boundary at the start of the
milestone. It is not completion evidence.

## Code-owned baseline

The runtime-state authority already retains Tool intents, pending and terminal
Approvals, bounded grants, Tool-execution intents/results, audit facts, and
outbox records. `runtimetool.Worker` reads a state-authorized immutable action
descriptor only after a grant is consumed, and can reconcile a reclaimed
operation without submitting it again. The public HTTP/Go SDK contract exposes
owner-scoped Tool lifecycle inspection plus Approval inspection and
idempotent approval decisions.

M7 adds the missing atomic broker admission seam: an immutable policy revision
requiring approval can admit one normalized Tool intent and its pending
Approval in one transition. Policy denial and a missing/mismatched revision
fail closed before an intent, Approval, grant, or adapter operation exists.
The public Approval projection includes only fixed action verb/target and a
maximum-use bound; raw model arguments, capability bytes/digests, and sandbox
descriptors remain private.

The Workspace Agent example now ships a loopback web binary and a terminal
binary. Both call only the public HTTP/Go SDK contract. The disposable
PostgreSQL/MinIO durable runner starts the API role, seeds pending approvals
through the private broker seam, proves owner-web approve/deny/cancel, a
cross-principal terminal cannot list another owner's inbox, expiry refusal,
and a restarted API role plus reconnected web client. The fixture is
deliberately broker-seeded: it is public-client evidence, not model-to-tool
composition or sandbox-execution evidence.

The model worker now accepts a bounded normalized Tool request only through
its private broker dependency. It stages the immutable descriptor, atomically
records the tool intent and pending approval, and moves the active Turn into
the non-terminal `waiting_for_approval` state. A successful owner approval is
the only decision that resumes the Turn; cancellation accepts the paused state.
The public Approval projection carries the owner requester and immutable policy
revision digest evaluated at admission.

## Remaining code-owned work

- add the canonical provider Tool-request parser/JSON-schema validation ahead
  of the now-composed model-worker broker handoff;
- record explicit denied/policy-invalidated/cancelled authorization facts and
  preserve queued Turn semantics while an Approval is pending;
- compose the Tool worker role, bounded output/artifact event path, restart
  reconciliation, and public API/SDK E2E;
- connect the public Workspace Agent to a composed model-to-tool producer once
  that worker role exists; the current durable client proof is broker-seeded;
- run the complete M7 focused, integration, public-path, documentation, and
  milestone gate evidence suite.

## Profile-gated dependency

Workspace Agent must not claim a session-scoped Firecracker workspace or
hostile-sandbox execution until M4 provides an available protected profile and
retained Linux x86_64 KVM, cgroup-v2, Jailer, boot, vsock, and cleanup evidence.
The local/macOS and memory-control adapters remain fail-closed development
seams only; they are not Firecracker evidence. M7 can test public approval
behavior and the descriptor-to-control boundary before that profile exists,
but its final Workspace sandbox E2E is blocked on that M4 evidence.
