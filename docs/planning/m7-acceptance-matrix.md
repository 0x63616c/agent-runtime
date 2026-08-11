# M7 acceptance matrix

This matrix is the M7 owner’s evidence plan. The binding requirements remain
the master requirements and acceptance ledger; this file records only the
approved seams, demonstrated coverage, and the next missing proof. A row stays
unclaimed until `evidence/requirements-ledger.json` contains a SHA-bound,
passing evidence entry of the required scope.

| Requirement | Approved seam | Demonstrated implementation coverage | Required acceptance proof still needed | Claim status |
| --- | --- | --- | --- | --- |
| TOL-001 | S5 Tool broker | Atomic broker admission, normalized model handoff, tool worker finalization. | Durable PostgreSQL/MinIO broker-to-grant-to-result proof retained at `evidence/m7-tool-broker-durable-postgres-minio.json` (code revision `168513d8b30e5476d09c7e1d7abd587e563aee1f`). | directly proven |
| TOL-002 | S5 Tool broker | Builtin wrapper, sandbox adapter, and Streamable HTTP MCP adapter implement the operation-ID recovery contract. | One shared broker-only contract suite across all three adapters. | unclaimed |
| TOL-003 | S5 Tool broker | Fake-clock unit cases cover expiry, revocation, max use, and cancellation refusal. | Durable integration proving those terminal states prevent dispatch. | unclaimed |
| TOL-004 | S5 Tool broker | State transitions create audit facts for admission, grant use, expiry, and terminal outcomes. | Durable audit ordering/secret-safety matrix for allow, deny, pending, expiry, exhaustion, and result. | unclaimed |
| TOL-005 | S5 Tool broker | Worker rejects oversized output, redacts credential-shaped output, and retains successful output as an Artifact. | Durable bounded/redacted Artifact and public-result/event reference integration. | unclaimed |
| TOL-006 | S5 Tool broker | MCP cancellation and status-only reconciliation return uncertainty rather than re-submit an effect. | Worker-level durable uncertain-outcome/recovery test carrying one operation ID. | unclaimed |
| HITL-001 | S5/S6 | Brokered model work moves the Turn to `waiting_for_approval`. | Durable approval-phase/restart proof through the public approval interface. | unclaimed |
| HITL-002 | S6 public approval | Public approval projection exposes safe action, scope, policy, requester, expiry, and state. | Golden public contract plus durable linkage proof. | unclaimed |
| HITL-003 | S6 public approval | Owner scope, idempotent approval, expiry, revocation, and cancellation paths have unit coverage. | Public fake-clock authorization matrix including deny and scope narrowing refusal. | unclaimed |
| HITL-004 | S5/S6 | Planner records approval and tool lifecycle effects. | Durable product-event and independent-audit ordering matrix for every terminal decision. | unclaimed |
| HITL-005 | S6 public approval | Retained local Stack proof covers pending reset/reconnect/idempotent replay and a separate public short-expiry late-decision conflict with no execution. | Retained at `evidence/m7-workspace-approval-public-stack-e2e.json` (code revision `cb6d9905c5b0da7c4ff483ad8dd4ac10e9fcc40b`). | directly proven |
| HITL-006 | S1 Workspace Agent | Retained disposable PostgreSQL/MinIO API-process proof runs both shipped binaries: web approve/replay/cancel/expiry, terminal deny, non-owner inbox isolation, and browser reconnect after API restart. | Retained at `evidence/m7-workspace-public-client-postgres-minio.json` (code revision `e916a7e2e8297332986e83274d3b34495390601e`); broker seeding and no-sandbox scope remain explicit. | directly proven |
| EX-002 | S1 plus M4 S9 | A declared local fixture produces an owner Artifact after approval, explicitly without a sandbox. | Session-scoped protected Workspace sandbox, safe file APIs, live process output, and Linux/KVM profile evidence. | blocked on M4 |

## Scope boundary

The declared local fixture is usable only for application composition evidence.
It does not execute a Workspace service, Sandbox, Firecracker, or protected
profile. M4 retains the Linux/KVM, Jailer, portable-transfer, mount, volume,
secret, and egress profile evidence required before EX-002 can be claimed.
