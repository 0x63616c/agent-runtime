# M7 acceptance matrix

This matrix is the M7 owner’s evidence plan. The binding requirements remain
the master requirements and acceptance ledger; this file records only the
approved seams, demonstrated coverage, and the next missing proof. A row stays
unclaimed until `evidence/requirements-ledger.json` contains a SHA-bound,
passing evidence entry of the required scope.

| Requirement | Approved seam | Demonstrated implementation coverage | Required acceptance proof still needed | Claim status |
| --- | --- | --- | --- | --- |
| TOL-001 | S5 Tool broker | Candidate proof covers broker admission, approval, grant, dispatch, audit, and finalization. | Tool registration and general JSON-schema validation remain unproven at the broker seam; the current public Tool definition contains only name/description and Broker admission consumes a precomputed descriptor/digest. | deferred |
| TOL-002 | S5 Tool broker | Builtin wrapper, sandbox adapter, and Streamable HTTP MCP adapter implement the operation-ID recovery contract. | Exact-head unit contract: `evidence/m7-1795e1e-tol002.json` (revision `1795e1ec3a62973afaddd01f0083f963e6a4de78`). The sandbox adapter remains a declared control-client seam only. | directly proven |
| TOL-003 | S5 Tool broker | Disposable PostgreSQL/MinIO integration covers single-use exhaustion plus expiry, revocation, cancellation, denial, and unavailable-policy terminal refusal without adapter dispatch. | Exact-head proof: `evidence/m7-1795e1e-tol003.json` (revision `1795e1ec3a62973afaddd01f0083f963e6a4de78`). | directly proven |
| TOL-004 | S5 Tool broker | The disposable lifecycle checks linked, separately authorized audit/outbox records across approval and terminal tool states. | Exact-head proof: `evidence/m7-1795e1e-tol004.json` (revision `1795e1ec3a62973afaddd01f0083f963e6a4de78`). It is runtime/audit integration, not a sandbox or Stack claim. | directly proven |
| TOL-005 | S5 Tool broker | Disposable integration retains bounded redacted output and rejects oversized output without a new Artifact/object or raw public value. | Exact-head proof: `evidence/m7-1795e1e-tol005.json` (revision `1795e1ec3a62973afaddd01f0083f963e6a4de78`). | directly proven |
| TOL-006 | S5 Tool broker | Lost observation is reconciled to a safe uncertain terminal state rather than resubmitting an external effect. | Exact-head proof: `evidence/m7-1795e1e-tol006.json` (revision `1795e1ec3a62973afaddd01f0083f963e6a4de78`). | directly proven |
| HITL-001 | S5/S6 | A pending Approval keeps its Turn non-terminal and survives the disposable public API-process restart path. | Exact-head proof: `evidence/m7-1795e1e-hitl001.json` (revision `1795e1ec3a62973afaddd01f0083f963e6a4de78`). | directly proven |
| HITL-002 | S6 public approval | The safe Approval projection preserves stable bounded linkage and state across restart. | Exact-head proof: `evidence/m7-1795e1e-hitl002.json` (revision `1795e1ec3a62973afaddd01f0083f963e6a4de78`). | directly proven |
| HITL-003 | S6 public approval | Candidate focused proof covers owner authorization, replay, denial, expiry, scope refusal, and no Tool dispatch. | Add a candidate proof that an Approval cannot survive policy invalidation; the current focused fake-clock matrix does not cover that required condition. | deferred |
| HITL-004 | S5/S6 | Approval terminal routes retain safe Product events and independent audit/outbox correlations. | Exact-head proof: `evidence/m7-1795e1e-hitl004.json` (revision `1795e1ec3a62973afaddd01f0083f963e6a4de78`). | directly proven |
| HITL-005 | S6 public approval | Historical Stack evidence is retained but is not attested to the assembled candidate runtime API image. | Re-run the reset/reconnect/replay and late-expiry/no-dispatch proof with an explicitly attested current candidate image; no source-built substitute has been promoted. | deferred |
| HITL-006 | S1 Workspace Agent | Shipped web and terminal clients cover owner decision/replay/cancel/expiry, denial, isolation, and reconnect through the public contract. | Exact-head proof: `evidence/m7-1795e1e-hitl006.json` (revision `1795e1ec3a62973afaddd01f0083f963e6a4de78`). | directly proven |
| EX-002 | S1 plus M4 S9 | A declared local fixture produces an owner Artifact after approval, explicitly without a sandbox. | Session-scoped protected Workspace sandbox, safe file APIs, live process output, and Linux/KVM profile evidence. | blocked on M4 |

## Scope boundary

The declared local fixture is usable only for application composition evidence.
It does not execute a Workspace service, Sandbox, Firecracker, or protected
profile. M4 retains the Linux/KVM, Jailer, portable-transfer, mount, volume,
secret, and egress profile evidence required before EX-002 can be claimed.
