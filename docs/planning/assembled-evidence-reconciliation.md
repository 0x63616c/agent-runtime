# Assembled-candidate evidence reconciliation

This audit applies to assembled candidate
`1795e1ec3a62973afaddd01f0083f963e6a4de78`. Historical artifacts and their
immutable revisions remain retained. They are not rewritten or treated as
candidate evidence when their code revision is not an ancestor of the assembled
candidate.

## Candidate-bound M7 proof

`./deploy/runtimeapi/run-durable-integration.sh` completed with exit status
zero on the candidate against disposable PostgreSQL, MinIO, and private Temporal
test services. Each M7 artifact below records that exact command and its zero
exit status; no workstation-local transcript is part of retained evidence.
The focused TOL-002 brokered builtin, sandbox-control, and MCP adapter contract
command also completed with exit status zero.

The separate redacted `evidence/m7-1795e1e-{tol002,tol003,tol004,tol005,
tol006,hitl001,hitl002,hitl004,hitl006}.json` artifacts are bound to that
exact revision; the earlier `b15a3e0` artifacts remain historical provenance.
The current artifacts complete TOL-002 through TOL-006 and HITL-001, HITL-002,
HITL-004, and HITL-006 only. TOL-001 remains in progress because broker tool
registration and general JSON-schema validation are not proven; HITL-003
remains in progress because policy invalidation is not proven. These artifacts
do not make a provider, deployed Stack, Workspace Sandbox, Firecracker,
Linux/KVM, or browser claim.

## Explicitly deferred physical proof

| Requirement set | Historical proof retained | Unmet candidate proof |
| --- | --- | --- |
| HITL-005 | Local Stack reset/reconnect/replay and late-decision proof. | Re-run with an attested current runtime API image; a source-built substitute is not promoted. |
| EX-003 | Local Stack Research Dossier proof. | Re-run the long research/blob/citation/resume/download path with an attested current runtime API image. |
| DEP-001–003, DEP-009 | Tilt two-Stack and teardown proof. | Fresh candidate Stack execution and teardown with the exact image identity. |
| DEP-004–006, TMP-001, TMP-007–008 | Self-hosted role/deployment smoke. | Fresh candidate hosted/self-hosted deployment proof. |
| INF-003–005 | Stack RBAC, reconcile/rollback, profile and hosted two-Stack evidence. | Fresh candidate physical/hosted Stack evidence. |

DEP-008 and INF-001–002 are also deferred: although their retained checks are
source/CI-oriented, the candidate changes Stack/runtime-API topology and no
candidate render/bootstrap proof has been retained. This is not a broader M1
completion claim.

## Status rule

Every deferred row is `in_progress` in the requirements ledger. Its historical
passing evidence remains as provenance, but cannot satisfy the candidate's
required physical proof until the stated acceptance path is rerun.
