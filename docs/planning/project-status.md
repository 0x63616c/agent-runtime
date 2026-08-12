# Project status

This is the one-page internal view of the project. It is for planning; it is
not published in the documentation site and it is not a product claim.

Snapshot: `main` at `791a783` on 2026-08-12.

## Read this first

- **Completed** means the repository ledger has retained evidence for that
  requirement. It is not a promise that every external production environment
  has been exercised.
- **In progress** means code or local proof exists, but the required final
  behaviour or evidence is incomplete.
- **Not started** means it has no accepted completion evidence yet.
- The authoritative detail for any ID is in the
  [plain-English requirements](requirements/master-requirements.md) and its
  required proof is in the [acceptance ledger](requirements/acceptance-ledger.md).

## Snapshot

| State | Requirements |
| --- | ---: |
| Completed | 66 |
| In progress | 40 |
| Not started | 77 |
| Total | 183 |

## What is actually working now

- Public Go SDK and HTTP API: all 12 API requirements are marked complete.
- Core domain/runtime behaviour: all 13 domain requirements are marked complete.
- Temporal payload codec/blob package: all 8 payload requirements are marked complete.
- Most tool-authority work is complete: 5 of 6 tool requirements.
- Durable approval flows are mostly complete: 4 of 6 approval requirements.
- The local API, Durable Chat, Research Dossier, Workspace Agent, local stack,
  and two-stack test paths exist and have local coverage. They are not all
  release-complete feature claims yet.

## The few big finish lines

1. **Runtime data and operations:** complete PostgreSQL authority, migrations,
   backup/restore, retention, and production operations evidence.
2. **Real sandbox execution:** complete the sandbox authority profiles and run
   Firecracker on a Linux host with KVM.
3. **Model and examples:** choose and wire the supported model path, then make
   the three example applications genuinely useful end to end.
4. **Deployment and release:** finish the self-hosted/role/deployment proof,
   observability, docs, and final release/independent-review checks.

## Every remaining requirement

Use this as the checklist. Each group is intentionally short; look up an ID in
the two linked ledgers above when you want its exact acceptance condition.

| Area | Done / active / not started | Remaining IDs |
| --- | --- | --- |
| Data authority | 10 / 0 / 3 | DAT-009, DAT-010, DAT-013 |
| Deployment | 0 / 8 / 1 | DEP-001, DEP-002, DEP-003, DEP-004, DEP-005, DEP-006, DEP-007, DEP-008, DEP-009 |
| Documentation | 2 / 0 / 6 | DOC-001, DOC-002, DOC-003, DOC-004, DOC-006, DOC-007 |
| Engineering standards | 0 / 10 / 0 | ENG-001, ENG-002, ENG-003, ENG-004, ENG-005, ENG-006, ENG-007, ENG-008, ENG-009, ENG-010 |
| Examples | 0 / 1 / 6 | EX-001, EX-002, EX-003, EX-004, EX-005, EX-006, EX-007 |
| Human approval | 4 / 2 / 0 | HITL-003, HITL-005 |
| Infrastructure | 0 / 5 / 0 | INF-001, INF-002, INF-003, INF-004, INF-005 |
| Model provider | 0 / 0 / 5 | MOD-001, MOD-002, MOD-003, MOD-004, MOD-005 |
| Repository/release | 5 / 5 / 0 | MON-001, MON-002, MON-003, MON-009, MON-010 |
| Observability | 0 / 0 / 5 | OBS-001, OBS-002, OBS-003, OBS-004, OBS-005 |
| Operations status | 0 / 2 / 0 | OPS-STAT-001, OPS-STAT-002 |
| Sandbox | 0 / 0 / 44 | SBX-001 through SBX-044 |
| Temporal/runtime roles | 7 / 3 / 0 | TMP-001, TMP-007, TMP-008 |
| Tool broker | 5 / 1 / 0 | TOL-001 |
| Test/release gates | 0 / 3 / 7 | TST-001, TST-002, TST-003, TST-004, TST-005, TST-006, TST-007, TST-008, TST-009, TST-010 |

## External dependencies, not coding loops

- A Linux host with KVM is needed for actual Firecracker execution.
- A supported model-provider decision/credential setup is needed before a real
  model-backed application can be proven.
- Protected operational environments are needed for final deployment,
  retention, backup/restore, and alerting evidence.

Everything else is normal repository work. When choosing the next task, start
with one remaining ID in an area above, implement the smallest vertical slice,
run its local proof, and update this page only when the user-facing picture
changes.
