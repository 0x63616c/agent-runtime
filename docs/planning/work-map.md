# Agent Runtime M0–M10 work map

Status: execution map for the user-authorized AFK direct-to-main build. The
canonical tracker index is [Wayfinder map: deliver Agent Runtime
M0–M10](https://github.com/0x63616c/agent-runtime/issues/1). It deliberately
carries execution as an explicit exception to Wayfinder's default
decision-only mode.

## Operating rules

- An open unassigned issue is unclaimed. An agent assigns it to itself before
  the first external write and works only that slice.
- Every issue body names its requirements, seams/invariants, exact evidence,
  docs, declarative-infrastructure impact, blockers and completion-notification
  relationship. Native GitHub blocking links are the graph authority; its body
  repeats the blocker list for auditability.
- Planning and issue creation are not implementation. Do not mark an issue or
  requirement complete without its acceptance-ledger evidence.
- The ownership column below is terminal evidence ownership: exactly one issue
  may turn each requirement row green. An earlier issue may contribute a
  library, contract, fixture, or proof used by that owner, but that contribution
  is not a second owner and does not make the earlier issue wait for downstream
  work before it can close.
- M3 has a hard safety gate: [M0: repair the sandbox acceptance contract and
  rerun independent review](https://github.com/0x63616c/agent-runtime/issues/6)
  must pass before #15, #16, #17, #18, #19, #20, #21 and #22 start. Local
  sandbox work never proves Firecracker.

## Dependency-ordered vertical slices

| Milestone | Issue | Native blockers | Terminal evidence ownership | Execution evidence focus |
| --- | --- | --- | --- | --- |
| M0 | [M0: establish the governed Go foundation and evidence machinery](https://github.com/0x63616c/agent-runtime/issues/2) | — | MON-004–008 | IDs/time/errors/config/evidence/notifier/ledger foundations. |
| M0 | [M0: repair the sandbox acceptance contract and rerun independent review](https://github.com/0x63616c/agent-runtime/issues/6) | #2 | None (design gate only; no terminal owner) | P0/P1 contract repair, compiled API fixture and independent re-review. |
| M0 | [M0: establish the public documentation system and deterministic refresh skill](https://github.com/0x63616c/agent-runtime/issues/8) | #2 | DOC-005, DOC-008 | Docs toolchain, skill and drift fixtures. |
| M1 | [M1: render and validate the single declarative Stack specification](https://github.com/0x63616c/agent-runtime/issues/10) | #2, #6 | INF-001–005, DEP-008–009 | Typed render/check/diff, lifecycle and teardown safety. |
| M1 | [M1: deliver isolated local Tilt stacks and developer experience](https://github.com/0x63616c/agent-runtime/issues/12) | #10 | DEP-001–003 | Two-stack isolation and clean checkout Tilt proof. |
| M1 | [M1: make self-hosted deployment roles and trust boundaries operable](https://github.com/0x63616c/agent-runtime/issues/14) | #10 | DEP-004–006, TMP-001, TMP-007–008 | Roles, trust separation and self-hosted deployment. |
| M2 | [M2: ship the reusable size-aware Temporal payload and blob pipeline](https://github.com/0x63616c/agent-runtime/issues/13) | #2, #10 | PAY-001–008, TMP-005–006 | Inline/zstd/offload conformance and UI codec proof. |
| M3 | [M3: implement the durable sandbox public contract and core](https://github.com/0x63616c/agent-runtime/issues/15) | #2, #6 | SBX-001, 003–004, 007–012, 015–020 | Frozen operations, process/output/limit API. |
| M3 | [M3: implement durable sandbox control, ledger, reconciliation and reaping](https://github.com/0x63616c/agent-runtime/issues/16) | #10, #15 | SBX-002, 005–006, 013–014 | Durable control/recovery/reaper/output integration. |
| M3 | [M3: implement enrolled, fenced sandbox host control protocol](https://github.com/0x63616c/agent-runtime/issues/17) | #6, #16 | SBX-040–044 | mTLS enrollment/envelope/fencing/quarantine. |
| M4 | [M4: prove the Linux/KVM Firecracker foundation profile](https://github.com/0x63616c/agent-runtime/issues/18) | #17 | SBX-021, DEP-007, TST-005 | Real KVM isolation and kill/recovery proof. |
| M4 | [M4: certify local, fake and Firecracker sandbox adapter capabilities](https://github.com/0x63616c/agent-runtime/issues/19) | #15, #18 | SBX-022–025, TST-003 | Refusal/capability conformance. |
| M4 | [M4: deliver portable transfer and securely gated host mounts](https://github.com/0x63616c/agent-runtime/issues/20) | #19 | SBX-026–028 | Transfer first; host-mount KVM security gate. |
| M4 | [M4: deliver durable volume and snapshot capability profiles](https://github.com/0x63616c/agent-runtime/issues/21) | #19 | SBX-029–032 | Leases, taint, snapshot manifest/recovery. |
| M4 | [M4: deliver command-scoped secrets and mediated egress profiles](https://github.com/0x63616c/agent-runtime/issues/22) | #19 | SBX-033–039, TST-004 | Secret isolation/broker and mandatory proxy KVM proof. |
| M5 | [M5: implement the durable agent kernel and public HTTP/Go SDK contract](https://github.com/0x63616c/agent-runtime/issues/23) | #2 | DOM-001–013, API-001–012 | Kernel state machine and public contract. |
| M5 | [M5: implement PostgreSQL data authority, event cursors, audit and outbox](https://github.com/0x63616c/agent-runtime/issues/24) | #10, #23 | DAT-001–013 | PostgreSQL authority, events, audit/outbox. |
| M5 | [M5: implement replay-safe Temporal orchestration and role composition](https://github.com/0x63616c/agent-runtime/issues/25) | #13, #14, #23, #24 | TMP-002–004, TMP-009–010 | Private Temporal/replay/Continue-As-New. |
| M6 | [M6: implement the verified Codex subscription model adapter](https://github.com/0x63616c/agent-runtime/issues/26) | #23, #25 | MOD-001–004 | Official support gate and safe lifecycle. |
| M6 | [M6: deliver Durable Chat through the public contract](https://github.com/0x63616c/agent-runtime/issues/27) | #12, #26 | MOD-005, EX-001 | Protected canary and restart/reconnect E2E. |
| M7 | [M7: implement policy-governed tools and durable human approval](https://github.com/0x63616c/agent-runtime/issues/28) | #23, #24, #25 | TOL-001–006, HITL-001–005 | Broker/grant/audit/approval recovery. |
| M7 | [M7: deliver Workspace Agent through public sandbox and approval contracts](https://github.com/0x63616c/agent-runtime/issues/29) | #12, #16, #19, #20, #21, #22, #28 | EX-002, HITL-006 | Session sandbox and browser/TUI approval E2E. |
| M8 | [M8: deliver Research Dossier as a resumable artifact-producing application](https://github.com/0x63616c/agent-runtime/issues/30) | #8, #12, #24, #25, #28 | EX-003 | Long research/blob/citation/resume/download E2E. |
| M9 | [M9: implement safe correlated observability and operator inspection](https://github.com/0x63616c/agent-runtime/issues/31) | #16, #24, #25, #28 | OBS-001–005 | Correlation/redaction/dashboards/inspection. |
| M9 | [M9: harden cross-example safety, tenancy and public-contract presentation](https://github.com/0x63616c/agent-runtime/issues/32) | #27, #29, #30 | EX-004–007, TST-006 | Example isolation and three-example Tilt E2E. |
| M9 | [M9: make verification, CI, completion reporting and independent review release-grade](https://github.com/0x63616c/agent-runtime/issues/33) | #18, #19, #22, #25, #31, #32 | ENG-001–007, ENG-010, TST-001–002, TST-007–008 | Project-wide standards/import guards and final CI matrix. |
| M10 | [M10: publish complete public documentation, references and operator guides](https://github.com/0x63616c/agent-runtime/issues/34) | #8, #27, #29, #30, #31, #32, #33 | DOC-001–004, DOC-006–007 | Pages docs, generated refs and truthfulness checks. |
| M10 | [M10: perform public release and retain milestone completion evidence](https://github.com/0x63616c/agent-runtime/issues/35) | #33, #34 | MON-001–003, MON-009–010, ENG-008–009, OPS-STAT-001–002, TST-009–010 | External consumer, command/generation smoke, full ledger, all records/notifications. |

## Prerequisite and partial evidence (non-terminal)

These relationships make reuse and closure semantics explicit without assigning
a second green owner.

| Contributing issue | Contribution | Terminal evidence owner |
| --- | --- | --- |
| #2 | Repository/module and direct-main foundations for MON-001–003 and MON-009–010; engineering libraries/checks for ENG-001–009; notifier/evidence machinery for OPS-STAT-001–002 and TST-001, TST-007, TST-009. | #33 for ENG-001–007, ENG-010, TST-001–002 and TST-007–008; #35 for MON-001–003, MON-009–010, ENG-008–009, OPS-STAT-001–002 and TST-009–010. |
| #6 | Reviewed contract and traceability for SBX-011–012, SBX-040–044 and INF-001–005. | #10 for INF-001–005; #15 for SBX-011–012; #17 for SBX-040–044. |
| #16 | Durable restart/reconnect integration reuses and validates the core-owned SBX-017 output spool/tee contract. | #15. |
| #25 | Temporal import/source guard and replay fixtures that contribute to ENG-010 and project-wide verification. | #33. |
| #18, #19, #22 and #32 | Concrete Linux/KVM, conformance, adversarial and local-Tilt suites for TST-003–006. | The same issues own TST-003–006 terminally; #33 aggregates them into the CI matrix but does not re-own them. |
| #8 | Completed docs skill/toolchain contracts for DOC-005 and DOC-008. | #8; #34 revalidates them during publication without re-owning them. |
| #33 | Complete-lane and independent-review inputs used by release verification, including MON-010 and TST-009–010 evidence. | #35. |

## Coverage and graph checks

The requirement inventory has 183 permanent IDs. Expanding every range in the
terminal-evidence-ownership column covers all 183 exactly once: no missing,
unknown, or duplicate terminal owners. The generated catalog records the owning
milestone from this mapping; the issue link in the same row is the unique issue
owner. The validation command added by M0 must fail for a missing, unknown,
unowned, or multiply owned ID. Narrative prerequisite/partial-evidence tables
are intentionally excluded from catalog generation.

The native graph is acyclic in delivery order M0 → M1/M2 → M3/M5 → M4/M6/M7 →
M8 → M9 → M10. The early duplicate links were removed and rewired to live
predecessors (#6 and #10); the closed duplicate records remain only as an
auditable explanation of the transient batched-creation mistake. No work may
start through a closed duplicate.

## Commands: planned versus working

`tilt up -- --stack=<name>`, `just test`, `just integration`, `just e2e`,
`just docs`, and `just docs-check` are **planned command contracts** until a
checked-in implementation and clean-checkout evidence exist.
Do not copy them into public quickstarts as working commands before then.
