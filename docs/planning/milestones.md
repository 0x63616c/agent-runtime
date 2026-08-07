# Agent Runtime delivery milestones

Status: planned execution map. This is not evidence that a milestone or a
command is complete or runnable. Binding scope remains the master requirements
and acceptance ledger.

Each milestone closes only when its uniquely terminal-owned ledger rows are
green, every prerequisite/gate issue assigned to that milestone has satisfied
its own bounded acceptance criteria, the required docs and retained
machine-readable evidence exist, direct-main checks are green, and a redacted
completion record is retained before the configured notification is sent to
`https://ntfy.sh/0x63616c-ai-agant`. A prerequisite-only issue may close when
its contract or foundation is accepted; it never waits for a downstream issue
to make that downstream requirement green. The percentage in a notification is
a weighted-ledger estimate, not proof by itself.

| Milestone | Outcome | Gate to begin | Completion evidence | Notification |
| --- | --- | --- | --- | --- |
| M0 — Contract and foundations | Governed Go/evidence/docs foundation and a safe sandbox implementation contract. | Initial program frontier. | Foundation/ledger/notifier tests; docs-skill fixtures; sandbox P0/P1 repair passes independent re-review. | First retained M0 record, then notification. |
| M1 — Isolated Tilt environment | One typed Stack renders isolated, self-hosted local environments. | M0 Stack and sandbox contract gates. | Renderer/policy/two-stack/RBAC/NetworkPolicy/Tilt/operator evidence. | First retained M1 record, then notification. |
| M2 — Payload and blob infrastructure | Reusable local converter and UI-only codec service with exact size-aware behavior. | M0 foundation and Stack renderer. | Codec conformance, two-consumer exchange and compatibility evidence. | First retained M2 record, then notification. |
| M3 — Durable sandbox control | Public durable operation control, ledger/reaper and enrolled fenced hosts. | **Independent sandbox re-review must pass.** | S9/S10/S11 recovery, host protocol and authority-boundary evidence. | First retained M3 record, then notification. |
| M4 — Firecracker execution | Linux/KVM foundation plus every final sandbox authority profile. | M3 host protocol. | Linux/KVM proofs and capability conformance; unavailable profile remains blocked. | First retained M4 record, then notification. |
| M5 — Durable agent runtime | Public SDK/API, kernel, PostgreSQL authority and private Temporal adapter. | Foundation, payload, roles and data authority dependencies. | S1/S2/S3/S7 contracts, replay and migration/outbox evidence. | First retained M5 record, then notification. |
| M6 — Codex and Durable Chat | Verified supported Codex subscription path and usable public Durable Chat. | M5 plus external support/credential evidence. | Protected live canary and restart/reconnect/cancel E2E. | First retained M6 record, then notification. |
| M7 — Tools, approval and Workspace Agent | Brokered authority, durable approval and sandbox-backed workspace application. | M5 and required M3/M4 profiles. | Tool/approval and browser/TUI public-path E2E. | First retained M7 record, then notification. |
| M8 — Research Dossier | Resumable research application producing durable artifacts. | M2, M5, M7 and its public local stack. | Long-run/blob/citation/resume/download E2E. | First retained M8 record, then notification. |
| M9 — Production hardening | Correlated safe observability, cross-example safety and real verification matrix. | All runtime, sandbox and example paths. | CI, Linux/KVM, local Tilt, adversarial and independent-review evidence. | First retained M9 record, then notification. |
| M10 — Public release | Published docs and one honest root-module release. | M9 green and docs publication ready. | Full ledger report, external-consumer test, Pages docs, all milestone records. | M10 owner sends final notification. |

## Planned and working commands

`just check` is the working incremental gate. `just verify` is the working
final evidence gate and is expected to fail until all 183 canonical rows have
valid completed evidence. Other planned commands—`tilt up -- --stack=<name>`,
`just test`, `just integration`, `just e2e`, `just docs`, and `just
docs-check`—become public instructions only after their implementations and
clean-checkout proof land. The retained reachability event `GCXy4IYjJp96` is
an operational fact, not feature or milestone proof.

## Milestone ownership

The exact issue-to-requirement terminal ownership, prerequisite contributions,
native dependency graph, and coverage validation live in
[work-map.md](work-map.md). Every requirement has exactly one terminal issue;
earlier planning, foundation, and aggregate-verification contributions are
named separately and are never a second path to green acceptance evidence.
