# Contributing to Agent Runtime

Read [AGENTS.md](AGENTS.md), [CONTEXT.md](CONTEXT.md), the binding
[requirements](docs/planning/requirements/master-requirements.md), and relevant
[ADRs](docs/adr/README.md) before changing behavior. Planning documents are not
proof that a capability exists.

This build lands atomic vertical slices directly on `main`; it does not use a
PR as its approval path. Start from an assigned GitHub Issue naming permanent
requirement IDs, approved seams, invariants, documentation impact, and expected
evidence. Add one behavior test, observe it fail, implement only that slice,
then run the focused suite and `just check`. Use Ginkgo/Gomega, injected clocks
and sources, and bounded safe references. Never put secrets, raw prompts, model
reasoning, or command output in tests, logs, issues, or evidence.

Before a push, retain the exact pre-push result and comment it on the Issue.
After a push, wait for main CI and attach its immutable revision and artifact.
Stop unrelated delivery on red main. Never force-push or rewrite published
history. `just verify` is the final release gate and is expected to remain red
until every canonical ledger row has completed evidence.

See the [direct-main runbook](docs/operations/direct-main.md),
[configuration reference](docs/reference/configuration.md), and
[evidence/status runbook](docs/operations/evidence-and-status.md).
