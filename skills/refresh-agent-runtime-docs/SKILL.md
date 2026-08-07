---
name: refresh-agent-runtime-docs
description: Deterministically update Agent Runtime public docs after a public capability, configuration, example, command, deployment, or evidence claim changes.
---

# Refresh Agent Runtime documentation

Use this skill when asked to “update the repository's docs” or when a public
contract, configuration field, deployment asset, example, command, operator
path, or verified security claim changes.

1. Read `AGENTS.md`, `CONTEXT.md`, the accepted ADRs, and
   `references/regeneration.md`. Treat passing implementation contracts as
   truth. Never publish planned behavior as implemented.
2. Inspect the exact code/config/example diff and update curated conceptual or
   operator pages deliberately. Generated pages are not hand-edited.
3. Update `source-manifest.json` when an input or generated output is added.
   The manifest is an explicit allow-list; do not replace it with a broad scan.
4. Run `just docs-generate`. The runner regenerates declared output atomically,
   refuses to overwrite dirty generated output, runs `just docs-check`, and
   prints the exact bounded documentation diff.
5. Review the complete diff. Report unsupported or undocumented behavior as a
   failure; do not claim the refresh succeeded when validation is red.

For CI or a no-write audit, run `just docs-check`. Its refresh phase compares
bytes and never creates or modifies generated output.
