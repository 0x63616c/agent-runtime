---
status: accepted
---

# Source of truth and monorepo boundary

The master requirements, `CONTEXT.md`, `docs/architecture/system.md`, and
accepted ADRs are the sole implementation source of truth. Agent Runtime is
one public MIT monorepo: runtime, sandbox, payload/blob package, SDK, examples,
deployment assets, documentation and evidence live here. Copied and external
drafts are historical input only; they cannot override an accepted decision or
move a component into another repository.

## Considered options

- Let the supplied discussion architecture or Software Factory draft remain
  co-equal authority.
- Extract shared runtime pieces into a separate repository before this release.

## Consequences

Conflicts are corrected in the binding documents before feature work. Historical
drafts remain attributable but are marked superseded rather than silently
rewritten into implementation guidance.
