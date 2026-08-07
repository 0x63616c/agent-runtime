---
status: accepted
---

# Documentation generation and deployment

Documentation has curated conceptual sections and explicitly owned generated
reference outputs. A repository-local refresh skill regenerates only declared
outputs atomically, supports check mode, and refuses stale or conflicting
content. GitHub Pages deployment will use a separate least-privilege workflow
after the docs stack exists; pull-request-only checks are not the direct-main
gate.

## Considered options

- Rewrite all documentation from source annotations.
- Deploy from a developer workstation or grant the main CI workflow Pages
  write authority.

## Consequences

Generated ownership and docs-version mapping are explicit. Main changes run
docs checks when implemented; deployment consumes a checked build artifact and
uses protected environment/identity permissions. M0 does not advertise a docs
command or deployment that does not yet exist.
