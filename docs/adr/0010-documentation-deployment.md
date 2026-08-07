---
status: accepted
---

# Documentation generation and deployment

Documentation has curated conceptual sections and explicitly owned generated
reference outputs. A repository-local refresh skill regenerates only declared
outputs atomically, supports check mode, and refuses stale or conflicting
content. GitHub Pages deployment uses a separate least-privilege workflow;
main CI also runs the no-write docs check, and pull-request-only checks are not
the direct-main gate.

## Considered options

- Rewrite all documentation from source annotations.
- Deploy from a developer workstation or grant the main CI workflow Pages
  write authority.

## Consequences

Generated ownership and docs-version mapping are explicit. Main changes run
docs checks; deployment consumes a checked build artifact and uses protected
environment/identity permissions. Search and publication remain visibly
pre-crawl until #34 proves the deployed site, accessibility, and navigation.
