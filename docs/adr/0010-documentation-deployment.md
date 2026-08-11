---
status: superseded
---

# Superseded documentation generation and deployment

This historical decision established curated conceptual sections and explicitly owned generated
reference outputs. A repository-local refresh skill regenerates only declared
outputs atomically, supports check mode, and refuses stale or conflicting
content. GitHub Pages deployment uses a separate least-privilege workflow;
main CI also runs the no-write docs check, and pull-request-only checks are not
the direct-main gate.

## Considered options

- Rewrite all documentation from source annotations.
- Deploy from a developer workstation or grant the main CI workflow Pages
  write authority.

## Supersession

ADR-0014 supersedes this document's Docusaurus-era platform and publication
details. The refresh ownership, atomicity, GitHub Pages artifact model, and
least-privilege constraints remain binding through ADR-0014 and the current
documentation stack contract.

## Historical consequences

Generated ownership and docs-version mapping are explicit. Main changes run
docs checks; deployment consumes a checked build artifact and uses protected
environment/identity permissions. Search and publication remain visibly
pre-crawl until #34 proves the deployed site, accessibility, and navigation.
