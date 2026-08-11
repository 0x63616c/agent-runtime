---
status: accepted
---

# Astro Starlight documentation platform

## Context

The public documentation site must remain a version-controlled static GitHub
Pages artifact with a reproducible Node lockfile, strict generated-reference
refreshing, accessible navigation, search, legacy-route handling, and a clean
production dependency audit. Docusaurus 3.10.2 inherited two unpatched high
severity `image-size` findings, temporarily tracked by ADR-0013 and issue #36.

## Decision

Use Astro **7.2.0** with Starlight **0.41.7** as the sole public documentation
platform. Curated and generated MDX lives under
`website/src/content/docs/docs/`, preserving the established `/docs/...`
public URLs. `website/astro.config.mjs` declares a checked Starlight sidebar,
Pagefind local static search, GitHub edit links, GitHub Pages project-site base
path, and explicit redirects for the old absolute Docusaurus routes.

`just docs-check` performs deterministic generated-doc freshness, `npm ci`,
`npm audit --omit=dev --audit-level=high`, Astro typecheck, production build,
and route-manifest verification over every current and legacy route. Its Pages
artifact is `website/dist`. There is no Docusaurus runtime, secondary permanent
documentation site, dependency override, or audit waiver.

The implementation uses only current official APIs: [Astro routing](https://docs.astro.build/en/guides/routing/),
[Starlight content](https://starlight.astro.build/getting-started/),
[Starlight sidebar navigation](https://starlight.astro.build/guides/sidebar/),
and [Starlight site search](https://starlight.astro.build/guides/site-search/).

## Consequences

ADR-0013 is superseded and issue #36 closes only after the clean audit and full
docs gate are retained on the migration revision. Issue #37 owns this one-way
platform migration. Future Astro/Starlight upgrades are intentional lockfile
changes and run the whole docs/reference/snippet/a11y/Pages gate.
