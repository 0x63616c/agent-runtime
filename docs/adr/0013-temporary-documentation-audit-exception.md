---
status: superseded
---

# Retired documentation production-dependency audit exception

## Context

The former Docusaurus 3.10.2 documentation dependency graph resolved
`image-size@2.0.2` through the MDX loader. GitHub advisories
`GHSA-w3rx-r6r6-pgpr` and `GHSA-5p2g-fcmc-qvqq` classify that version as high
severity and currently list no patched version. The normal documentation gate
runs `npm audit --omit=dev --audit-level=high`, so this known upstream defect
otherwise prevents a release even when the repository source, typecheck, and
site build pass.

## Retired decision

The repository temporarily accepted one narrow, visible release-risk exception
until **2026-08-10T00:00:00Z**, while the documentation platform migration was
implemented. It applied only to the static documentation build and only when
all of these conditions held:

1. the lockfile resolves exactly `image-size@2.0.2`;
2. the production audit has no critical findings;
3. every high finding reaches exactly the two accepted `image-size` advisories
   above, and no other high advisory; and
4. the exception validator prints its accepted-exception result in CI rather
   than hiding the audit result.

This decision is retired by ADR-0014. The Astro Starlight lockfile has a clean
production audit, `just docs-check` invokes the ordinary high-severity audit
directly, and [#36](https://github.com/0x63616c/agent-runtime/issues/36) closes
only with retained clean-audit evidence.

The historical exception did not claim the dependency graph was
vulnerability-free, did not apply to runtime dependencies, and did not
authorize an npm override, unreviewed fork, or unsupported dependency
substitution.

## Consequences

No release evidence may cite this exception as active. ADR-0014 records the
replacement platform and its ordinary clean-audit gate.
