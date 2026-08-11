---
status: accepted
---

# Temporary documentation production-dependency audit exception

## Context

The pinned Docusaurus 3.10.2 documentation dependency graph resolves
`image-size@2.0.2` through the MDX loader. GitHub advisories
`GHSA-w3rx-r6r6-pgpr` and `GHSA-5p2g-fcmc-qvqq` classify that version as high
severity and currently list no patched version. The normal documentation gate
runs `npm audit --omit=dev --audit-level=high`, so this known upstream defect
otherwise prevents a release even when the repository source, typecheck, and
site build pass.

## Decision

Accept one narrow, visible release-risk exception until
**2026-11-08T00:00:00Z**. It applies only to the static documentation build and
only when all of these conditions hold:

1. the lockfile resolves exactly `image-size@2.0.2`;
2. the production audit has no critical findings;
3. every high finding reaches exactly the two accepted `image-size` advisories
   above, and no other high advisory; and
4. the exception validator prints its accepted-exception result in CI rather
   than hiding the audit result.

`just docs-check` still executes the production audit on every run. A changed
lockfile, a new high or critical advisory, a resolved audit left with this
exception in place, or the expiry date all fail the gate. The linked tracking
issue is [#36](https://github.com/0x63616c/agent-runtime/issues/36).

The exception does not claim the dependency graph is vulnerability-free, does
not apply to runtime dependencies, and does not authorize an npm override,
unreviewed fork, or unsupported Docusaurus dependency substitution.

## Consequences

Release evidence must call out this conditional audit result until #36 closes.
The issue must be reassessed for every release milestone and immediately after
a compatible Docusaurus or `image-size` update. Removal requires a supported
upgrade, separately approved platform migration, or maintained and reviewed
patch, followed by a clean high-severity production audit and deletion of this
exception.
