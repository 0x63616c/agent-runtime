# Regeneration contract

The source manifest is the complete read/write boundary. Each generated output
declares its inputs, artifact kind, public status, and renderer version.

- Check mode compares bytes only. Missing or stale output fails without writes.
- Write mode renders in memory, rejects dirty existing output, and replaces a
  changed file through a same-directory fsynced temporary file and atomic rename.
- Curated paths are never generator destinations. A needed prose or claim
  change is proposed and edited deliberately by the agent.
- Output contains no timestamps, local machine paths, environment-derived
  values, credentials, secret values, random identifiers, or unbounded content.
- The final review is exactly `git diff --no-ext-diff HEAD -- website/
  skills/refresh-agent-runtime-docs/ skills/develop-with-agent-runtime/
  deploy/catalog.yaml` after `just docs-check` passes.

When a source category does not exist yet—such as the deployment catalog or
runnable examples—the public site says so. Add the real path to the manifest
only in the same slice that implements it.

The current public OpenAPI contract has a generated HTTP operation index. It
parses only the declared path, method, operation ID, and successful response
status; curated reference prose owns semantic and implementation-status
explanation. The Go SDK, deployment catalog, and runnable examples do not yet
have complete generated reference outputs, so the site must continue to label
them according to their implemented state. The Go SDK's declared public source
files additionally produce a documented symbol index. It rejects a missing
package comment or undocumented exported declaration or method and does not
infer implementation availability from source shape. Its `go list` discovery
is pinned to Linux/amd64 with cgo and ambient Go flags disabled, so the public
reference does not depend on the workstation that refreshes it.
