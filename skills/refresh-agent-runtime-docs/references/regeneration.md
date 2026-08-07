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

When a source category does not exist yet—such as the public OpenAPI contract,
Go SDK, deployment catalog, or runnable examples—the public site says so. Add
the real path to the manifest only in the same slice that implements it.
