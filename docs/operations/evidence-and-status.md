# Evidence and status runbook

The generated catalog owns the canonical 183 requirement IDs, milestone
ownership, and positive weights. The curated ledger owns status and proof
references and is never generator output. `just check` validates generation,
tests, and structural honesty; `just verify` additionally requires every row to
be `completed` with evidence.

Proof scopes are `unit`, `workflow`, `contract`, `integration`,
`local_tilt_e2e`, `linux_kvm_e2e`, `manual`, `documentation`,
`independent_review`, `main_ci`, and `release`. A required main-branch CI result
uses `main_ci`; other workflow locations are not proof scopes. Combine
complementary proofs where acceptance requires them, and record only bounded
revision, UTC, command, and artifact references with result `passed`.

Status reports contain the exact seven ADR-0007 fields. The percentage is a
weighted estimate, never standalone completion proof. Retain the report before
delivery; retain classified retryable failure state without provider error
text. Only the milestone owner sends to the typed `agant` topic after all owned
rows, immutable main CI, documentation, and final `just verify` are green.
Regular updates use completed, in-progress, blocked, uncertainty, last proof,
and next checkpoint without upgrading partial evidence.

Main CI retains its bounded artifact for 90 days. Before that expires, the
issue owner validates the downloaded record, copies its immutable revision,
`main_ci` scope, command ID, and `gha-<run>-<attempt>` reference into the
curated requirement ledger/evidence record, and links the GitHub run on the
Issue. The ledger reference is durable; the temporary artifact is supporting
verification, not the sole long-term record.

Documentation release evidence records the ordinary clean Astro Starlight
production audit from [ADR-0014](../adr/0014-astro-starlight-documentation-platform.md).
`just docs-check` executes `npm audit --omit=dev --audit-level=high` directly;
no exception or waiver applies. The retired ADR-0013 issue closes only with a
retained clean-audit result and completed migration evidence.
