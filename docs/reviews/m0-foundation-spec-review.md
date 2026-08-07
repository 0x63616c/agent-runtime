# M0 foundation — Spec review

Fixed point: `4439138`. Scope: the requested uncommitted M0 foundation files,
Issue #2, its latest author disposition, and the binding MON-001–010,
ENG-001–010, OPS-STAT-001–002, TST-001, TST-007 and TST-009 contract at seams
S2, S11 and S12. This is independent of the standards review.

## Final independent re-review — 2026-08-06

The catalog, curated ledger, notifier DTO and redaction repairs are real, and
the latest author comment is appropriately explicit that Issue #2 remains
open. The proposed disposition nevertheless does not resolve the binding
completion-gate contract, and the evidence schema cannot represent several
required proof levels.

## Prior-finding disposition

| Prior finding | Final disposition |
| --- | --- |
| P0: `just verify` can be green while binding rows are not green | **Not resolved.** `just verify` now validates a complete catalog/ledger pair, but it still exits 0 with 25 Issue #2 rows `in_progress`. The non-green rejection was moved to `just completion-check`, contrary to the acceptance ledger's explicit `just verify` gate. |
| P1: required acceptance evidence absent or unit-shaped | **Honestly incomplete, not falsely claimed.** The ledger has all 25 Issue #2 rows `in_progress`, zero completed rows and zero proof records. The author explicitly leaves the S2 kernel, canonical/property vectors, full TST-001/TST-007, documentation, immutable revision and main-CI evidence open. These remain prerequisites to closing Issue #2. |
| P1: notifier payload cannot carry regular-status semantics | **Resolved.** `Report` has exactly the seven ADR fields, and structured `evidence_summary` carries completed, in-progress, blocked and uncertainty references. Estimate and retained delivery detail remain outside the transport DTO. |
| P1: malformed Session ID leaks caller input | **Resolved.** Rejection returns the fixed `parse session ID: invalid value` text; the strict 16-character ASCII payload and tests prevent echoing oversized or credential-bearing input. |
| P2: no-wait gate proves less than TST-007 | **Partially repaired and honestly still open.** The AST gate now checks production and test source, aliases and dot imports for six real-time wait APIs and honors cancellation. It still does not prove bounded polling or test-order independence, and the author correctly leaves full TST-007 incomplete. |

## Independently verified repairs

- The master requirement source, generated manifest, generated catalog and
  curated ledger contain the exact same 183 unique IDs. There are no ownership
  mismatches, every catalog weight is positive, and every ID has one primary
  milestone derived from the first owning row in
  [work-map.md](../planning/work-map.md). The catalog has 183 rows; the ledger
  separately has 183 rows.
- The generator writes only `internal/milestone/manifest.go` and
  `evidence/requirements-catalog.json`, using temporary-file replacement. It
  reads and validates `evidence/requirements-ledger.json` but does not generate
  or overwrite that curated state.
- The curated ledger contains exactly the Issue #2 set—MON-001–010,
  ENG-001–010, OPS-STAT-001–002, TST-001, TST-007 and TST-009—as 25
  `in_progress` rows. The other 158 rows are `not_started`; none is completed
  and none contains evidence.
- `just completion-check` fails as expected on the first `in_progress` row.
  This is an honest negative check, but it does not replace the named binding
  gate.
- JSON serialization of `Report` is fixed to exactly `milestone`,
  `estimated_overall_percent`, `evidence_summary`, `next_milestone`,
  `commit_or_revision`, `utc_time` and `status`. Weighted completed state,
  unfinished/blocked state, explicit uncertainty, next checkpoint and the
  immutable revision all reach those seven fields without adding a shadow
  transport field.
- No real notifier transport exists in this slice, no ledger row claims
  completion, and Issue #2 remains open. The author's statements that no ntfy
  milestone notification, immutable-main proof or complete TST-001/TST-007
  evidence exists match the repository state.

## Findings

### P0-1 — The required completion behavior is attached to the wrong command

The acceptance ledger requires the **`just verify`** ledger parser to reject
missing, unknown and non-green requirements
([acceptance-ledger.md](../planning/requirements/acceptance-ledger.md), lines
195 and 200–204). TST-009 likewise requires final `just verify` to emit a
machine-readable completion report naming every requirement, its
proven/blocked/not-applicable state and evidence links, without treating “not
implemented” as passed
([master-requirements.md](../planning/requirements/master-requirements.md),
lines 771–774).

The current `verify` recipe invokes `ledger-report` without `--require`
([Justfile](../../Justfile), lines 4–10). That path only validates catalog and
ledger shape, then emits:

```json
{"ledger":"evidence/requirements-ledger.json","result":"complete-catalog-valid"}
```

It neither names the 183 row states/evidence nor rejects non-green entries
(`cmd/ledger-report/main.go`, lines 15–18 and 49–64). In the current worktree it
exits 0 while all 25 Issue #2 rows are `in_progress`. The separate
`completion-check` correctly exits 1, but changing the command name is not an
authorized change to TST-009 or its acceptance row. This is the same material
failure as the prior P0, not its resolution.

**Required fix.** Keep a structural catalog check if useful, but make the
binding `just verify` completion mode reject every required non-green row and
emit the complete per-requirement status/evidence report. Until the full
release gate is intended to activate, an explicitly named development/schema
command may pass structural validation; it must not be represented as the
binding `just verify`. Add negative fixtures for missing, unknown,
`not_started`, `in_progress`, blocked-without-explicit-allowed disposition and
completed-without-valid evidence, plus a complete-report golden fixture.

### P1-1 — The canonical proof schema cannot represent required proof levels

`ProofLevel` accepts only `unit` and `ci`
(`internal/milestone/types.go`, lines 38–46), and ledger validation rejects
every other value. But the repository contract requires machine-readable
evidence to state whether proof is unit, workflow, integration, local Tilt E2E
or Linux/KVM E2E ([AGENTS.md](../../AGENTS.md), lines 194–197). The acceptance
ledger also distinguishes contract, integration, local-stack and Firecracker
proof families. “CI” is an execution location, not a substitute for those
proof scopes. The canonical 183-row ledger therefore cannot truthfully retain
several evidence families it is designed to govern.

**Required fix.** Define and validate the complete stable proof-level taxonomy
required by the binding evidence families—at minimum unit, workflow,
integration, local Tilt E2E and Linux/KVM E2E—and keep CI/run identity as
separate provenance if needed. Add parse/golden/refusal cases and demonstrate
that a requirement can retain multiple complementary proof records without
collapsing their scope.

### P1-2 — TST-007 coverage remains deliberately incomplete

The repaired source check finds direct `time.Sleep`, `After`, `AfterFunc`,
`NewTimer`, `NewTicker` and `Tick` calls (`internal/nowait/check.go`, lines
80–133). It still has no rule or evidence for eventual polling without a
deadline or reliance on test order, both explicit parts of TST-007. The author
does not claim otherwise and the row remains `in_progress`, so this is not a
false evidence claim. It is still required Issue #2 work before the row or
issue can be completed.

## Scope creep

None found. The manifest/catalog generator, curated ledger, status calculation,
fake notifier, typed configuration, opaque Session ID, fake clock, safe error
wrapper and source-time check are within Issue #2's stated S2/S11/S12
foundation scope. No infrastructure bootstrap or real notification transport
was added.

## Checks

- `just verify`: exited 0 and printed `complete-catalog-valid`; this is the P0
  evidence above, not completion proof.
- `just completion-check`: exited 1 with `requirement is in_progress, not
  completed`, as expected.
- Independent catalog script: 183 master IDs, 183 work-map owners, 183 catalog
  rows, 183 ledger rows, exact ID equality, zero ownership mismatches, all
  weights positive, exact 25-row Issue #2 `in_progress` set, zero completed and
  zero evidence rows.
- `go test -race ./...`, `go vet ./...`, `go mod verify` and `git diff --check`:
  exited 0.

## Final spec verdict

**FAIL.** The catalog/ledger separation, ownership derivation, seven-field
regular-status payload and honest incomplete-state reporting are sound, but
P0-1 leaves the binding completion gate unsatisfied and P1-1 cannot represent
required proof scopes. Issue #2 must remain open; no M0 completion or milestone
notification may be claimed. P1-2 must also be completed before TST-007 turns
green.

## Final correction re-review — 2026-08-06

This section supersedes the preceding verdict after independently reviewing the
command/evidence corrections. The fixed point and implementation scope remain
unchanged.

### Corrected finding disposition

| Finding | Final disposition |
| --- | --- |
| P0-1 final `just verify` did not reject non-green rows | **Resolved.** `just check` is now the explicitly incremental passing gate. Final `just verify` composes it with `ledger-report --complete`, emits all 183 required IDs and all 183 ledger entries, then exits 1 when any row lacks completed evidence. `completion-check` is only a compatibility alias for that same final gate. |
| P1-1 proof schema could not represent accepted evidence scopes | **Resolved.** `ProofLevel` now has distinct unit, workflow, contract, integration, local Tilt E2E, Linux/KVM E2E, manual, documentation, independent-review and release values. Validation accepts exactly that finite set, supports multiple complementary proof records and refuses unknown scope text. CI/run location is no longer misrepresented as the proof scope. |
| P1 notifier regular-status semantics | **Resolved and unchanged.** The transport remains exactly seven fields. Structured `evidence_summary` carries completed, in-progress, blocked and uncertainty references; weighted estimate, next checkpoint, immutable revision and overall status all cross the exact DTO without adding transport fields. |
| P1 malformed Session ID disclosure | **Resolved and unchanged.** Strict bounded ASCII validation returns one fixed rejection string and never echoes caller input. JSON and source-failure behavior remain covered. |
| P2 full TST-007 proof | **Honestly non-green.** The cancellable AST gate covers direct real-time wait APIs in production and test source, including aliases/dot imports. Bounded-polling and test-order-independence evidence is still incomplete, remains `in_progress`, and is not claimed as acceptance. |

### Independent evidence

- `just check` exited 0 after generated-manifest drift checking, module
  verification, `go test -race ./...`, vet, no-real-wait inspection and
  complete 183-row catalog/ledger structural validation.
- Final `just verify` first completed the same incremental checks, then emitted
  `required-requirements-not-completed` with exactly 183 required IDs and 183
  requirement records before exiting 1. The emitted state is exactly 25
  `in_progress`, 158 `not_started`, zero completed rows and zero evidence rows.
  This is the required honest negative result, not a false-green check.
- An independent expansion of the binding master requirements and work-map
  ownership found 183 unique master IDs and 183 primary owners. Those sets
  exactly equal the 183 generated catalog IDs and 183 curated ledger IDs;
  ownership mismatches are zero and every weight is positive.
- The generator still writes only the manifest and catalog using atomic
  replacement. It reads and validates the curated ledger but never generates
  or overwrites it.
- The proof validator's finite taxonomy covers all accepted proof families,
  while focused tests retain complementary levels, reject an unknown level,
  reject missing/unknown and every non-green status, reject completed rows with
  no evidence, and fix the complete-report JSON shape.
- The seven-field report semantics, fixed-topic notifier behavior,
  retain-before-deliver/retry ordering, safe failure classification, config
  redaction, ID non-disclosure and fake-clock behavior remain covered by the
  passing race suite.
- `go test ./...`, `go test -race ./...`, `go vet ./...`, `go mod verify` and
  `git diff --check` independently exited 0.

### Remaining explicitly non-green Issue #2 scope

Issue #2 correctly remains open. Its 25 owned rows have not earned completion
evidence. In particular, the deterministic S2 kernel, canonical/property
vectors and full TST-001 coverage, bounded-polling/test-order TST-007 proof,
required contributor/configuration/evidence/status documentation, immutable
revision and retained main-CI/AFK evidence remain incomplete. No real notifier
transport or milestone notification was exercised, no ledger row is marked
completed, and no author or document claims otherwise.

No new specification gap, false evidence claim or scope creep was found. The
manifest/catalog generator, curated ledger, status/notifier machinery, typed
configuration, opaque Session ID, fake clock, safe error wrapper and source-time
check remain within Issue #2's S2/S11/S12 foundation scope.

### Final spec verdict

**PASS.** The previous command-gate and proof-taxonomy findings are resolved,
and the remaining unfinished acceptance work is explicitly non-green rather
than silently passed. This approves the current M0 foundation specification
machinery; it does not authorize closing Issue #2, recording M0 complete or
sending a milestone notification. Those actions remain blocked until all 25
owned rows have their binding acceptance evidence and final `just verify`
passes.
