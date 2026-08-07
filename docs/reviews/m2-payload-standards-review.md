# M2 payload boundary review — standards axis

Status: failed on 2026-08-07; remediation is active. Fixed point
`337b74337e7a0de29b9c4f2da1eb2045ee28f775`, reviewed through `596d3d2` with
the diff restricted to issue #13 paths.

1. The retained MinIO record names `86ad751` as the tested revision while the
   promoted ledger evidence named `063ef55`. Evidence must name the exact
   revision tested.
2. Completed PAY-002–PAY-005, PAY-008 and TMP-005–TMP-006 rows substituted
   unit or narrow adapter proof for their required golden, conformance,
   integration and E2E proof levels. The promotion was not honest.
3. `UIHandlerOptions` used a mutable options struct instead of the repository's
   sealed functional-option convention.
4. `Observation.InputSize` and `Observation.OutputSize` omitted the required
   byte units from raw numeric field names.

No material Fowler smell was reported. Commit `bac89b8` returned every M2 row
to `in_progress` before issue closure or milestone notification.

## Final independent re-review — 2026-08-07 UTC

Reviewed exact revision `676f69ecc8fd02260e247cb08e2cae3fa7814753`
against `AGENTS.md`, the accepted ADRs and architecture, the repository smell
baseline, and every earlier standards/evidence finding.

| Prior finding | Final disposition |
| --- | --- |
| MinIO evidence revision disagreed with promoted ledger evidence | Resolved safely. All M2 rows remain `in_progress`; the implementation-evidence narrative identifies the retained MinIO artifact as an older bounded S3 run and forbids reusing it for unrelated requirements or another revision. |
| Unit/narrow proof was promoted as golden, integration or E2E proof | Resolved safely. The promotion was reverted, and the current narrative distinguishes focused implementation tests, real Temporal integration, and the older MinIO artifact without promoting the ledger. |
| Mutable `UIHandlerOptions` violated the sealed-option convention | Resolved. The handler uses sealed functional options with constructor validation. |
| Raw numeric observation fields omitted byte units | Resolved. The public fields are `InputSizeBytes` and `OutputSizeBytes`. |
| Factory converter accessor widened the runtime composition seam | Resolved. The unchecked accessor is absent; client construction owns the mandatory compatibility gate and workers require its checked client. |
| Constructor guards missed aliases, `NewNamespaceClient`, and remote codec symbols | Resolved. One AST-based symbol guard covers client, worker and remote codec constructors through normal, aliased, dot-imported and function-value references. |
| Compatibility and GC tests used real or unbounded waits | Resolved. Compatibility checks inspect a finite deadline without waiting, and GC concurrency uses `testing/synctest` plus a joined `WaitGroup`. |

No documented-standard violation, security regression, unsafe abstraction, or
material Fowler smell remains in the reviewed M2 scope. **Final standards
verdict: PASS — 0 P0, 0 P1, 0 P2 findings.**

Independently run against a clean archive of `676f69e`:

```text
go test -race ./temporalpayload/... ./internal/temporalpayloadruntime
go test ./tests/architecture
go test -race -tags=integration ./temporalpayload ./internal/temporalpayloadruntime
go vet ./temporalpayload/... ./internal/temporalpayloadruntime ./tests/architecture
git diff --check 676f69e^ 676f69e
```

All commands passed. Documentation regeneration/check also passed after this
review was recorded. The real MinIO harness was not independently rerun here;
its retained evidence remains scoped to the exact older revision it names.
No ledger row was changed, no issue closure is claimed, and no milestone
notification is authorized by this review alone.
