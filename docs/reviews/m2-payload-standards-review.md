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
