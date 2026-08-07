# Generated artifact ownership

`docs/planning/requirements/master-requirements.md` supplies permanent IDs and
`docs/planning/work-map.md` supplies exactly one terminal milestone owner. The
generator atomically owns only:

- `internal/milestone/manifest.go`
- `evidence/requirements-catalog.json`

`evidence/requirements-ledger.json` is curated durable state. The generator
may validate it but must never create, overwrite, or infer its statuses or
evidence. Duplicate terminal ownership, missing ownership, unknown IDs,
non-positive weights, drift, or partial ledgers fail visibly. Explicit
non-terminal contribution rows do not transfer ownership.

Run `go run ./cmd/generate-requirement-manifest --check` or `just check` after
changing binding requirements or the work map. Change generator inputs and
implementation together; never hand-edit generated output. Public API/docs
generation will follow this same declared-input, atomic-output, clean-diff
policy when those artifacts exist.
