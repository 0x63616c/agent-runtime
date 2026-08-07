set shell := ["bash", "-ceu"]

# Runs the passing deterministic gate for an incremental main change. Requires just 1.58.0.
check:
    go run ./cmd/generate-requirement-manifest --check
    go run ./cmd/afk-evidence -mode validate -file evidence/afk/m0-foundation-local.json
    go mod verify
    go test -race ./...
    go vet ./...
    go run ./cmd/no-real-wait --root .
    go run ./cmd/ledger-report --catalog evidence/requirements-catalog.json --ledger evidence/requirements-ledger.json

# Runs check, then requires all 183 rows to have valid completed evidence.
verify: check
    go run ./cmd/ledger-report --catalog evidence/requirements-catalog.json --ledger evidence/requirements-ledger.json --complete

# Compatibility alias for the final completion gate.
completion-check: verify
