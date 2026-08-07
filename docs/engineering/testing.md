# Test suites and proof classification

Hermetic unit/property/fuzz suites live beside their Go packages. They use
in-memory inputs, injected clocks and sources, and no repository filesystem,
network, subprocess, environment, entropy, or wall-clock waits. Their proof
scope is `unit`.

`tests/architecture` is deliberately a repository contract suite, not a unit
suite. It reads the checked-out repository root to verify contributor guidance,
the canonical glossary, accepted ADR index, architecture authority, required
runbooks, and the declarative main-CI workflow. Its proof scope is `contract`.
That filesystem access is the behavior under test and is intentionally reached
only by `go test ./...`/`just check`; product packages remain hermetic.

Workflow, integration, local Tilt E2E, Linux/KVM E2E, documentation,
independent-review, main-CI, and release results use their matching explicit
proof scopes. A passing lower scope never substitutes for a required higher
scope.
