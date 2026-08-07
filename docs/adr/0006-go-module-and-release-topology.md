---
status: accepted
---

# Go module and release topology

The repository publishes one root Go module,
`github.com/0x63616c/agent-runtime`, with public packages below that path.
The Go SDK is `github.com/0x63616c/agent-runtime/sdk/go`; reusable packages
such as `temporalpayload` remain root-module packages. `go.work` may support
contributors but cannot define an external import or release boundary.

## Considered options

- Publish independent nested modules joined by `go.work`.
- Keep separate package repositories with independently timed releases.

## Consequences

One semver tag, Go-version floor, compatibility/deprecation policy and
docs-version mapping govern the release. A clean external-consumer test must
import the released SDK and payload package without `go.work`.
