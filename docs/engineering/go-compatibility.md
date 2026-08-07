# Go version and compatibility policy

The root module declares Go `1.26.0`; that is the current language and standard
library floor. CI reads `go.mod` rather than selecting an ambient Go version.
The repository publishes one root module and one semver release train. A local
`go.work` must never be required by a consumer or create a second release
boundary.

Before raising the Go floor or changing a public contract, record the
compatibility decision, update the module and documentation together, run a
clean external-consumer check once public packages exist, and include the
change in release notes. Deprecations remain supported for a documented
window; removals require the next allowed semantic-version boundary. The
`sdk/go` contract and `temporalpayload` package both have clean
external-consumer compile tests. No stable release has been cut yet, so those
tests prove module independence rather than a semver compatibility guarantee.
