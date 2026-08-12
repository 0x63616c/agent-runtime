# Public API v1 compatibility

The checked-in `api/openapi/compatibility-v1.json` is the retained minimum
compatibility baseline for the public v1 HTTP and Go SDK contract. Its test
requires each listed route, success status, required schema field, and closed
enum member to remain available. Additive optional fields, routes, and enum
members require an OpenAPI/SDK/docs update but may remain v1-compatible.

For example, `producer.gap` is an additive Event vocabulary member. It is
emitted before the terminal Event when a producer outcome cannot be recovered,
so callers can inspect the durable terminal state rather than treating a
missing live stream segment as success.

The drained-Session cancellation slice is also additive within v1. It adds the
`POST /v1/sessions/{session_id}/cancel` route, the `SessionCanceller` SDK
capability, and the `session.cancelled` and `session.failed` Event members. It
does not widen `RuntimeClient`; existing implementations remain source
compatible, while callers opt into cancellation by accepting the narrower
capability interface or using the concrete `Client`.

Removing or renaming a route, required field, ID format, failure/event value,
Agent/Policy/Tool field, or changing its meaning is breaking. It requires the
next permitted semantic-version boundary, a new compatibility baseline, and a
migration guide that states the old and new forms, rollback limits, and the
support window. A Policy revision is immutable: callers create a new revision
and consumers remain pinned to the digest they accepted; existing revisions
are never edited in place.

Before a public contract change, run `just check`, regenerate the OpenAPI and
documentation indexes, add an explicit compatibility decision to release
notes, and retain an external-consumer SDK check at release time. The checked
release-consumer contract creates a temporary module with `GOWORK=off`, imports
only `github.com/0x63616c/agent-runtime/sdk/go`, and typechecks the retained
`RuntimeClient` plus additive `ArtifactStreamer` and `ToolCallInspector`
and `SessionCanceller` capabilities. The same gate retains the OpenAPI
vocabulary baseline. Until a version is published it checks the release
candidate through a local module replacement; it does not claim that an
immutable remote tag has been tested.
