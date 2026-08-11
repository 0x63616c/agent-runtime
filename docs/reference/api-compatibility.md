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
capabilities. The same gate retains the OpenAPI vocabulary baseline. Until a
version is published it checks the release candidate through a local module
replacement; it does not claim that an immutable remote tag has been tested.

## Unreleased compatibility decisions

### M7 approval lifecycle projection

`Approval.tool_call_id` and the `waiting_for_approval` Turn state are additive
v1 response vocabulary. The field makes the already durable Approval-to-Tool
call relationship observable without exposing a descriptor, capability,
credential, grant ID, or backend handle. The state makes the existing
non-terminal, cancellable approval wait observable. Existing SDK callers keep
the string-backed `TurnState` type and may continue ignoring additional
response fields; clients that validate response JSON must accept documented
additive fields and enum values. No existing route, request field, response
field, ID grammar, or enum member is removed or redefined.

`approval.expired` and `approval.cancelled` are additive v1 Product-event
vocabulary. `approval.resolved` continues to cover explicit approval and
denial; the new safe events distinguish automatic expiry from owner withdrawal
of a pending Approval. They expose only the existing ordered event envelope,
never an action descriptor, capability value, credential, grant ID, or backend
handle. Existing SDK callers retain the string-backed `EventKind` type and may
ignore unrecognized event kinds; strict event consumers must accept documented
additive enum values. No existing route, request field, response field, ID
grammar, or enum member is removed or redefined.

The M7 `requester`, `policy_revision`, `action`, and `scope` Approval
projection is required in the OpenAPI response schema. The runtime admits an
Approval only with that closed safe summary and bounded scope; it does not add
a request parameter or expose descriptors, capabilities, credentials, grants,
or backend handles.

Snapshots written by the earlier internal `RequestApproval` path can lack the
original action summary. They are deliberately rejected as durable-integrity
failures on store and public API reads rather than being projected with an
invented action. An operator must reconcile each affected snapshot from its
authoritative source (or safely retire the pending action) before the tenant
can resume reads; this is not an automatic migration and has no rollback
shortcut. This is an unreleased compatibility decision, not evidence of a
published version boundary.
