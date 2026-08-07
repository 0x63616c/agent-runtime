# Configuration reference

Status: M0 notifier configuration and completion transport implemented; runtime
service configuration remains planned.

All process configuration is constructed explicitly at a composition root and
validated once by `internal/runtimeconfig.New`. Domain and workflow code may not
read environment variables. Schema version `1` is the only accepted version.

| Field | Required behavior | Diagnostic form |
| --- | --- | --- |
| `version` | Must equal `1`. | `1` |
| `notifier.topic` | Empty selects, or an explicit value must equal, `https://ntfy.sh/0x63616c-ai-agant`. | Full allowlisted topic |
| `notifier.access_token` | Optional and delivered only to an explicit authorization sink. | `[REDACTED]` or `[NOT CONFIGURED]` |

`cmd/milestone-notify` composes the fixed-topic network transport for milestone
completion operations. It retains a private crash-durable record before
delivery, uses a stable sequence identifier, and records retryable failures.
JSON, formatting, diagnostics, structured logging, fuzz tests, and validation
errors must not disclose the token. The declarative Stack owns the eventual
credential reference; the notifier does not create a Secret or bootstrap
infrastructure.
