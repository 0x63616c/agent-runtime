# Configuration reference

Status: M0 implemented foundation only.

All process configuration is constructed explicitly at a composition root and
validated once by `internal/runtimeconfig.New`. Domain and workflow code may not
read environment variables. Schema version `1` is the only accepted version.

| Field | Required behavior | Diagnostic form |
| --- | --- | --- |
| `version` | Must equal `1`. | `1` |
| `notifier.topic` | Empty selects, or an explicit value must equal, `https://ntfy.sh/0x63616c-ai-agant`. | Full allowlisted topic |
| `notifier.access_token` | Optional and delivered only to an explicit authorization sink. | `[REDACTED]` or `[NOT CONFIGURED]` |

No runtime environment loader or notifier network transport exists in M0.
JSON, formatting, diagnostics, structured logging, fuzz tests, and validation
errors must not disclose the token. A later operator-owned declarative Stack
will own the credential reference; this foundation does not create a Secret or
bootstrap infrastructure.
