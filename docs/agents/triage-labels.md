# Triage labels

The engineering workflow uses five canonical roles. GitHub labels use the same
strings. Create these labels in the repository before relying on label-based
queries; do not invent per-agent variants.

| Canonical role | GitHub label | Meaning |
| --- | --- | --- |
| `needs-triage` | `needs-triage` | A maintainer must evaluate the request. |
| `needs-info` | `needs-info` | Waiting for reporter information or reproducible evidence. |
| `ready-for-agent` | `ready-for-agent` | Fully specified and safe for AFK implementation. |
| `ready-for-human` | `ready-for-human` | Requires a human decision, credential, spend, or implementation action. |
| `wontfix` | `wontfix` | Will not be actioned. |

An issue is `ready-for-agent` only when it names binding requirement IDs,
approved seams/invariants, acceptance evidence, declarative-infrastructure
impact, documentation impact, dependencies, and any external authority it
needs. A direct-main commit must not turn an under-specified issue into an
implicit decision.

Labels describe triage state, not completion. Close only after the acceptance
ledger evidence is green and the direct-main evidence record names the immutable
revision and proof level.
