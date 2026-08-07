---
status: accepted
---

# Milestone status and ntfy reporting

Each milestone completion is retained as evidence and then posted to the typed,
operator-configured notifier topic `https://ntfy.sh/0x63616c-ai-agant`. The
secret-safe payload includes `milestone`, `estimated_overall_percent`,
`evidence_summary`, `next_milestone`, `commit_or_revision`, `utc_time` and
`status`. Percentages are labelled weighted-ledger estimates, not claims that
blocked work passed.

## Consequences

Regular reports use the same evidence model. Failed delivery remains a visible
failure/retry record and cannot claim a notification was sent. Test event
`GCXy4IYjJp96` confirms the corrected topic was reachable on 2026-08-06; it is not proof
of a milestone completion.
