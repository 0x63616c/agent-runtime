---
status: accepted
---

# Approval persistence and authority

Approval is first-release durable domain state, not an in-memory callback or a
UI-only pause. A pending Approval is persisted with bounded scope, actor
authority, expiry, and the Turn it governs. Approve, deny, expiry, and
cancellation are idempotent terminal decisions; workflow replay and worker
restart observe the same decision exactly once.

## Considered options

- Add Approval after the first release or keep it in workflow memory only.
- Treat a Tool call or UI response as implicit authorization.

## Consequences

Policy and the durable store decide authority before Tool execution. Public
events may report safe Approval state, but do not contain credentials or grant
authority. The implementation requires restart/replay and concurrent-decision
evidence before it can be claimed complete.
