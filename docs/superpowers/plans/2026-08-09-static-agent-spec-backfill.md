# StaticAgentSpecBackfillV1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional, validated, render-only StaticAgentSpecBackfillV1 Stack declaration that cannot apply or deploy infrastructure.

**Architecture:** The declaration is top-level and independent of Stack profiles and generic Kubernetes resources. Legacy v1 Stack documents remain valid when absent; a dedicated compiler validates only pinned, non-secret static facts and emits a canonical `not_applied` plan.

**Tech Stack:** Go, standard JSON encoding, CockroachDB errors, Ginkgo/Gomega, AgentSpecBackfill CRD generator.

---

### Task 1: Optional declaration and CRD provenance

**Files:**

- Modify: `internal/stack/spec.go`
- Create: `internal/stack/agentspecbackfill.go`
- Test: `internal/stack/agentspecbackfill_test.go`

- [x] Write a failing parse test for legacy absence and a wrong CRD digest.
- [x] Run `go test -race ./internal/stack -run TestStack` and observe the missing declaration seam.
- [x] Add the optional top-level parser field and validate its declared digest against `agentspecbackfillcrd.Render()`.
- [x] Run the focused test green.

### Task 2: Static authority validation

**Files:**

- Modify: `internal/stack/agentspecbackfill.go`
- Test: `internal/stack/agentspecbackfill_test.go`

- [x] Write failing table tests for mutable image, duplicate route, absent retention, and raw DSN.
- [x] Run the focused test red.
- [x] Require immutable controller image/config digests, fixed identities, unique fixed routes/ports, RBAC and credential digests, 30–3650 day retention, and complete unique teardown inventory.
- [x] Run the focused test green.

### Task 3: Deterministic render-only plan

**Files:**

- Modify: `internal/stack/agentspecbackfill.go`
- Test: `internal/stack/agentspecbackfill_test.go`

- [x] Write a failing test for `RenderStaticAgentSpecBackfill`, canonical output, digest, and `not_applied: true`.
- [x] Run the focused test red.
- [x] Implement the compiler without calling `RenderKubernetes`, `KubectlAdapter`, `stackctl`, or a provider.
- [x] Run `go test -race ./internal/stack` and `just check` green; commit the atomic slice.
