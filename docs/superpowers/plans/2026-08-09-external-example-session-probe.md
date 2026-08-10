# External Example Session Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove that a non-UI example can consume the common Session lifecycle solely through the public Go SDK, without creating an application or runtime deployment.

**Architecture:** A `tests/architecture` specification writes a temporary independent Go module and runs its deterministic fake-backed consumer test. A small test-only AST reader rejects forbidden direct imports from that fixture. It adds no application source, public API, HTTP route, Stack profile, model, tool, durability, or documentation claim.

**Tech Stack:** Go standard library, Ginkgo/Gomega, external temporary Go module.

---

### Task 1: External common-session consumer fixture

**Files:**

- Modify: `tests/architecture/runtime_public_test.go`

- [x] Add a failing architecture specification that requires a temporary external consumer source for the common Session lifecycle.
- [x] Run `go test -race ./tests/architecture` and observe the missing fixture/helper failure.
- [x] Implement only a test-only fixture that typechecks a fake-backed `CreateSession → SendInput → Events(cursor resume) → InspectTurn → CancelTurn → CloseSession` sequence through `sdk/go`.
- [x] Run the focused architecture suite green.

### Task 2: Fixture direct-import guard

**Files:**

- Modify: `tests/architecture/runtime_public_test.go`
- Create: `tests/architecture/testdata/example_forbidden_import.go`

- [x] Add a failing negative specification and fixture for direct internal, Temporal, blob, sandbox-control, and test-route imports.
- [x] Run `go test -race ./tests/architecture` and observe the missing scanner failure.
- [x] Implement the minimal test-only AST import scanner and assert the external common-session fixture has no forbidden direct imports.
- [x] Run `go test -race ./tests/architecture` and `just check` green.
- [ ] Commit the atomic test-only slice and request independent review.
