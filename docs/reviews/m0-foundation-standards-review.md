# M0 foundation — standards review

Fixed point: `4439138` (only commit: `4439138 Initial commit`). Scope includes
the tracked README diff and every current untracked implementation file named
by the review brief. `just verify` and `go test -race ./...` pass; findings below
are standards/design findings that those tools do not enforce.

## Findings

1. **Hard violation — `Justfile:5-9`: the complete verification gate omits race
   detection.** `verify` runs `go test ./...`, while `AGENTS.md:198-199` requires
   race detection in the complete Go gate. The separate manual race run passing
   does not make the declared gate complete; add `-race` to the gate.

2. **Hard violation — `internal/nowait/check_test.go:21-30`: unit tests use the
   real filesystem.** `TempDir` plus three `os.WriteFile` calls directly violate
   the hermetic-unit rule forbidding filesystem access (`AGENTS.md:186-188`).
   The checked-in `testdata` files do not cure that path. Test an injected
   `fs.FS`/parser seam, or classify a filesystem-backed check as integration.

3. **Hard violation — `internal/nowait/check.go:23-42`: filesystem traversal is
   not cancellable.** `CheckDir(root string)` performs `WalkDir` without a first
   `context.Context`, contrary to the propagation/honouring rule
   (`AGENTS.md:151-153`).

4. **Hard violation — exported symbols lack required comments.** Examples are
   `Clock.Now` (`internal/clock/clock.go:12`), `Source.Next`
   (`internal/identity/identity.go:16`), `AuthorizationSink.SetBearerToken`
   (`internal/runtimeconfig/config.go:40`), and the exported enum constants,
   interface methods, `DeliveryFailure.Error`, `MemoryStore` methods, and
   `FakeNotifier.Deliver` in `internal/milestone/milestone.go:20-32,242-307,
   407-422,497-540,576`. This violates `AGENTS.md:201-203`.

5. **Hard violation — bare errors cross meaningful boundaries.** Examples are
   `internal/milestone/milestone.go:80-81,96-97,327-332,442-445,465-467,
   497-499`, `internal/identity/identity.go:89-91,102-104`, and
   `cmd/generate-requirement-manifest/main.go:20-22,36-37`. These return or print
   dependency/validation errors without action context, contrary to
   `AGENTS.md:154-158`.

6. **Hard violation — `internal/identity/identity.go:50-52`: unsafe unbounded
   input is copied into an error.** An arbitrary rejected identifier is quoted
   without a maximum length or redaction, conflicting with bounded, safe
   diagnostic data (`AGENTS.md:66-70,164-169`).

## Judgement-call smells

- **Divergent Change:** `internal/milestone/milestone.go` combines JSON parsing,
  catalog validation, estimation, delivery orchestration, storage, and test
  fakes. Split along the existing seams so each reason to change has one owner.
- **Primitive Obsession:** the same file models requirement IDs, milestone IDs,
  revisions, command IDs, artifact references, and evidence references as raw
  strings despite the typed-invariant preference (`AGENTS.md:64-67`).
- **Primitive Obsession:** `internal/runtimeerror/error.go:7` accepts a supposedly
  safe identity as an unchecked string; a safe typed/log-valued identity would
  enforce the promise at the boundary.

Summary: 6 documented-standard findings and 3 judgement-call smells; the worst
issue is the verification gate omitting its required race run.

## Final re-review — 2026-08-06 — PASS

Fixed point and scope are unchanged. The current implementation resolves every
prior standards finding:

| Prior finding | Final disposition |
| --- | --- |
| Race omitted from `verify` | Resolved: `Justfile` runs `go test -race ./...`. |
| Unit test used the OS filesystem | Resolved: `nowait` tests use `fstest.MapFS`. |
| Filesystem scan was not cancellable | Resolved: `CheckDir`/`CheckFS` take and honor `context.Context`. |
| Exported symbols lacked comments | Resolved: interfaces, methods, constants, fields, and added exported types have conforming comments. |
| Bare boundary errors | Resolved: affected identity, milestone, generator, store, and delivery boundaries add safe action context while preserving causes. Deliberately injected fake failures remain adapter results, and surrounding production boundaries classify/wrap them. |
| Invalid Session ID leaked input | Resolved: IDs have an exact bounded payload and rejection returns no caller value; a canary test proves redaction. |
| `milestone.go` Divergent Change | Resolved: types, ledger validation, report calculation, delivery, and fakes have separate files. |
| Milestone Primitive Obsession | Resolved: requirement, milestone, revision, command, artifact, and evidence references are typed. |
| Runtime-error Primitive Obsession | Resolved: `SafeIdentity` validates bounded safe text before wrapping/logging. |

The accepted command split is accurately enforced. `just check` passed,
including generated drift, module verification, race, vet, no-real-wait, and
catalog/ledger structural validation. `just verify` then correctly failed its
completion gate because required ledger rows are not green. Before failing it
emitted the complete report naming all 183 required rows and their statuses.
That expected failure is not itself a standards violation, and no completion or
notification is claimed.

The correction-only pass also resolves the sole later hard finding:
`cmd/ledger-report/main_test.go` now uses `testing.T` only for the conventional
Ginkgo suite entry point, with behavior expressed through Ginkgo `Describe`/`It`
and asserted through Gomega. The focused race test passes, and the file is
gofmt-clean with no whitespace errors.

No new unsuppressed Fowler smell was found. Similar bounded-string validators
remain intentionally local: the repository forbids grab-bag shared packages
and requires demonstrated reuse before extraction, so that documented rule
overrides a possible duplication smell.

**Final standards verdict: PASS — 0 hard findings, 0 judgement-call smells.**
