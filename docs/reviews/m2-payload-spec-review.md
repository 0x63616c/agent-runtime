# M2 payload boundary review — specification axis

Status: failed on 2026-08-07; remediation is active. The review used issue
#13, PAY-001–PAY-008, TMP-005–TMP-006, the S3/S8 seams and ADR-0009.

1. TMP-005 was partial: the factory accepted an arbitrary Temporal client,
   its test applied client options twice rather than constructing a worker,
   and the source guard did not cover every raw SDK constructor.
2. TMP-006 was partial: startup compatibility was an optional self-round-trip,
   not an enforced gate that decoded retained compatible inline, zstd and
   remote payloads before accepting work.
3. PAY-008 was partial: two codec instances in one test package did not prove
   exchange between the runtime and a separate in-repository consumer.
4. PAY-002 lacked literal frozen inline and remote complete-wire size vectors.
5. PAY-005 exposed an eligibility-check/delete time-of-check-time-of-use window
   and lacked authoritative coordinated deletion evidence.

The review found no material scope creep. These findings block issue #13,
ledger completion and the M2 notification until fixed and independently
re-reviewed.

## Final independent re-review — 2026-08-07 UTC

Reviewed exact revision `676f69ecc8fd02260e247cb08e2cae3fa7814753`
against issue #13, PAY-001–PAY-008, TMP-005–TMP-006, S3/S8, ADR-0009,
the accepted architecture, and every earlier specification finding.

| Prior finding | Final disposition |
| --- | --- |
| TMP-005 allowed arbitrary clients and incompletely guarded raw constructors | Resolved. The runtime-owned Factory creates the Temporal client, workers accept only its checked client, and the AST guard covers current client/worker constructors through normal, aliased, dot-imported and function-value forms, including `NewNamespaceClient`. |
| TMP-006 startup compatibility was optional and did not decode retained forms | Resolved. `NewClient` must decode retained inline, zstd and remote vectors and verify current emission before dialing; the Factory exposes no unchecked converter accessor. |
| PAY-008 did not prove runtime-to-independent-consumer exchange | Resolved. A startup-gated Factory client and actual Temporal worker exchange inline, zstd and remote results through a Temporal development server; an independent public codec and the authorized UI handler decode each stored representation. |
| PAY-002 lacked literal complete-wire vectors | Resolved. Frozen inline, zstd and remote complete-wire vectors, including the remote stored-inner bytes and exact wire sizes, are retained and checked. |
| PAY-005 had a reference-eligibility/delete TOCTOU window | Resolved. One `RetentionCoordinator` operation owns authoritative reference fencing and conditional deletion/tombstone semantics; deterministic tests cover a reference created after listing and concurrent deletion. |
| Later correction exposed an unchecked Factory converter and unbounded compatibility I/O | Resolved. The accessor was removed, and remote-vector seed I/O uses the configured finite codec timeout. |

No new missing, partial, incorrectly implemented, or out-of-scope requirement was
found. **Final specification verdict: PASS — 0 P0, 0 P1, 0 P2 findings.**

Independently run against a clean archive of `676f69e`:

```text
go test -race ./temporalpayload/... ./internal/temporalpayloadruntime
go test ./tests/architecture
go test -race -tags=integration ./temporalpayload ./internal/temporalpayloadruntime
go vet ./temporalpayload/... ./internal/temporalpayloadruntime ./tests/architecture
git diff --check 676f69e^ 676f69e
```

All commands passed. The tagged run independently started the Temporal
development server. The real MinIO harness was not independently rerun in this
review; the retained MinIO record names its older tested revision and was not
used as proof for the corrected Factory, GC, guard, or two-consumer behavior.
Issue #13 and its ledger rows remain open/`in_progress`, so this PASS clears the
independent code/specification review gate but does not promote evidence, close
the issue, or authorize the M2 notification.
