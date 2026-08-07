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
