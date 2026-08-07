# Direct-main delivery runbook

Every change begins with one assigned GitHub Issue and ends with evidence on
that Issue. The atomic commit message/body names requirement IDs, approved
seams, documentation, and retained evidence references.

1. Add a behavior test at an approved seam and observe the intended failure.
2. Implement the smallest vertical slice; update owned docs and generated
   outputs without editing generated files by hand.
3. Run focused checks and `just check`. Record a `pre_push` AFK evidence entry
   against the immutable commit that will be pushed.
4. Push directly to `main` without force or history rewriting. Wait for the
   `main-ci` workflow for that exact revision.
5. Attach the uploaded bounded evidence artifact and immutable revision to the
   Issue. If CI is red, record `red_main_halt`, stop unrelated delivery, and
   repair with an additive commit.

The log schema is versioned JSON with bounded records. Events are
`local_check`, `pre_push`, `main_ci`, or `red_main_halt`. Each record names
requirements, seams, documentation paths, revision/source ref, UTC time, proof
scope, command ID, artifact reference, result, and limitations. It never embeds
argv output, logs, credentials, raw content, or backend identifiers. Validate a
retained file with:

```sh
go run ./cmd/afk-evidence -mode validate -file <evidence.json>
```

A local record is mutable partial evidence. Only a 40-character commit on
`refs/heads/main` can be immutable main evidence. Main CI uploads its safe JSON
record even when `just check` fails, then makes the workflow fail visibly.
