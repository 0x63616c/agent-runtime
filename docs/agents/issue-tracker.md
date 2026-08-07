# Issue tracker: GitHub

Issues, program work, and PRDs for Agent Runtime live in GitHub Issues for
`0x63616c/agent-runtime`. Use the `gh` CLI from this checkout; it resolves the
repository from the `origin` remote.

## Direct-main build policy

This build intentionally lands directly on `main` and opens no pull requests.
GitHub Issues are therefore the durable request, design, and evidence surface:

- Create an issue before beginning a distinct deliverable. Include the
  requirement IDs, approved seams/invariants, acceptance evidence, declarative
  infrastructure impact, documentation impact, risks, and dependencies.
- Assign/claim the issue before its first external write. Keep one owner while
  active; split independent work into linked issues rather than overlapping a
  filesystem area.
- Before a direct-main push, comment the exact focused checks/evidence run and
  their result. After the push, add the immutable commit, proof level,
  limitations, evidence location, and next checkpoint.
- Close an issue only when its acceptance-ledger evidence is green. A blocked
  KVM runner, provider credential, notification delivery, or missing proof is
  visible as blocked; it is never silently converted into a pass.
- Do not force-push, rewrite published history, or use a PR as a substitute
  approval flow for this build. Correct mistakes with additive commits.

## Common operations

- Create: `gh issue create --title "..." --body "..."`
- Read with comments and labels: `gh issue view <number> --comments`
- List: `gh issue list --state open --json number,title,body,labels,assignees`
- Comment: `gh issue comment <number> --body "..."`
- Edit labels/assignees: `gh issue edit <number> --add-label "..." --add-assignee @me`
- Close after proof: `gh issue close <number> --comment "..."`

Use a heredoc or a checked-in issue body for multiline content. Do not place
credentials, raw prompts, raw tool output, internal backend IDs, or secret URLs
in an issue.

## Pull requests as a triage surface

**PRs as a request surface: no.** External PRs are not part of the AFK build
workflow. GitHub's shared issue/PR number space still applies: resolve a bare
number as a PR before treating it as an issue when ambiguity matters.

## Wayfinding and dependencies

A multi-session program map is one issue labelled `wayfinder:map`; child work
items are GitHub sub-issues (or a task list fallback) labelled
`wayfinder:research`, `wayfinder:prototype`, `wayfinder:grilling`, or
`wayfinder:task`. Express blockers using GitHub native issue dependencies when
available; otherwise write a `Blocked by: #<number>` line at the start of the
child issue. The live frontier contains open, unassigned child issues with no
open blockers.

When another engineering skill says to publish to or fetch from the issue
tracker, it means create or read a GitHub Issue using these conventions.
