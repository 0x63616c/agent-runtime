# Codex subscription support research

**Research date:** 2026-08-06
**Scope:** M6, `MOD-001`–`MOD-005`, ADR-0004, and GitHub issue #26
**Evidence level:** official-source research and read-only local CLI inspection;
not a live authentication or model canary

## M6 start re-verification (2026-08-11)

The official App Server page was re-read at M6 start. It still describes App
Server as a deep Codex-agent integration (authentication, conversation
history, approvals, and streamed agent events), not a provider-neutral raw
model protocol. More importantly, it still states that the App Server command
and WebSocket transport are experimental and unsupported for production
workloads. The official authentication and feature-maturity pages were also
re-read. No stable, production-supported subscription-backed `Model` surface
with a verified no-Codex-tools boundary was found.

Accordingly, M6 now has a deterministic, fail-closed support-assessment seam
at `internal/providers/codexsubscription`. It accepts only bounded, non-secret
review metadata and refuses composition until all of the following are
independently evidenced: official production support, a model-only tool
boundary, isolated credential identity, and protected-canary authority. It
does not parse, copy, refresh, or transmit credentials and it cannot fall back
to an API key. This advances the visible-blocked behavior required by
`MOD-001`; it is not a Codex adapter or `MOD-005` canary evidence.

## Decision

**The required production Codex-subscription `Model` adapter is currently
blocked.**

OpenAI now documents genuine subscription-capable integration surfaces. In
particular, Codex App Server is described as the interface for embedding Codex
into a product, and it exposes Codex-managed ChatGPT browser/device login,
account state, automatic token persistence/refresh, rate-limit state, threads,
turns, approvals, and streamed events. This is materially stronger support
than an undocumented ChatGPT backend.

It does not yet close this runtime's release gate:

1. The installed official CLI labels `app-server` experimental, and OpenAI's
   App Server guide says the app-server command and WebSocket transport are
   experimental and unsupported for production workloads. OpenAI defines an
   experimental feature as unstable and use-at-own-risk, not production-safe.
2. App Server, the Codex SDKs, `codex exec`, and the MCP server control a
   complete coding agent. They do not expose a provider-neutral raw model
   invocation. Codex owns threads, command execution, file changes, approvals,
   tools, and local history. The custom/dynamic tool surface is itself
   experimental.
3. No confirmed stable switch in the reviewed official interface disables all
   Codex-owned executable tools while retaining subscription-backed model/tool
   calling for this runtime's own Tool broker. Running Codex beside its
   credential store while model-directed shell/file tools remain possible
   would violate the intended model-role/tool-role separation unless a proven
   outer isolation boundary prevents access.
4. OpenAI documents ChatGPT-managed auth for local Codex use and selected
   trusted automation. It explicitly warns against the `auth.json` CI/CD
   workflow for public/open-source repositories. Business/Enterprise Codex
   access tokens are documented for trusted local/app-server automation, but
   they do not establish a Plus/Pro multi-tenant service credential model.
5. Personal account credentials cannot be shared or used to make one account
   available to unrelated users. A public self-hosted runtime therefore cannot
   pool an operator's personal subscription across tenants. Each human user
   would need their own authenticated and isolated Codex identity, or a
   business/workspace identity explicitly authorized for that workflow.

The project may design a **local, single-user experimental preview** around a
pinned official Codex App Server over stdio, with Codex itself owning OAuth and
token refresh. That preview is not `MOD-001` production evidence and cannot
make M6 or the release green. Implementation of an undocumented OAuth flow,
direct reuse of ChatGPT tokens against an inferred Responses endpoint, or an
API-key substitute is rejected.

The block can be reconsidered when at least one of these becomes true:

- OpenAI marks a suitable App Server/SDK surface stable and production
  supported, with a stable way to prevent Codex-owned tools from bypassing the
  runtime Tool broker and credential boundary; or
- OpenAI documents a subscription-authenticated model/tool protocol intended
  for third-party production runtimes; or
- the project explicitly changes architecture from a provider-neutral
  `Model` adapter to a distinct nested `CodexAgent` integration, with new
  requirements, threat model, lifecycle, and user authorization. That is a
  scope/architecture change, not a transparent implementation of `MOD-001`.

## Confirmed official facts

### Subscription and authentication

- OpenAI documents two local OpenAI sign-in modes: ChatGPT sign-in for
  subscription access and API-key sign-in for usage-based access. ChatGPT
  workspace permissions, RBAC, retention, and residency controls apply to the
  former. See [Codex authentication](https://developers.openai.com/codex/auth/).
- App Server's stable auth/account surface includes `account/read`,
  `account/login/start`, login completion/update notifications, login cancel,
  logout, and ChatGPT rate-limit reads. In ChatGPT-managed mode, Codex owns the
  OAuth flow, persists tokens, and refreshes them automatically. Browser and
  device-code starts are documented. See [App Server auth
  endpoints](https://developers.openai.com/codex/app-server/).
- Device-code authentication is beta and may require the user or workspace
  administrator to enable it. Browser login uses a localhost callback; OpenAI
  documents SSH forwarding and credential-cache copying as headless fallbacks.
- Codex can cache credentials in `auth.json` under `CODEX_HOME`, an OS keyring,
  or an automatic choice. OpenAI says the file contains access tokens and must
  be treated like a password. The CLI and IDE extension share the same cached
  login by default; logout in one affects the next use of the other.
- `chatgptAuthTokens`, where a host app supplies and refreshes ChatGPT tokens,
  is explicitly experimental. It is not an acceptable escape hatch for this
  release.
- Codex access tokens are documented for ChatGPT Business and Enterprise
  workspaces. They are user/workspace-bound agent identities for trusted local
  CLI or App Server automation, must be secret-managed and rotated, and must
  not run on public/forked/untrusted runners. See [Codex access
  tokens](https://learn.chatgpt.com/codex/enterprise/access-tokens).

### Integration surfaces

| Surface | Officially documented purpose | Subscription-capable | M6 fit |
| --- | --- | --- | --- |
| `codex exec --json` subprocess | Non-interactive coding-agent automation with JSONL events, resume, sandbox and approval settings | Reuses saved ChatGPT auth | Not a raw Model seam; Codex may perform its own commands/tools. Useful only as a constrained compatibility canary or separate nested-agent product. |
| Codex App Server over stdio | Embed Codex into a product with auth, history, approvals and streamed agent events | Yes; Codex-managed browser/device OAuth | Best protocol candidate, but the command is currently experimental/unsupported for production and represents a complete Codex agent. |
| App Server over WebSocket | Remote App Server transport | Yes | Explicitly experimental/unsupported; reject for production. stdio is the only candidate boundary. |
| TypeScript Codex SDK | Server-side control of local Codex threads | Reuses local Codex runtime/auth | Official application integration, but it is a coding-agent SDK, not Go and not a raw model provider. |
| Python Codex SDK | Controls pinned local App Server via JSON-RPC | Reuses local Codex runtime/auth | Beta and still inherits App Server semantics/maturity. It can inform a Go protocol adapter but is not itself release evidence. |
| Codex MCP server | Use Codex as a specialist from another orchestrator | Reuses Codex auth | Explicitly experimental; semantically a nested agent/tool, not a Model adapter. |
| Direct OAuth/device implementation | None for third-party runtimes; App Server/CLI own the documented flows | Inferred only | Reject. Do not copy client IDs, exchange/refresh tokens, or call inferred endpoints. |
| Platform Responses API | Supported model API with API credentials | No subscription-billing substitute confirmed | Useful for deterministic/API-key work only; cannot satisfy `MOD-001`. |

Sources: [App Server](https://developers.openai.com/codex/app-server/),
[Codex SDK](https://developers.openai.com/codex/sdk/), [non-interactive
mode](https://developers.openai.com/codex/noninteractive/), and [Codex MCP
server](https://developers.openai.com/codex/mcp-server/).

### Protocol and maturity

- App Server uses a version-generated JSON-RPC/JSONL schema over stdio. The
  CLI can generate stable-only JSON Schema matching its exact installed
  version; experimental fields require explicit opt-in.
- The documented stable thread/turn surface still describes a full agent:
  thread and turn lifecycle, command/file items, built-in approvals, sandbox
  settings, history, and event notifications.
- `dynamicTools` and the corresponding tool-call flow require experimental API
  opt-in. They cannot back the runtime's stable Tool broker contract.
- The official maturity guide defines experimental features as unstable and
  potentially removable, while stable features are the production-safe tier.
  See [feature maturity](https://learn.chatgpt.com/codex/feature-maturity).

### Terms and account boundaries

- OpenAI's App Server and SDK documentation expressly invite product and
  application integrations. That supports building against the documented
  surfaces; it does not upgrade an experimental surface to production support.
- Individual [Terms of Use](https://openai.com/policies/terms-of-use/) prohibit
  sharing account credentials or making one account available to someone else,
  and prohibit bypassing restrictions/rate limits. The terms also contain a
  broad restriction on programmatic extraction, while OpenAI separately
  documents Codex SDK/App Server automation. This research does not attempt a
  legal interpretation beyond using only documented product surfaces and
  refusing account pooling, scraping, or restriction bypass.
- The [OpenAI Services Agreement](https://openai.com/policies/services-agreement/)
  has different business/customer application provisions. A self-hosted
  operator must follow the agreement attached to the authenticating account
  and workspace; this project cannot claim one credential model fits personal,
  Business, Enterprise, and Edu accounts.

## Read-only local inspection

The installed official standalone CLI was inspected without running login,
logout, auth status, device flow, model requests, or credential diagnostics.

| Item | Observed |
| --- | --- |
| CLI | `codex-cli 0.146.1`, official standalone package, Apple ARM64 |
| Login CLI | Browser/default login, `--device-auth`, stdin API key, and stdin access-token entrypoints are present |
| App Server | Command is labelled `[experimental]`; stdio, Unix socket, and experimental WebSocket transports are present |
| Schema | Exact-version JSON Schema/TypeScript generation commands are present |
| Automation | `codex exec --json`, `--ephemeral`, `--ignore-user-config`, `--ignore-rules`, resume, sandbox, and approval controls are present |
| MCP | `codex mcp-server` is present; official source labels its interface experimental |

No credential file, keyring entry, token, account identity, workspace identity,
login state, or user configuration was read.

## Confirmed constraints versus inferences

### Confirmed

- Codex-managed ChatGPT login and automatic refresh exist in App Server.
- Credential file/keyring storage is configurable; `auth.json` contains access
  tokens and is security-sensitive.
- Business/Enterprise Codex access tokens support trusted App Server/CLI
  automation.
- App Server embeds a complete Codex agent and currently carries an
  experimental/unsupported-for-production warning.
- WebSocket, MCP, external ChatGPT-token injection, and dynamic tools are
  experimental in the reviewed official material.
- OpenAI warns not to use the ChatGPT-managed `auth.json` CI/CD workflow for a
  public/open-source repository.

### Inferences requiring proof or OpenAI clarification

- A self-hosted single-user application can likely launch one pinned App Server
  per authenticated principal and remain within the intended “embed into your
  product” use case. That is an inference until tested and, for a production
  support claim, until the experimental warning is removed or clarified.
- Sharing one App Server/Codex home across tenants would mix credentials,
  history, config, rate limits, and logout. The design must isolate them even
  if the protocol could technically multiplex threads.
- A model-driven Codex command may be able to read files available to the
  App Server process, including a file-backed credential cache, unless an
  independently proven boundary denies it. No reviewed official setting
  establishes the complete no-built-in-tools/credential-isolation property the
  runtime requires.
- Translating Codex thread events into Model deltas does not make Codex a raw
  Model adapter. Its retry, history, tool, approval, and cancellation semantics
  could conflict with the runtime's own durable state unless explicitly
  redesigned as a nested agent.

## Credential lifecycle contract if the block is later cleared

The runtime must delegate ChatGPT OAuth/token refresh to the pinned official
Codex process. It must never parse, export, refresh, copy, or log tokens itself.

1. Allocate an isolated credential/context directory or supported keyring
   identity per authenticated principal and environment. Never share it across
   tenants or unrelated users.
2. Run exactly one refresh-owning Codex process per credential context, or use
   a documented Codex-safe locking/daemon topology. Runtime “single writer”
   means process/lease ownership, not a second refresh implementation.
3. Mount the credential context only into the model-role process. Do not mount
   it into runtime sandboxes, examples, tool workers, API pods, tests, or docs.
4. Expose only redacted source identity and safe account state through runtime
   operator diagnostics. Browser auth URLs and one-time device codes are
   shown only to the authenticated initiating user, bounded by login ID and
   expiry, and excluded from logs/evidence.
5. Treat App Server logout as the documented local operation; do not claim
   remote token revocation unless a current official surface proves it. For
   Business/Enterprise access tokens, follow their explicit rotate/revoke
   lifecycle.
6. Pin the Codex runtime version and artifact digest, generate and retain its
   stable-only schema, reject unexpected versions/schema, and re-run this
   official-source review on upgrades.

This conflicts with any design that copies a developer's `~/.codex/auth.json`
into a Kubernetes Secret or lets the runtime own token refresh. ADR-0004 and
`MOD-003` correctly forbid credential values in declarative state.

## Acceptance-test implications

### Evidence that can be built now without credentials

- A fake App Server contract fixture for initialize, account state, browser and
  device login start/cancel/completion, rate-limit state, thread/turn events,
  terminal success/failure, disconnect, malformed frames, overload, and
  version/schema mismatch.
- A pinned-binary manifest and stable-only generated-schema drift test.
- Static/process isolation tests proving no provider token is accepted by the
  Go adapter, no credential value enters config/Temporal/PostgreSQL/events/
  logs/artifacts, and only the model role can access the opaque credential
  context.
- A capability test that fails closed while Codex-owned command/file/tool
  execution cannot be completely disabled or externally isolated.
- Normalization tests proving a disconnect never becomes a false terminal
  Turn result and provider IDs/items stay private diagnostics.

These tests may advance the adapter seam but do not turn `MOD-001` or
`MOD-005` green.

### Protected live canary requirements

A canary is allowed only after the production-support and tool/credential
boundary block is resolved. It must:

1. run on a dedicated trusted runner or operator-owned machine, never an
   untrusted fork/PR job and never beside arbitrary repository-controlled
   build scripts;
2. use one authorized test user/workspace identity, never a shared personal
   subscription for application tenants;
3. prefer a documented Business/Enterprise Codex access token for non-
   interactive automation where available; a personal ChatGPT login can be a
   manual local proof but must not seed `auth.json` into this public repo's CI;
4. pin the Codex artifact/version/schema, use an empty isolated workspace,
   disable user config/rules/plugins/MCP, request the least execution authority,
   and execute only a fixed benign prompt;
5. retain only revision, CLI version/digest, schema digest, auth mode category,
   plan category if safe, timestamps, normalized event kinds, terminal state,
   bounded usage/rate-limit class, and redacted error class; and
6. retain explicit negative proof that no prompt, output, OAuth URL, device
   code, token, account/email/workspace ID, raw provider event, filesystem
   content, or internal thread/request ID was uploaded.

The canary proves one supported identity worked at one time. It does not prove
terms compliance, all plan types, long-term protocol compatibility, or the
runtime Tool-broker security boundary.

### Ledger disposition on 2026-08-06

| Requirement | Current disposition | Reason |
| --- | --- | --- |
| MOD-001 | **Blocked** | Official subscription-capable integration exists, but the candidate App Server production/tool boundary is not stable/supportable enough for the runtime Model seam. |
| MOD-002 | Research only | Event shapes exist; durable normalization/finalization is unimplemented and untested. |
| MOD-003 | Policy supported, evidence absent | Official storage guidance supports opaque model-role-only ownership; no runtime isolation test exists. |
| MOD-004 | Partially specified | Codex can own login/refresh/cancel/logout. Runtime single-writer/isolation/revocation semantics remain unimplemented; external token injection is rejected. |
| MOD-005 | **Blocked** | No live canary was run, and a canary cannot override the production/tool-boundary blocker. |

## Required follow-up

1. Ask OpenAI, through an official support/channel appropriate to the user's
   account, whether a third-party public self-hosted product may rely on App
   Server stdio with ChatGPT subscription auth in production, and whether a
   stable no-built-in-tools mode or provider-level model/tool protocol is
   available/planned.
2. Keep issue #26 open and blocked on that answer or official maturity change.
3. Do not import Software Factory's direct Codex Responses/OAuth client. It is
   superseded by official Codex-owned auth surfaces for any future preview.
4. If the user accepts a nested Codex agent rather than a Model adapter, write
   a new ADR and requirements before implementation. Do not hide that semantic
   change inside the provider package.
5. Re-run this official-source audit against the exact pinned Codex release at
   M6 start and immediately before the protected canary/release.

## Official sources consulted

- [Codex authentication](https://developers.openai.com/codex/auth/)
- [Codex App Server](https://developers.openai.com/codex/app-server/)
- [Codex SDK](https://developers.openai.com/codex/sdk/)
- [Codex non-interactive mode](https://developers.openai.com/codex/noninteractive/)
- [Use Codex with the Agents SDK / MCP server](https://developers.openai.com/codex/mcp-server/)
- [Codex feature maturity](https://learn.chatgpt.com/codex/feature-maturity)
- [Codex access tokens](https://learn.chatgpt.com/codex/enterprise/access-tokens)
- [Using Codex with your ChatGPT plan](https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan)
- [OpenAI Terms of Use](https://openai.com/policies/terms-of-use/)
- [OpenAI Services Agreement](https://openai.com/policies/services-agreement/)
- [OpenAI Codex App Server source documentation](https://github.com/openai/codex/blob/main/codex-rs/app-server/README.md)
- [OpenAI Codex MCP interface source documentation](https://github.com/openai/codex/blob/main/codex-rs/docs/codex_mcp_interface.md)
