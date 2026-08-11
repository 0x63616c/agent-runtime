# Public documentation stack and refresh contract

**Status:** accepted design; M0 site foundation and refresh skill implemented
for DOC-005/DOC-008, with #34 retaining publication revalidation ownership.
**Owns:** DOC-001--008, plus documentation checks for API, deployment, examples, and milestone notifications.
**Decision date:** 2026-08-06.
**Research standard:** linked sources are current official primary documentation checked on the decision date.

## Decision

Create a TypeScript Astro **7.2.0** + Starlight **0.41.7** site in `website/`; deploy its `website/dist/` with GitHub Pages' native artifact workflow; use npm with a committed lockfile; and run Node **24 LTS**. Pin Astro and Starlight to exact compatible versions. Use `npm install` only for intentional dependency updates and use `npm ci` in all repeatable commands and CI jobs.

`docs/` remains private planning/engineering material. `website/` is the public-site source root, preventing unfinished design from being published. Generated reference comes from passing source contracts, typed config, and declarative deployment assets. Curated concepts, tutorials, security limits, and runbooks are human-owned and evidence-mapped.

| Decision | Official source | Consequence |
|---|---|---|
| Astro 7.2.0, Starlight 0.41.7, Node 24, TypeScript | [Starlight getting started](https://starlight.astro.build/getting-started/) specifies the Astro/Starlight project model and `src/content/docs/` source convention. | Use the exact compatible Astro/Starlight pair and reject Node <24. |
| Node 24 and lockfile install | [Node releases](https://nodejs.org/en/about/previous-releases) lists Node 24 as LTS; [GitHub Node CI](https://docs.github.com/en/enterprise-cloud@latest/actions/tutorials/build-and-test-code/nodejs) describes `npm ci` as lockfile-preserving. | Record Node 24 in .nvmrc, package engines, and CI. Keep one package-lock.json. |
| Pages deployment | [GitHub Pages custom workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages) specifies configure-pages, upload-pages-artifact, deploy-pages, permissions, and deployment environment. | Upload the build output; do not write a gh-pages branch. |
| Links and legacy routes | [Astro routing](https://docs.astro.build/en/guides/routing/) documents static configured redirects. | Keep current `/docs/...` URLs, explicitly redirect historic absolute routes, and assert all rendered route files through the checked route manifest. |
| Search | [Starlight site search](https://starlight.astro.build/guides/site-search/) documents its default static Pagefind index. | Build local static search into the Pages artifact with no crawler or third-party query service. |
| Go reference | [Go doc comments](https://go.dev/doc/comment) identifies doc comments as input to go doc, pkg.go.dev, and local pkgsite. | Go doc comments are canonical SDK-reference input. |
| HTTP reference | [OpenAPI Specification](https://spec.openapis.org/oas/) is the primary OpenAPI source. | The validated checked-in OpenAPI document is canonical HTTP-reference input. |

## Information architecture

Use one `current` documentation version until the first compatible public release. Pre-release versions add drift without a supported contract. Each release then contains its matching OpenAPI and Go SDK snapshot.

    Start here                 overview, safety boundary, five-minute start
    Concepts                   Session, Turn, event, tool, approval, artifact
    Build and run              local Tilt, configuration, deployment, operations
    Reference                  HTTP/OpenAPI, Go SDK, config/deployment catalog
    Security and reliability   sandbox profiles, capabilities, evidence classes
    Extend                     models, tools, sandbox backends, migration
    Examples                   Durable Chat, Workspace Agent, Research Dossier
    Help                       troubleshooting, FAQ, support, changelog

`website/src/content/docs/docs/reference/generated/` contains generator-owned pages only. Curated reference introductions describe semantics and compatibility, but never duplicate endpoint, field, or error definitions.

## Reference integration choices

| Need | Options assessed | Decision |
|---|---|---|
| OpenAPI pages | Starlight plugin; separate hosted interactive UI; repository renderer from a validated spec. | Choose a small repository renderer so schema rendering stays an explicitly owned repository contract. Emit operations, parameters, requests, responses, errors, schemas, and downloadable openapi.yaml. |
| Go SDK pages | Only link pkg.go.dev; run pkgsite; static generation from public Go docs. | Publish released modules on pkg.go.dev and generate package/symbol/index pages with go list, go/doc, and go doc -all. Pkgsite is a local developer convenience, never production infrastructure. |
| Examples | Hand-copied snippets; generated clients; executable public-contract examples. | The three apps in examples/ are the single runnable source. Pages link named fixtures instead of copying their implementation. |

The HTTP renderer fails on an invalid or stale spec. The Go renderer fails when a declared public package cannot be listed, lacks a package comment, or has an undocumented exported symbol. Both exclude internal packages and adapter implementation types.

## Declarative configuration, deployment, and notification reference

Every operator-visible configuration/deployment field has an explicit desired-state record in checked-in `deploy/catalog.yaml`. It is a declarative ownership registry, not a hidden setup script.

    id: runtime.notifications.ntfy.topic-url
    kind: config
    schema: internal/config/Notifications.NtfyTopicURL
    desiredState:
      dev: deploy/dev/values.yaml#/notifications/ntfy/topicURL
      production: deploy/production/runtime.yaml#/notifications/ntfy/topicURL
    owner: runtime-platform
    lifecycle:
      create: declarative apply
      reconcile: deployment controller / Tilt development loop
      rotate: restart after approved value or Secret reference change
      teardown: delete with owning instance namespace/release
    secret: false
    examples: [examples/research-dossier]

The catalog is checked against:

1. Typed Go config declarations: ID, type, default, validation, scope, and secret/reference class.
2. Rendered development and production desired state. Any field reaching an environment, volume, service, resource/policy setting, or Secret reference without catalog ownership fails.
3. Public OpenAPI configuration schema, where exposed.
4. Generated docs, including desired-state owner and full lifecycle.

`docsgen deployment` renders the public config/deployment catalog: source path, precedence, default, requiredness, secret treatment (reference only), role, affected example, owner, and lifecycle. It never renders secret values. This is the generated reference required for **every** deployment/config field.

### Milestone completion notifications

The operator guide includes an explicit Notifications.Ntfy page generated from the same catalog. Ntfy is an operator-configured delivery adapter, not hard-coded library behaviour. This build's declarative profile records the specified topic URL; runtime code receives it only through resolved role configuration, and uses a normalized notifier interface with no topic literal.

Document and test this redacted payload:

    {
      "milestone": "M4 — Firecracker execution",
      "estimated_overall_percent": 40,
      "evidence_summary": ["bounded evidence reference"],
      "next_milestone": "M5 — durable agent runtime",
      "commit_or_revision": "immutable revision",
      "utc_time": "RFC3339 UTC time",
      "status": "completed"
    }

- `milestone` is the stable ledger/milestone identity/display name;
  `estimated_overall_percent` is a bounded weighted-ledger estimate, not a
  release-completion claim.
- `evidence_summary` contains bounded evidence references and status only:
  never raw prompts, artifacts, secret values, headers, provider payloads, or
  unbounded logs. `next_milestone` is the declared next milestone or `none`.
- `commit_or_revision` is the immutable source revision; `utc_time` is the
  recorded UTC completion time; `status` is the retained delivery status. No
  payload contains a credential-bearing URL, credential, token, secret or
  internal backend ID.
- Topic URL exposure is catalogued. Where it is sensitive, declare it as a Secret reference and render only reference path plus rotation/restart lifecycle.
- Persist completion-candidate evidence before delivery. Delivery is
  idempotency-keyed by milestone/evidence revision, bounded by timeout/retry
  policy, and records a redacted audit result. A milestone is recorded complete
  only after the successful notification is retained. Delivery failure preserves
  the candidate evidence as a visible retryable release-operations failure; it
  cannot claim completion or a sent notification.
- Unit tests prove exact safe payload/redaction and no call before milestone completion. HTTP contract tests use an httptest ntfy-shaped endpoint for topic, headers, idempotency/retry and failure behaviour. Retain the already-successful live test as dated operational evidence, not as a substitute for repeatable proof.

Deployment documentation presents only canonical declarative paths: `just dev`, `just dev-down`, reviewed deploy inputs, and documented CI/Tilt invocations. Docs validation rejects instructions requiring ad-hoc kubectl mutation, copied Secrets, manual cloud state, permanent port-forward daemons, or hidden local config. `just dev-preflight` may inspect/fail with a remedy but must not install software, change Kubernetes context, or mutate a cluster.

## Proposed repository tree

    website/
    ├── package.json                         # npm only; exact Astro/Starlight versions
    ├── package-lock.json
    ├── astro.config.mjs                     # sidebar, redirects, Pages URL/base path
    ├── route-manifest.json                  # current and legacy rendered-route evidence
    ├── scripts/check-routes.mjs
    ├── src/{content,styles,pages}/
    ├── static/reference/openapi.yaml         # generated exact HTTP contract
    ├── src/content/docs/docs/
    │   ├── {start-here,concepts,build-and-run,security,extensions,examples,help}/
    │   └── reference/
    │       ├── overview.mdx                  # curated
    │       └── generated/
    │           ├── http/{index,operations,schemas}.mdx
    │           ├── go-sdk/{index,packages,symbols}.mdx
    │           └── configuration/{index,roles,fields}.mdx
    ├── docs-coverage.yaml                    # topic -> page/evidence/source
    ├── snippets.yaml                         # snippet classification/fixtures
    └── cspell-project-words.txt

    api/openapi/openapi.yaml                  # validated canonical HTTP contract
    deploy/catalog.yaml                       # ownership/lifecycle registry
    deploy/{dev,production}/                  # desired-state assets
    examples/                                 # runnable public-contract apps
    sdk/go/                                   # public Go module

    skills/
    ├── refresh-agent-runtime-docs/
    │   ├── SKILL.md
    │   ├── source-manifest.json
    │   ├── references/regeneration.md
    │   └── scripts/refresh-docs/
    └── develop-with-agent-runtime/
        ├── SKILL.md
        ├── source-manifest.json
        └── references/runtime-map.md         # generated capability map

    tools/{docsgen,doccheck}/
    .github/workflows/{ci,docs-pages}.yml

The source manifest is an allow-list, not a broad scan. Every output names its input paths, renderer version, artifact kind, source contract/evidence, and public status. It also declares curated markers, coverage/snippet fixtures, external-link exception ownership, and validation commands. Renderers may read only declared paths.

## refresh-agent-runtime-docs skill contract

This adopts dimensions' refresh-dims-skill pattern, widened to the public runtime. It is tested executable policy, not a prose reminder. Its SKILL.md treats current passing source/contracts/examples as truth and never describes proposed routes, config, profiles, commands, notifications, or security claims as implemented. Trigger it for every public capability, OpenAPI, SDK, config, deployment asset, example, command, troubleshooting path, milestone notification, or security/evidence change.

The deterministic runner:

1. Resolves root, schema-validates the manifest, and rejects paths outside root or the output allow-list.
2. Runs prerequisite contract checks: OpenAPI, public Go discovery, typed config, and rendered deployment/catalog consistency.
3. Renders in memory in stable sorted order; timestamps, machine paths, random IDs, secret values, and environment values are banned.
4. In `--check`, compares bytes only and fails missing/stale output. It never writes, creates directories, or formats.
5. Refuses to replace any existing untracked output or selected tracked output with differing staged or unstaged edits. A genuinely missing output may be created. Preserve complete `BEGIN/END curated-NAME` byte ranges; print a labelled, unapplied patch proposal when evidence suggests curated prose change.
6. Writes only changed allow-listed files with same-directory temporary file, fsync/close/atomic rename. Failure leaves no partial tree; unchanged repeat has no diff.
7. Runs `just docs-check` and only then prints exact unfiltered `git diff --no-ext-diff HEAD -- website/ skills/refresh-agent-runtime-docs/ skills/develop-with-agent-runtime/ deploy/catalog.yaml`, followed by bounded rendering of existing untracked files. Missing git state is reported, never claimed as reviewed.

No success marker is written. The byte comparison and exact final diff are the evidence.

| Renderer | Inputs | Outputs | Failure rule |
|---|---|---|---|
| HTTP | Validated OpenAPI + manifest | raw spec, operation/schema MDX | Invalid/stale spec, undocumented operation/schema/error, altered generated output |
| Go | public sdk/go, go list, AST/docs, manifest list | package/symbol MDX, capability map | Internal package, missing docs, unstable order, unlisted export |
| Deployment | typed config, catalog, rendered dev/prod state | config/role/field docs | Missing/duplicate field, unowned desired state, secret value, catalog mismatch |
| Notifications | notifier config, catalog, milestone model/fixtures | ntfy operator/config/payload docs | Hard-coded topic, unsafe payload field, unclassified failure policy |
| Coverage/claims | requirements ledger, coverage map, evidence annotations | check-only reports | Missing DOC topic/evidence class/example/claim owner |

## Links, snippets, commands, and CI

Astro Starlight production build plus the explicit route manifest is the
implemented deterministic internal link/route gate. #34 adds the bounded external-link checker and requires each
exception to name an owner, reason, and expiry; it cannot weaken internal build
checking.

When runnable public capabilities arrive, each fenced sh, bash, console, go,
json, yaml, and HTTP block will have a stable ID in `website/snippets.yaml` and
be one of:

- **run:** hermetic executable fixture and expected result;
- **compile:** extracted parsed/compiled fixture;
- **verify-only:** redacted/destructive operator command, syntax-checked and linked to exact integration/E2E proof;
- **non-executable:** diagram/pseudocode only, with rationale.

#34 will add `tools/doccheck`, reject unclassified blocks, and execute fixtures
in a temporary checkout with timeout and no ambient credentials. A real local
stack is permitted only through a named just fixture that starts and cleans it
up. The three tutorials will run actual public SDK/HTTP demos. Formatting,
spelling, MDX validation, production build, and browser
accessibility/navigation smoke then become one publication gate.

Implemented M0 documentation commands:

    just docs
      npm --prefix website ci
      npm --prefix website run start

    just docs-generate
      go run ./skills/refresh-agent-runtime-docs/scripts/refresh-docs --root .

    just docs-check
      go run ./skills/refresh-agent-runtime-docs/scripts/refresh-docs --root . --check
      npm --prefix website ci
      npm --prefix website audit --omit=dev --audit-level=high
      npm --prefix website run typecheck
      npm --prefix website run build
      npm --prefix website run check:routes

ci.yml runs `just docs-check` on every default-branch push with exact Node 24
and an npm cache keyed by `website/package-lock.json`. This direct-main build
does not add a pull-request-only gate. GitHub documents setup-node caching for
npm/Yarn/pnpm and warns against cached secrets; cache dependencies only.

docs-pages.yml has build/deploy jobs. Default-branch/manual runs build and
upload `website/dist` using upload-pages-artifact. GitHub Pages is enabled with
GitHub Actions as its source, and the M0 deployment at the declared project URL
was verified over HTTPS. Deploy needs that build and only has contents: read,
pages: write, id-token: write, targets protected github-pages, then calls
deploy-pages. #34 still owns final-release accessibility, navigation, search,
versioning, and rollback evidence rather than treating early publication as the
M10 documentation gate.

Set `site: https://0x63616c.github.io` and `base: /agent-runtime` so CI tests the project-site prefix. A custom domain is a separate reviewed change. Pagefind search is built into the static artifact; a future hosted search service requires a separate privacy decision.

## Acceptance tests

| ID | Proof |
|---|---|
| DOC-001 | docs-check and Pages fixture prove strict build, navigation/accessibility smoke, search config or pre-crawl state, artifact, deployment URL. |
| DOC-002 | Coverage map proves every required topic, deployment surface, evidence class, and example has page, owner, source/evidence. |
| DOC-003 | Changed operation, exported Go symbol, or catalog field fails docsgen --check; second render is byte-identical. |
| DOC-004 | Broken internal link/anchor, bad external target, unclassified snippet, format/spell/MDX/a11y fault each fail. |
| DOC-005 | Skill fixtures cover missing output, path escape, dirty output, stale API/config/deployment, curated proposal, partial write, stale manifest, and --check no-write. |
| DOC-006 | Root README links/quickstart pass clean-checkout link/snippet fixtures. |
| DOC-007 | Fixtures reject local/Tilt as KVM proof; every security/deploy claim carries proof level, scope, owner, evidence. |
| DOC-008 | Locked site toolchain/root, Pages URL/permissions, versioning, search privacy/cost, accessibility and rollback are documented; docs-skill fixtures detect drift without rewriting curated security/operator content. |
| Notification docs | Catalog/docs generate ntfy topic/lifecycle; unit/HTTP fixture proves redaction, exact schema, idempotency/retry, successful-delivery-before-completion ordering, and visible retryable failure. |
| Declarative binding | Rendered field without owner/lifecycle, or hidden imperative instruction, fails docs check. |
| CI drift | Modify declared input without regeneration: PR fails before deploy. Regenerate: no diff; PR still never deploys. |

## Risks and controls

| Risk | Control |
|---|---|
| Astro/Starlight/Node drift | Exact pins; updates run full docs/reference/snippet/a11y/Pages checks. |
| Community OpenAPI plugin becomes contract | No plugin initially; use source-manifest-controlled renderer. |
| Pagefind index drift | Navigation is independent; `just docs-check` rebuilds the static search index and route manifest. |
| Hidden ownership/setup | Catalog coverage mandatory; docs checker rejects imperatively hidden paths. |
| Generator overwrites prose | Separate generated paths; curated markers preserved and proposals never auto-applied. |
| External link flakiness | Deterministic internal build first; bounded checker with expiring exceptions. |
| Snippet mutates host/requires secrets | Isolated fixtures; exceptional commands classify/link proof; no ambient credentials. |
| Ntfy leaks or changes milestone truth | Bounded redacted references; persist milestone first; async failure observable but non-rollback. |
| Security overclaim | Claim annotations distinguish local, fake, Linux/KVM, and operator proof. |

## Implementation sequence

1. Add Node/npm/Astro Starlight skeleton, strict config, Pages build workflow, and commands only as real.
2. Define config field IDs and deploy/catalog.yaml with first deployment asset, including ntfy topic ownership/lifecycle; test consistency first.
3. Add docsgen, manifest, fixtures, generated reference from real public source only.
4. Implement refresh skill with check-only, containment, atomic-write, dirty-output, curated-proposal, exact-diff tests.
5. Add coverage/claim/snippet/link/a11y checks and tutorials as runtime capabilities arrive.
6. Publish Pages, retain live ntfy test as evidence, verify deployed navigation/Pagefind search, make DOC-001--008 release gates.
