# Proposed M3 sandbox-role integration after M1

Status: **proposed; not deployed and not acceptance evidence.**

This is the implementation handoff for connecting the M3 control/host/reaper
protocol work to the M1 declarative Stack after M1 lands. It does not replace
the requirements ledger, accepted ADRs, or issue ownership. In particular, it
does not claim a production deployment, a working Tilt path, certificate or
trust reload, or Linux/KVM/Firecracker isolation.

## Purpose and dependency graph

The target is three separately supervised roles, with authority kept outside
the public `sandbox` SDK and Temporal-facing runtime API:

```text
named public caller -- TLS :8443 --> sandbox-control -- limited SQL --> state
                                      ^
                                      | mTLS :9443
                                      |
                           sandbox-host -- RWO journal PVC

sandbox-reaper -------------------------- limited SQL ----------> state
```

The private listener is an enrolled-host protocol endpoint, not a public API.
`sandbox-host` has no Service or inbound port. `sandbox-reaper` is independent
of control and host failure domains.

The proposed dependency edges are:

1. M1's final reviewed Stack topology and deployment evidence must land.
2. M3's durable control/host/reaper chain must be rebased onto that exact
   `origin/main` base and independently rereviewed.
3. Stack model, migration and image capabilities below must be implemented
   before role declarations are added.
4. Declarative secrets, database grants, certificate issuance and enrollment
   must be supplied by their named operators before a local deployment test.
5. Retained local Stack evidence precedes any claim beyond protocol integration;
   Linux/KVM evidence remains an M4 gate.

## Current gaps that block deployment

These are confirmed integration gaps, not optional cleanup:

| Gap | Current state | Required proposed slice |
| --- | --- | --- |
| Runtime image | Production image contains `/runtime` and `/egress-proxy`, while M1 sandbox roles invoke generic HTTP placeholders. | Build `/sandbox-control`, `/sandbox-host`, and `/sandbox-reaper`; publish provenance/SBOM; promote one immutable digest in a separate reviewed Stack change. |
| File configuration | Stack projects PVCs and secret environment values only. M3 processes require strict absolute config, certificate, key and CA paths. | Add read-only, typed ConfigMap and SecretReference key-file projections with exact paths, key inventory and no secret literals. |
| Rollout binding | Projected ConfigMap/Secret changes alone do not force a safe pod restart. | Bind immutable config/trust references to a reviewed pod-template digest/annotation and require an ordered rollout. |
| Network policy | Stack renders egress-only, service-target rules without explicit ports. | Add default-deny ingress and egress peers with finite protocol/port rules and declared resource references. |
| Host deployment wiring | The M3 host now has a cancellable daemon loop: `--config` and an explicit finite `--poll-interval`, safe no-work observation, and bounded transient retry. This is internal code-level evidence only. | Declare the exact command argument, supervision/readiness contract, journal PVC, one-host identity, and retained local Stack evidence in a separate reviewed M1 integration slice. Do not infer deployment proof from the daemon tests. |
| Migration execution | Stack executes every declared SQL artifact on every apply; M3 v2--v8 are not repeatable `ALTER` statements. | Add a durable, digest-pinned migration ledger with locking, drift refusal, exact-once apply and tested rollback semantics. |
| Database authority | Existing Stack state credentials are admin-like and do not model control/reaper grants. | Declare database principal/grant/bootstrap authority and issue separate least-privilege control and reaper DSNs. |
| Credential proof | M1's generic runtime negative-environment test does not prove an M3 binary rejects arbitrary env. | Make an explicit Stack credential/projection matrix the validated source; prove live manifests contain exactly those bindings and no Kubernetes API token. |

## Proposed Stack resources and authority

All names below are proposed resource identities. Final values, resource limits,
retention and profile-specific references require review in the Stack change;
no ambient defaults are permitted.

| Role/resource | Proposed declaration | Authority and exclusions |
| --- | --- | --- |
| `sandbox-control` | One Deployment, `/sandbox-control --config /etc/sandbox-control/control.json`, ports `https` 8443 and `host-control` 9443. | Owns authenticated public admission and durable host assignment; no migration, Kubernetes, host-execution or cleanup-inference authority. |
| `sandbox-control` Service | Public TLS 8443 Service. | Reached only by the named public caller/probe on TCP 8443. The caller is an unresolved explicit choice; do not copy the bearer credential to every role. |
| `sandbox-host-control` Service | Private mTLS 9443 Service selecting the control pods. | Reached only by `sandbox-host` on TCP 9443. A Service name does not enforce this boundary; port-specific pod policy does. |
| `sandbox-host` | One Deployment per enrolled host ID/generation; daemon command; no Service; RWO `sandbox-host-journal` PVC at `/var/lib/sandbox-host`. | Owns only one fenced reference-host identity. Never scale replicas sharing a journal, certificate, host ID or generation. A pool/StatefulSet awaits a distinct ordinal/enrollment design. |
| `sandbox-reaper` | One Deployment, `/sandbox-reaper --config /etc/sandbox-reaper/reaper.json`; no Service or port. | Owns bounded durable reconciliation only; it never infers guest cleanup from liveness. |
| ConfigMaps | Exact v2 `control.json`, `host.json` and `reaper.json`, projected read-only. | Non-secret declarations only. Host configuration names `https://sandbox-host-control:9443` and a TLS server name present in the private listener certificate SAN. |
| Secret references | Separate public/control TLS, private-host TLS, host-client CA, host server CA, host mTLS identity, control runtime secrets, host runtime secrets, reaper DB secret and named caller credential. | Certificate/key/CA material is file-projected. Existing M3 secret-lookup fields remain explicit environment references. Public control verification keys are integrity-critical even when not confidential. |
| Service accounts/RBAC | Dedicated control, host and reaper ServiceAccounts; `automountServiceAccountToken: false`, service links disabled, no Role/RoleBinding unless a concrete API call is introduced. | Projected secrets do not justify Secret-list/read Kubernetes API authority. |
| Network policies | Namespace default deny in both directions; control ingress from caller/probe TCP 8443 and host TCP 9443; host egress only to control TCP 9443 plus DNS; reaper/control egress only to state TCP 5432 plus DNS when required. | Do not retain telemetry or broad service allowances unless the implemented binary uses them. |

The control configuration must remain version 2. A version-1 host declaration,
or a version-1 control declaration with `host_control`, is intentionally
refused rather than translated into invented trust bindings.

## Persistence, trust and rollout proposals

`sandbox-control-database` is proposed as a separately named database resource
for the existing `agent_runtime` / `runtime` ownership boundary, after an
explicit schema-ownership review. Its migration artifacts remain canonical
under `deploy/sandboxcontrol/migrations/`; the Stack operator should use
`deploy` as migration root and address M1 artifacts as
`production/migrations/...`, avoiding copied trees. The migration ledger must
key an applied revision by Stack/profile/database resource/version/digest,
serialize with an advisory lock, reject a changed known digest and record a
revision only with its successful transaction. It must cover initial M1
baselining, idempotent reapply, concurrent operators and bounded rollback.

The database operator, not a runtime process, provisions the schema and
principal grants. `sandbox-control` and `sandbox-reaper` receive distinct DSNs
with only reviewed SQL authority. Host enrollment remains the audited
`HostControlStore.ProvisionHost` boundary; a process start must never enroll a
host or create certificates.

M3 has no watched certificate or trust configuration reload. A proposed
rotation is therefore an ordered, immutable-reference rollout: make the next
host verification key available, roll hosts, switch control signing, wait the
envelope/lost-ack window, then remove/revoke the previous key. Deployment
validation must parse the mounted v2 files and verify keypair, CA chain, TLS
SAN, host ID/generation, and control-signing/public-verification
key/version/validity/revocation coherence before apply. `AtomicTrust`
retirement history is only in-memory for one instance unless authenticated
persisted history is implemented; it must not be represented as restart-safe.

## Rebase and ownership plan

After M1 lands, create a clean worktree at updated `origin/main` and compute
the M3-only commit range rather than replaying a fixed historical SHA. Preserve
the commit order, resolve interfaces using tests, run the M3 PostgreSQL
integration harness, then independently review the rebased result. The current
M3 tip used to prepare this handoff is `c7cb65d`; it is a planning reference,
not a merge target or acceptance record.

| Owner | Files/seams expected to overlap | Required review |
| --- | --- | --- |
| M1/Stack platform | `internal/stack/{resource,kubernetes,policy}.go`, Stack render tests, `deploy/production/stack.json`, production smoke, Tilt/CI contracts. | Typed projection, migration-ledger, policy and all-profile rendering review. |
| M3 sandbox | control/host/reaper commands and process packages, host protocol/journal, M3 migrations, sandbox runbooks. | Host lifecycle, recovery, TLS/mTLS/trust and secret-redaction review. |
| Image/release | production Dockerfile, image contract, publish workflow and digest promotion. | Build inputs, multi-arch provenance/SBOM and immutable digest review. |
| Security/database operator | external secret schemas, CA/key lifecycle, host enrollment/revocation, database grants. | Least privilege, rotation ordering, no ambient secret/Kubernetes authority. |
| Runtime operator | designated public sandbox caller and its one credential binding. | Confirm caller identity before opening public ingress or distributing the static bearer. |

Known direct rebase overlaps with the M1 candidate include `Justfile`,
`deploy/sandboxcontrol/control.example.json`,
`docs/reference/sandbox-control-v1.md`, and generated website inventory. The
Stack files are additionally high-risk semantic overlaps even where Git does
not report a same-file conflict.

## Proposed evidence gates

None of these gates has been run for this plan. A deployment change may be
considered for independent review only after all applicable evidence exists:

1. TDD unit/render tests for projections, matrix enforcement, pod restart
   binding, port-specific policy and migration-ledger failure paths; focused
   race tests for host trust/journal/control.
2. `just check`, image build/contract checks and
   `deploy/sandboxcontrol/postgres/run-integration.sh` against a real
   disposable PostgreSQL instance.
3. A retained local Tilt/two-Stack proof at one exact commit and image digest:
   digest-verified migrations then safe reapply; TLS public submit; mTLS host
   pull; journal-before-effect restart; receipt/result recovery; reaper pass;
   and journal PVC restart persistence.
4. Negative proof that unsafe/legacy configuration, an unauthorized public
   caller, wrong CA/certificate, unprovisioned generation, retired key or
   wrong trust epoch is refused; that caller traffic cannot reach private 9443;
   and that host traffic cannot reach public/undeclared workloads.
5. Redacted retained manifests, role credential/projection matrix, image
   provenance, render/audit identifiers, logs and PostgreSQL observations, plus
   teardown proof. Evidence must contain no secret material.
6. Independent infrastructure/security and code-quality reviews. The proof
   must state that this is reference-host protocol integration, not Linux/KVM
   or Firecracker isolation.

The known website dependency-audit failure is a direct-main promotion blocker
until it is resolved or the governing delivery policy records a valid change;
this document does not waive that gate.
