# Issue #10 typed Stack implementation evidence

Status: implementation and disposable-cluster execution are complete. The
K3s harness provides retained default-deny and named-egress enforcement proof;
this issue is ready for its ledger/issue owner to close without promoting the
ledger from this working slice.

## S11 behavior matrix

| Behavior | Dangerous negative | Retry/lifecycle boundary | Literal outcome |
| --- | --- | --- | --- |
| Strict Stack parse | Unknown field, missing profile, implicit/default namespace, duplicate/dangling/cyclic resource, or profile topology divergence | Reparse the same bytes deterministically | Accepted value has one identity and three explicit profiles. |
| Typed policy admission | Mutable image, zero/unbounded compute/quota, wildcard RBAC, non-deny NetworkPolicy, missing migration rollback, literal secret, or ambiguous migration target | Correct desired state and reparse; no provider effect occurred | Invalid input is rejected before render. |
| Typed Kubernetes render | Reordered resources/dependencies attempt to change output | Re-render produces the same canonical Kubernetes List | Namespace and every object carry exact Stack/profile/resource containment labels. |
| Audited operator action | Missing actor, non-absolute kubeconfig/migration root, implicit context, digest-mismatched SQL, or provider failure | Re-observe/diff or run declared rollback deliberately | JSONL audit retains action, actor, context, Stack/profile/digest, result, and bounded resource IDs. |
| Teardown | Wrong Stack/profile/namespace/digest/label/UID, foreign resource, or tombstone with no adapter | Re-observe current provider identity | No plan/deletion is returned until containment is proven; action order is reverse dependency order. |

## Implemented evidence

- internal/stack strictly parses one Stack/three profiles with a closed typed
  resource union, lifecycle metadata, finite quota policy, deterministic
  provider-independent render, and typed Kubernetes v1/List projection.
- Kubernetes projection covers explicit Namespace, ServiceAccount, Role,
  RoleBinding, ConfigMap, Deployment, StatefulSet, Job, Service, NetworkPolicy,
  PVC, and ResourceQuota. Workloads have digest-pinned images, finite requests
  and limits, explicit service accounts/ports/storage, non-secret environment,
  and an optional explicit readiness probe.
- stackctl implements pure/read-only render, manifests, check, diff, and
  preflight; and separately audited apply, observe, diff-live, reconcile,
  rollback, and teardown. Mutating commands require explicit Stack identity,
  absolute kubeconfig and migration-root paths, explicit context/actor/audit-file,
  and never run in runtime startup.
- The Kubectl adapter uses argv-only subprocesses, one fixed field manager,
  server-side apply/diff, live UID+label observation, and re-observation
  immediately before a delete. It refuses tombstone behavior without a
  registered containment adapter.
- Database migration declarations bind strictly ordered upgrade/rollback
  artifact paths and SHA-256s to a readiness-probed declared workload. The
  operator verifies every artifact digest before kubectl exec invokes psql.
- deploy/stacks/issue10-disposable-v1.json,
  deploy/stacks/issue10-disposable-v2.json, and
  deploy/stacks/issue10-peer-v1.json are explicit disposable profiles; the
  four checked-in SQL files are their reviewed reversible artifacts.

## Retained local OrbStack evidence

The 2026-08-06 local target was discovered read-only before mutation:
kubectl 1.33.9 client/server, Docker 29.4 daemon, and OrbStack Kubernetes
running on linux/arm64. kind and k3d were unavailable. The selected
orbstack context authorized namespace and Deployment creation. All operator
mutations were submitted with the explicit absolute kubeconfig/context and
are retained in deploy/issue10-orbstack-operator-audit.jsonl.

| Command/evidence | Result | Proof level |
| --- | --- | --- |
| stackctl preflight on v1/local | kubectl, explicit orbstack context, and arm64 prerequisites passed | local integration |
| stackctl apply v1/local | rendered manifests applied; v1 SQL created issue10_migration_v1 | local Kubernetes |
| kubectl auth can-i create deployments as runtime-account | no | local Kubernetes RBAC-negative |
| stackctl apply v2/local then stackctl rollback v2 to v1 | v2 table appeared, then v2 table was absent and v1 table remained | local Kubernetes migration upgrade/rollback |
| stackctl diff-live v1/local after field-manager correction | empty changes | local Kubernetes observe/diff |
| stackctl reconcile on containment fixture | empty live diff; Applied false and retained unchanged audit result | local Kubernetes reconcile |
| apply issue10-peer | distinct work/peer namespace UIDs and service ClusterIPs; each isolated database contained v1 table | local Kubernetes two-Stack namespace/database/port isolation |
| stackctl teardown on issue10-teardown | re-observed UID/labels/digest and deleted only the proof ConfigMap then its Namespace; later namespace get returned NotFound | local Kubernetes safe teardown |
| default-deny probe | policy admitted, but pg_isready from the selected probe to the database service still returned accepting connections | negative OrbStack-CNI result, preserved separately |

The audit contains one initial migration-startup failure and one initial
field-manager diff conflict before their respective fixes. They are retained as
failed evidence; later successful apply/diff/rollback records are not presented
as erasure of those failures.

## Retained Docker/K3s NetworkPolicy proof

`deploy/harness/run-k3s-networkpolicy-evidence.sh` starts no global tooling. It
uses Docker only, a pinned arm64 K3s OCI manifest digest, a temporary kubeconfig
and exact default context, then removes its named container and temporary state
on every exit. K3s supplies its embedded kube-router NetworkPolicy controller.

The final invocation retained:

- `deploy/issue10-k3s-final-audit.jsonl`: explicit CI-profile v1 and v2 applies;
- `deploy/issue10-k3s-networkpolicy-result.json`: three consecutive denied
  direct database probes under v1 default-deny, followed by three consecutive
  successful probes after v2 declared Postgres egress; and
- no remaining `agent-runtime-issue10-netpol` Docker container.

This converts the OrbStack CNI observation from a blocker into negative
environment evidence. It does not erase the OrbStack result or use that
environment as NetworkPolicy proof.

## Local command evidence

| Command | Result | Proof level |
| --- | --- | --- |
| go test ./internal/stack ./cmd/stackctl | pass | unit/contract |
| go test -race ./internal/stack ./cmd/stackctl | pass | unit/race |
| go vet ./internal/stack ./cmd/stackctl | pass | static |
| go test ./... | flaky one-time failure in unrelated milestone file-mode test; subsequent just check race suite passed | repository unit/contract |
| just check | pass | repository incremental gate |
| git diff --check | pass | patch hygiene |
