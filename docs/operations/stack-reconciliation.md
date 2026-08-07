# Stack reconciliation, rollback, and teardown

Status: typed Kubernetes manifest rendering and the audited `stackctl` operator
adapter are implemented. The retained Docker/K3s NetworkPolicy harness result
is `deploy/issue10-k3s-networkpolicy-result.json`; the harness always removes
its exact named container and temporary kubeconfig on exit.

## Authority boundary

Parsing, validation, rendering, policy admission, preflight, and
provider-independent diff are pure or read-only. They cannot create or mutate
Kubernetes objects, Temporal configuration, buckets, databases, credentials,
kubeconfig, or local Stack state. Runtime startup and workflows never call
infrastructure mutation.

`stackctl` is the explicit audited operator adapter. It accepts only a
validated rendered digest/catalog, bounded actor, exact `--stack` identity,
absolute kubeconfig, explicit context, audit destination, and migration root.
It passes kubeconfig/context as argv to `kubectl`; it does not read
current-context or ambient credential selection. Provider discovery can report
drift but cannot widen desired state.

For a disposable local proof, audited `stackctl bootstrap` first uses an
atomic Kubernetes create to establish only the absent rendered Namespace. It
fails if the name already exists and retains the new UID, exact containment
labels, and rendered digest. The declared `local-generated` Secret controller
may then populate exactly the declared key inventories before full apply.
Secret values are generated per run, remain in mode-0600 temporary files, flow
through stdin rather than argv or logs, and are never retained as evidence.
The disposable proof requires absolute audit and evidence paths. It creates
generated Secrets exactly once rather than adopting or applying over existing
objects, and strips generator line endings before their values reach the
provider.

## Reconcile and rollback procedure

1. Run `stackctl preflight` with the absolute kubeconfig and explicit context
   that will be passed unchanged to the audited action.
2. Render the selected profile and inspect `stackctl manifests` output.
3. Run audited `stackctl observe` and `stackctl diff-live` with the explicit
   operator target. `diff-live` uses the same server-side field manager as
   apply, so it does not manufacture a conflict with the operator itself.
4. Review the bounded resource changes and immutable migration pairs.
5. Run audited `stackctl apply` or `stackctl reconcile`; reconcile applies only
   Kubernetes manifests when the bounded live diff is non-empty, and always
   reconciles or verifies every declared provider resource.
6. Re-observe and retain the JSONL audit outcome.
7. On failure, run audited `stackctl rollback` with an explicit previous Stack
   document. It digest-verifies and executes only rollback artifacts newer than
   that previous declaration, then applies the previous manifests. It never
   synthesizes SQL or infrastructure at runtime.

Migration declarations require strictly increasing positive versions, immutable
SHA-256 upgrade and rollback artifacts, safe relative artifact paths, and a
declared workload with an explicit readiness probe. The adapter reads each
artifact only beneath the supplied migration root and rejects a digest mismatch
before passing the bytes to `psql` over argv-only `kubectl exec`.

## Containment-safe teardown

`stack.PlanTeardown` produces no mutation capability. `stackctl teardown`
first asks each declared provider adapter to re-observe and execute its owned
lifecycle, then asks its Kubernetes adapter to re-observe and execute that
plan. It refuses
any plan unless:

- Stack, profile, namespace, and rendered digest match;
- namespace labels and current provider-observed UID match;
- the observed resource set exactly equals the rendered resource set;
- every resource has matching Stack/profile labels and a current observed UID;
- no duplicate or foreign resource is present.

Actions are reverse dependency ordered and retain each resource's declared
`delete`, `tombstone`, or `retain` behavior. The Kubernetes adapter re-fetches
and compares labels and UID immediately before every deletion, refuses a
tombstone without a registered containment adapter, and leaves the Namespace
in place when a Kubernetes object is retained. Local/CI `local-generated`
Secrets are ephemeral/delete resources: their provider verifies exact keys,
UID, containment/controller labels, bootstrap Namespace UID, and render digest
before explicit deletion. Production external-provider Secret references stay
retained. Blob teardown deletes only the declared prefix and refuses to remove
a non-empty bucket. Immediately before Namespace deletion, the adapter permits
only Kubernetes' automatic `default` ServiceAccount and
`kube-root-ca.crt` ConfigMap; any other namespaced object fails closed. A cached
state file is only a locator; it is never teardown authority. A mismatch stops the operation without
deleting a sibling Stack, `default`, or cluster-scoped state.

The disposable smoke harness never performs raw Namespace deletion. It invokes
teardown only after full apply returned the exact declared Kubernetes resource
set. If bootstrap or apply stops before that checkpoint, or any UID, label,
digest, provider resource, or declared object later differs, the Namespace is
retained for explicit operator inspection instead of being guessed safe.

## Prerequisite failure

Preflight reports only the declared check name, pass/fail state, and bounded
repair text. It does not print credentials or automatically change Kubernetes
context. A missing executable, wrong context, architecture mismatch, or low
disk blocks apply. Operators repair the environment deliberately and rerun the
same Stack/profile check.
