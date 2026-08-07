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

## Reconcile and rollback procedure

1. Run `stackctl preflight` for declared, read-only prerequisites.
2. Render the selected profile and inspect `stackctl manifests` output.
3. Run audited `stackctl observe` and `stackctl diff-live` with the explicit
   operator target. `diff-live` uses the same server-side field manager as
   apply, so it does not manufacture a conflict with the operator itself.
4. Review the bounded resource changes and immutable migration pairs.
5. Run audited `stackctl apply` or `stackctl reconcile`; reconcile applies only
   when the bounded live diff is non-empty.
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
then asks its Kubernetes adapter to re-observe and execute that plan. It refuses
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
in place when a Kubernetes object is retained. A cached state file is only a
locator; it is never teardown authority. A mismatch stops the operation without
deleting a sibling Stack, `default`, or cluster-scoped state.

## Prerequisite failure

Preflight reports only the declared check name, pass/fail state, and bounded
repair text. It does not print credentials or automatically change Kubernetes
context. A missing executable, wrong context, architecture mismatch, or low
disk blocks apply. Operators repair the environment deliberately and rerun the
same Stack/profile check.
