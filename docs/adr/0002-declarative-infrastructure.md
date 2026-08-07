---
status: accepted
---

# Declarative infrastructure ownership and rendering

All owned infrastructure is explicit version-controlled desired state described
by one typed, versioned Stack specification. Local Tilt, CI and production
render the same declared topology for their profile; they do not discover or
invent a second topology. Runtime binaries, workflows and ad-hoc helpers never
create or mutate infrastructure as a startup side effect; a declared migration
job applies only a reviewed versioned schema change.

## Considered options

- Bootstrap dependencies lazily from runtime code or imperative convenience
  scripts.
- Treat Kubernetes manifests as declarative while leaving Temporal, buckets,
  migrations, retention, RBAC or observability implicit.

## Consequences

Each resource has explicit ownership and lifecycle, render/check/diff detects
drift and unsafe defaults, reconciliation is an audited operator action, and
an OS-selected foreground port-forward is connection state rather than desired
infrastructure.
