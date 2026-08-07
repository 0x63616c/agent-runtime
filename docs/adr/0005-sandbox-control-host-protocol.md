---
status: accepted
---

# Sandbox control and host-agent protocol

Sandbox control is durable and centralized. Hosts enroll with durable identity
and mutually authenticated transport. A host acts only on a versioned,
authenticated operation envelope binding tenant/principal, immutable
Effective-Spec digest, Operation ID, capability snapshot, expiry, assignment
and lease/fencing token. The control plane owns assignment, fencing,
reconciliation and quarantine; stale or duplicate results are refused.

## Considered options

- Trust a host-agent connection or process-local handle after initial client
  authorization.
- Let individual adapters decide their own durability, authorization and
  recovery semantics.

## Consequences

The control plane, sandbox core, host agent and Jailer receive explicit,
non-overlapping authority for cgroups, network, image admission, mounts, output
limits and cleanup. The local-unsafe adapter exercises the protocol/refusal
semantics but is never production trust-boundary proof; Firecracker validates
the protocol in the Linux/KVM lane.
