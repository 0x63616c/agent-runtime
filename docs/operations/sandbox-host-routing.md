# Sandbox host routing and reconciliation

Status: M3 implements the PostgreSQL-backed enrolled-host protocol and a
separately runnable reference host. This runbook covers protocol and recovery
evidence only; it does not promote Linux/KVM or Firecracker security profiles.

## Explicit authority matrix

| Owner | May do | Must not do |
| --- | --- | --- |
| Infrastructure operator | Apply reviewed migrations; issue/revoke CA identities; inject signing keys; provision/revoke host generations; confirm cleanup evidence. | Hide resources in startup code or grant the runtime migration/certificate authority. |
| Sandbox control | Authenticate enrolled hosts; choose tenant/capability-compatible work; persist envelopes; own leases, fences, sequence watermarks, quarantine, and reassignment. | Execute guest work, widen Effective Specs/capabilities, create infrastructure, or infer cleanup from liveness. |
| Sandbox core/public API | Canonicalize, authorize, admit, and expose Principal-scoped Operations. | Expose host, assignment, backend, TLS, PostgreSQL, or Temporal identifiers. |
| Reference host | Verify one envelope; journal before its simulated effect; send receipt and signed result. | Claim isolation or enforce cgroups, network, image, mount, secret, output-content, or cleanup policy. |
| M4 host/Jailer | Enforce only the already-admitted envelope under separately certified capability profiles. | Widen control authority or substitute liveness for cleanup proof. |

## Deployment declarations

Apply every ordered `deploy/sandboxcontrol/migrations/*.up.sql` before starting
the service. `sandbox-control` has no migration authority. Its public HTTPS
listener and private host listener use distinct addresses and certificate/key
paths. The private listener additionally declares a client CA; monotonic trust,
revocation, and current-key versions; current-key validity; a signing-key secret
environment name; and a finite lease. The reference host declares the same
trust version and revocation epoch plus complete current/optional-next public
keys and validity intervals. Legacy envelopes with zero key version or zero
revocation epoch are refused.

Use `deploy/sandboxcontrol/control.example.json` as the strict control
declaration and `deploy/sandboxhost/reference.example.json` as the strict
one-shot reference-host declaration. Paths are absolute mounted paths. Secret
fields name injected environment values; secret material is never serialized
in either document. The three `test_fault_*` fields exist only for the reference
host's recovery test profile and must remain false in normal runs.

Enrollment is a separate audited operator action using the durable
`HostControlStore.ProvisionHost` boundary. Runtime startup never auto-enrolls a
peer. The operator supplies raw bounded evidence, a declared attestation
profile, and a verifier predicate to that call. The store derives and persists
only its digest and `verified`, `failed`, or `metadata-only` outcome atomically;
it never trusts caller-supplied outcome fields or stores the raw evidence. A
failed outcome is durable and cannot authenticate. The local-unsafe profile is
honestly `metadata-only`, never hardware-attested.

## Rotation and revocation

1. Publish the next control verification key to hosts while current remains
   accepted; atomically reload the complete higher trust-bundle version.
2. Move control signing to that key only after the overlap is deployed.
3. Remove the prior key in a strictly newer bundle after its envelope TTL and
   lost-ack window; increment the revocation epoch for immediate refusal.
4. Issue a next-generation client certificate and host signing key.
5. Provision the new generation while the old generation remains active.
6. Drain/fence work from the old generation, then revoke it explicitly.

Revocation and quarantine deny future authentication and fence all of that
Host ID's non-terminal work. Rotation overlap permits both exact generations;
it never permits an unspecified generation or certificate digest.

## Failure and reconciliation rules

| Failure | Durable response |
| --- | --- |
| Control or host process exits before receipt | The current envelope is replayed byte-for-byte; the host journal returns its stable receipt and does not repeat the effect. |
| Host exits after receipt but before result | Pull still replays the current envelope; the journal skips the effect and the host resends receipt and signed result. |
| Lease is renewed | Epoch and fence advance together; older outputs/results are stale. |
| Host signs with the wrong key, changes a duplicate, skips output sequence, or sends an impossible binding | Quarantine the enrolled generation, increment fences, clear assignments, and mark affected Operations `uncertain`. |
| Host disappears or lease expires | Fence and expose uncertainty; do not guess that guest resources are gone. |
| Operator proves cleanup | Record explicit cleanup confirmation, then requeue the Operation without reusing its prior fence. |

Reassignment is forbidden until cleanup is explicit for cleanup-required work.
The M3 reference proof calls `ConfirmHostCleanupAndRequeue` directly as an
operator seam. The independent `sandbox-reaper` owns expiry, cleanup claims,
and safe tombstoning, but it preserves this evidence boundary rather than
inferring cleanup from timeout, process exit, or revocation.

## Disposable PostgreSQL and multi-process evidence

From the repository root run:

```sh
./deploy/sandboxcontrol/postgres/run-integration.sh
```

The harness creates a disposable digest-pinned PostgreSQL stack, applies all
reviewed migrations, builds both roles with the race detector, and executes
the integration packages sequentially against the real database. Its
multi-process test proves public Submit, durable body/routing, mTLS host pull,
host restart after journal commit, stable single-execution receipt recovery,
restart after receipt with result recovery, signed completion, rogue signing
key quarantine, explicit cleanup, certificate-generation rotation,
reassignment, and final public success. The harness removes its temporary
binaries, network, database container, and volume.

This test uses a reference effect marker. It is not Linux/KVM execution or a
hostile-tenant isolation test; those claims remain M4-gated.
