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

Use `deploy/sandboxcontrol/control.example.json` and
`deploy/sandboxhost/reference.example.json` as the strict version-2 control and
one-shot reference-host declarations. Paths are absolute mounted paths. Secret
fields name injected environment values; secret material is never serialized
in either document. The three `test_fault_*` fields exist only for the reference
host's recovery test profile and must remain false in normal runs.

### Configuration-format v1 to v2 migration

This format change is deliberately not a transparent fallback. A version-1
host declaration only names one control public key; it cannot express the
monotonic trust-bundle version, revocation epoch, key version, or finite key
validity that the signed envelope requires. Accepting it would turn the new
bindings into invented defaults. A version-1 control declaration remains
accepted only when it has no `host_control` listener; any version-1 declaration
that enables host control, and every version-1 reference-host declaration,
fails startup validation with an explicit `migrate to version 2` diagnostic.

Migrate during a controlled drain, not a mixed-version rollout:

1. Stop assignment and drain or explicitly fence every version-1 host. Do not
   reassign cleanup-required work until the operator records cleanup.
2. Change both declaration roots to `"version": 2`. In control's
   `host_control`, declare non-zero `control_trust_version`,
   `control_revocation_epoch`, `control_key_version`, and UTC
   `control_key_not_before`/`control_key_not_after` alongside the existing key
   ID and signing-key environment reference.
3. In each host declaration, replace the legacy `control_key_id` and
   `control_public_key_environment` fields with `control_trust`: a non-zero
   bundle version and revocation epoch, a `current` key with ID, version,
   public-key environment reference and UTC validity, plus an optional distinct
   `next` key for rotation overlap.
4. Have the reviewed deployment validation parse the exact v2 declarations
   before rollout, then deploy the v2 control and v2 hosts as the same reviewed
   change. The roles do not currently expose a standalone `--check` mode; do
   not mistake a process start for a safe configuration dry run. The parser
   rejects legacy single-key fields in v2 instead of merging the two trust
   models.

The protocol identifier remains `sandbox.host-control/v1`; configuration
version 2 changes only how operators declare its control-key trust. It does
not change public `sandbox` APIs or allow a host to accept old zero-bound
envelopes.

Enrollment is a separate audited operator action using the durable
`HostControlStore.ProvisionHost` boundary. Runtime startup never auto-enrolls a
peer. The operator supplies raw bounded evidence, a declared attestation
profile, and a verifier predicate to that call. The store derives and persists
only its digest and `verified`, `failed`, or `metadata-only` outcome atomically;
it never trusts caller-supplied outcome fields or stores the raw evidence. A
failed outcome is durable and cannot authenticate. The local-unsafe profile is
honestly `metadata-only`, never hardware-attested.

## Rotation and revocation

The following is the required operator procedure for a future deployed
rotation controller; it is not evidence that M3's long-lived reference host or
the multi-process harness performs a certificate or control-trust rotation.
M3 unit coverage exercises complete in-memory control-trust replacement and
refusal of a retired key within one running `AtomicTrust` instance. It does not
persist or authenticate retirement history across a host restart, and it does
not exercise a watched configuration reload, control signing-key change,
overlapping host certificates, or a live certificate-generation rotation.

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
key quarantine, explicit cleanup, reassignment to a newly enrolled generation,
and final public success. It does not exercise a certificate rotation or
control-trust rotation/reload. The harness removes its temporary binaries,
network, database container, and volume.

This test uses a reference effect marker. It is not Linux/KVM execution or a
hostile-tenant isolation test; those claims remain M4-gated.
