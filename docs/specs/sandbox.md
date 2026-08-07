# Sandbox durable control specification

Status: binding implementation specification.

Scope: the sandbox subsystem in the single public agent-runtime monorepo. This
implements SBX-001 through SBX-044, including SBX-040, SBX-041, SBX-042,
SBX-043 and SBX-044, and the sandbox-owned portions of INF-001 through INF-005
in
[the master requirements](../planning/requirements/master-requirements.md).
Every original review finding is dispositioned in
[sandbox-review-disposition.md](sandbox-review-disposition.md).

Binding requirement traceability is literal rather than inferred from a range:
`SBX-001`, `SBX-002`, `SBX-003`, `SBX-004`, `SBX-005`, `SBX-006`, `SBX-007`,
`SBX-008`, `SBX-009`, `SBX-010`, `SBX-011`, `SBX-012`, `SBX-013`, `SBX-014`,
`SBX-015`, `SBX-016`, `SBX-017`, `SBX-018`, `SBX-019`, `SBX-020`, `SBX-021`,
`SBX-022`, `SBX-023`, `SBX-024`, `SBX-025`, `SBX-026`, `SBX-027`, `SBX-028`,
`SBX-029`, `SBX-030`, `SBX-031`, `SBX-032`, `SBX-033`, `SBX-034`, `SBX-035`,
`SBX-036`, `SBX-037`, `SBX-038`, `SBX-039`, `SBX-040`, `SBX-041`, `SBX-042`,
`SBX-043` and `SBX-044`. The infrastructure contract is likewise `INF-001`,
`INF-002`, `INF-003`, `INF-004` and `INF-005`; its authoritative project-wide
details live in the root Stack and accepted infrastructure ADR.

## 1. Binding decision and release scope

Sandbox is a durable, tenant-scoped control plane with per-host execution
agents. It is not an in-process VM handle and is not owned by a Temporal
activity. The public client, control plane, core, adapters, deployment
configuration, docs, examples and tests are all owned in this monorepo and
share its release train.

The final release delivers all requested authority profiles: Firecracker
Linux/KVM foundation; portable file/directory transfer; domain-restricted
egress; RO/RW host mounts; named volumes; disk snapshots and restore;
command-scoped secret delivery; and elevated credential brokering or admitted
trusted execution. Profiles are independently gated security capabilities. A
profile is unavailable and makes no security claim until its exact contract and
conformance/security evidence are green. This is sequencing, not removal from
the final requested feature set.

The macOS/local adapter is explicitly unsafe developer convenience. It cannot
prove Firecracker, filesystem, network or secret isolation and must never be
used as production security evidence.

## 2. Terms

| Term | Meaning |
| --- | --- |
| Principal | Non-forgeable authenticated tenant/actor context bound at client construction. It is the authorization boundary; an ID is not. |
| Sandbox | Durable resource with desired/actual state, Effective Spec, host route and lease. |
| Process | One durable command execution in a Sandbox with Operation, Result and output sequences. |
| Operation | Durable mutation or control request. Caller supplies one opaque Operation ID per intent. |
| Effective Spec | Immutable resolved policy: normalized request, defaults, image admission, numeric identity, capability snapshot and versions. |
| Grant | Command-specific authority selection that can only narrow Effective Spec. |
| Control plane | Durable service that authorizes, owns ledger/resources/routes, writes audit and reaps. |
| Host agent | Per-host process that owns execution adapter and receives fenced normalized dispatches. |
| Backend SPI | Expert-only internal adapter seam, never consumer API. |
| Lease | Finite generation-numbered host, attachment, snapshot-read or cleanup ownership. |
| Taint | Provenance of SDK-managed secret exposure; not proof that arbitrary bytes are or are not secret-derived. |
| Tombstone | Retained terminal record preventing ID reuse and preserving safe lifecycle evidence. |

## 3. Architecture, ownership and declared infrastructure

### 3.1 Modules and roles

~~~text
runtime tool broker / activity
             |
       principal-bound sandbox client
             |
       durable sandbox control plane
       |       |          |       |
 ledger+outbox router     reaper   output/artifact store
             |
    authenticated host-agent control channel
             |
 Firecracker | local-unsafe | deterministic fake adapters
~~~

The durable client/control interface is the only supported runtime and test
seam. A public client never receives VMM, jailer, vsock, mount, host path or
backend handles. Host agents have no public API. Core wraps every backend call;
ordinary consumers cannot import or invoke an adapter.

Production has separate sandbox-control and sandbox-host-agent roles. Control
holds ledger, authorization, policy and audit-outbox credentials. Host agents
receive only fenced dispatch credentials for assigned resources. Temporal
workers submit/observe durable operations; they never own VMMs or streams.

### 3.2 Durable routing and recovery

Before dispatch, control records Sandbox ID, desired state, Host ID and Host
Generation, lease expiry, Effective Spec digest, required capabilities and
owning Principal. A retry on any worker reconnects by those IDs and is routed
to the owning agent; task-queue affinity is irrelevant.

An unreachable host is visible actual state, not hidden retry. Reaper uses
bounded injected-clock backoff to re-establish route, fence and clean after
lease expiry, or record typed SandboxLost/OutcomeUncertain. A new host agent
requires a higher generation; stale lease tokens are rejected.

### 3.3 Host enrollment, authenticated envelopes and fencing

This section is the concrete protocol required by SBX-040, SBX-041, SBX-042,
SBX-043 and SBX-044. It is deliberately not a public Go API: the public S9 durable-control seam proves
its effects without exposing host credentials, certificates, addresses, VMM
handles or protocol internals.

**Enrollment and trust.** A production host receives a durable `HostID` only
after an audited, declared `HostEnrollment` has been reconciled by the operator
authority. The record binds HostID, enrollment generation, pool, allowed
capability-profile digests, supported protocol range, certificate/key Secret
*references*, revocation state, expiry and bounded attestation evidence. The
host and control both use TLS 1.3 mutual authentication: each verifies the
other's current certificate chain, expected SAN/role and revocation generation.
The control certificate is authorized only for `sandbox-control`; a host
certificate is authorized only for its HostID/generation. Private key material
is supplied by the declared external Secret controller and is never in Stack
values, sandbox data, logs, Temporal, artifacts or this protocol.

Certificate rotation overlaps current and next credentials for a finite
declared interval. Control marks the next generation usable only after a fresh
authenticated handshake, and revocation takes effect before assignment,
renewal, result acceptance or receipt replay. A revoked, expired, unenrolled,
wrong-pool, protocol-incompatible, failed-attestation or quarantined host
cannot receive an operation and cannot complete one. Attestation can establish
only the explicitly configured launch-time measurements and freshness; it does
not prove a host remains uncompromised, prove tenant isolation by itself, or
replace Linux/KVM evidence. A profile that depends on an unavailable or failed
attestation stays unavailable rather than weakening its claim.

**Control-signing lifecycle.** `ControlSigningKeyRef` names an operator-owned
Ed25519 signing key, its public verification key and a non-secret key ID. The
Stack declares its finite not-before/not-after lifetime, maximum envelope TTL,
rotation grace, trust-bundle version and monotonic revocation epoch. The next
key is published to enrolled hosts before control may sign with it; current and
next key IDs are accepted only during the declared overlap. A host verifies the
canonical envelope bytes, key ID, algorithm, validity interval and revocation
epoch before accepting a delivery. A retired/revoked/unknown key or a signature
outside its allowed interval is refused, including duplicate-receipt lookup.
The private signing key is never serialized into a capability snapshot, API
response, Effective Spec, log, artifact or test fixture. `KeyLifecycle` exposes
only safe lifecycle metadata so callers can detect regression without learning
trust material.

**Assignment.** Control records an immutable `HostAssignment` before sending
work: AssignmentID, SandboxID, HostID, host enrollment generation, monotonically
increasing lease epoch/fencing token, expiry, effective-spec digest, capability
snapshot digest and desired resource generation. Assignment, lease renewal,
fencing, quarantine and reassignment are serializable ledger transitions. Only
control chooses or renews assignment. A host may ask for no assignment and
report health, but cannot select tenant, resource, capability, lease epoch or
another host's work.

**Envelope.** Each dispatch, control, cancellation, cleanup, output-ack and
result request is a `sandbox.host-control/v1` envelope. It is protected in
transit by the mutually authenticated encrypted channel and signed by the
current control signing key; hosts verify both before decoding its bounded
canonical body. It contains at least:

~~~text
protocol_version, envelope_id, delivery_id, issued_at, expires_at,
control_key_id, host_id, host_enrollment_generation, assignment_id,
lease_epoch_and_fencing_token, tenant_and_principal_scope, sandbox_id,
process_id_if_any, operation_id, operation_kind, effective_spec_digest,
capability_snapshot_digest, canonical_request_digest, sequence_contract,
payload_digest, signature
~~~

`envelope_id` and its nonce are single-use delivery identity; `delivery_id` is
the intentional at-least-once delivery attempt for one immutable operation and
assignment. Hosts persist the accepted envelope digest and receipt key
`(HostID, AssignmentID, LeaseEpoch, OperationID, CanonicalRequestDigest)` before
starting an effect. A byte-identical retried delivery over a currently valid
mutual-auth channel does **not** execute again: it returns the prior safe
receipt as `DuplicateDelivery`. A new signed `delivery_id` for the same receipt
key is a permitted lost-ack redelivery and likewise returns that receipt. Any
reused/altered envelope ID or nonce, changed digest, expired envelope, bad
signature, invalid channel identity, wrong tenant/principal, incompatible
version, stale lease or unexpected assignment is refused without an effect.
Thus a malicious replay is refused or is at most an authenticated duplicate
receipt; it can never cause a second command, widen authority or cross tenants.

The signature input is the exact `sandbox.host-control/v1` canonical envelope
object with `signature` omitted, including protocol version, every listed
binding field, `control_key_id`, nonce, delivery identity and payload digest.
There is no alternate JSON, map ordering, Unicode or `host:port` textual form
that verifies. Envelope IDs/nonces, key IDs and receipt entries have declared
finite retention no shorter than the maximum envelope TTL plus lost-ack retry
window; reaper deletes them only after that window and durable terminal state.

Hosts sign results and output headers with their current enrolled key and send
them only on the mutual-auth channel. Control accepts one only when its HostID,
enrollment generation, assignment, lease epoch, operation/spec/capability
digests and result kind match the current durable ledger. Control owns public
output sequence numbers: a host proposes a bounded per-stream sequence and
chunk digest, while control accepts exactly the next sequence, records a
duplicate, or records an explicit loss/gap. A stale or duplicate host result
cannot overwrite a newer lease, assignment, terminal state or output sequence.

**Loss, quarantine and recovery.** A failed authentication, protocol violation,
signature mismatch, impossible receipt/result, attestation regression or
security-policy violation immediately fences the current assignment, records a
safe audit fact and quarantines the host. Quarantine revokes new dispatches and
lease renewals, starts bounded reconciliation/cleanup, and requires an audited
operator re-enrollment or explicit declared unquarantine transition. Reaper may
reassign only after fence/cleanup evidence makes the old assignment unable to
act; otherwise it retains `OutcomeUncertain`/`SandboxLost`. Control and host
restart recover their ledger, receipt journal and assignment state before new
work; no in-memory connection is authority.

### 3.4 Declarative Stack, resource ownership and reconciliation

The typed, versioned `SandboxStack/v1` is the **sole** local, CI and production
input for sandbox infrastructure rendering. It is a component of the root
Stack, not a second topology. Tilt may choose a declared profile and apply its
deterministically rendered objects; it cannot invent values, Kubernetes objects,
SQL, buckets, Temporal configuration, ports or trust material. Runtime
binaries, workflows and startup helpers have no create/update/delete authority
over these resources. A reviewed migration Job is the only declared schema
mutator and applies only a versioned migration already in the Stack.

Every row below is an explicit typed Stack resource or an explicit typed
external reference. Each has a schema version/canonical digest and exact
declared finite limits. `Owner` is the reconciler accountable for desired
state; **runtime RBAC** says what running control/host processes are denied,
not merely what they normally avoid.

| Stack resource/reference | Owner; scope; dependencies | Finite lifecycle, backup/restore and safe deletion | External controller; runtime RBAC denial |
| --- | --- | --- | --- |
| `SandboxNamespace` and labels | Platform reconciler; one namespace per Stack; cluster policy | quota/retention labels and tombstone hold are finite; platform owns namespace backup/restore; delete only after labeled owned-object inventory is empty | Kubernetes; control/host ServiceAccounts cannot create namespaces, labels or cross-stack objects |
| `SandboxControlDeployment`, `Service`, `ServicePort` | Sandbox operator; per Stack; control image digest, config, PostgreSQL, trust refs | replicas, requests/limits, history/output/audit retention and rollout deadline are finite; database operator owns restore; delete scales down only after reaper drain/tombstone policy | Kubernetes deployment controller; control cannot mutate its Deployment, Service, port or image |
| `HostAgentPool`/DaemonSet and `HostPrerequisite` | Sandbox operator; selected Linux/KVM nodes; trust, Jailer, image policy, NetworkPolicy | pool capacity, KVM/cgroup checks, lease/cordon deadlines finite; node/platform owner restores hosts; retirement fences, drains, reaps and tombstones HostID | Kubernetes/host provisioning controller; host agent cannot alter its DaemonSet, node labels, capacity or pool membership |
| `HostEnrollment`, `HostTrustBundleRef`, `HostCertificateRef`, `ControlCertificateRef`, `ControlSigningKeyRef` | Security operator; per HostID/pool/control role; declared external Secret references and revocation registry | certificate TTL, overlap, enrollment expiry, revocation retention and audit retention finite; security operator owns backup/restore; revoke/fence before key reference removal, then tombstone enrollment | external Secret/certificate controller; no runtime SA can read another role's key, issue/revoke certificates, alter trust bundle or enrollment |
| `HostAssignmentLedger` and `HostRevocationRegistry` | Sandbox control database schema; per Stack/Principal; PostgreSQL, trust records | assignment/receipt/audit/outbox retention, lease expiry and tombstone hold finite; database operator owns backup/PITR/restore; delete only after reaper and retention expiry | PostgreSQL operator/migration Job; host cannot write assignments/revocations, control cannot run arbitrary DDL or create databases |
| `SandboxDatabase`, `MigrationJob`, `OutboxPolicy` | Data operator and reviewed migration owner; per Stack; PostgreSQL service/credentials | storage quota, WAL/backup/PITR, migration timeout and rollback plan finite; data operator owns restore; failed migration blocks rollout and uses declared rollback/tombstone path | database operator; control/host cannot create database/schema, execute bootstrap DDL or mutate migration history |
| `ControlServiceAccount`, `HostServiceAccount`, `ProxyServiceAccount`, `Role` and `RoleBinding` | Platform/security reconciler; namespace-scoped; namespace and workloads | binding/session expiry where supported and audit retention finite; platform restores RBAC; revoke binding before workload deletion | Kubernetes RBAC controller; each role denies all undeclared resource mutation, especially Secrets, deployments, namespaces and peer workload exec |
| `ControlHostNetworkPolicy`, `HostJailerNetworkPolicy`, `ProxyNetworkPolicy`, `ControlService`, `ProxyService`, declared ports | Sandbox operator; namespace/role scoped; services, trust, DNS policy | connection/resource limits and policy rollout deadline finite; platform owns network-policy rollback; delete fences traffic then drains/reaps dependent operations | CNI/service controller; control/host/jailer cannot create routes, ingress, services, ports or NetworkPolicies; guest has no direct network path |
| `EgressProxyDeployment` and `ResolverPolicy` | Sandbox operator; per Stack; proxy image, trust, NetworkPolicy, capacity | request/connection/bandwidth/cache bounds and log retention finite; operator owns restore/rollback; delete denies new egress then drains | Kubernetes controller; control/host/guest cannot bypass proxy, mutate resolver policy or create external ingress |
| `ArtifactStoreRef`, `OutputStoreRef`, `VolumeStoreRef`, `SnapshotStoreRef` and prefix policies | Storage operator; Stack/tenant prefixes; encryption keys, database manifests | byte/object/inode quotas, retention/GC, legal hold and tombstone duration finite; storage operator owns backup/restore; delete marks tombstone then GC after retention | external object/block controller; runtime gets only declared least-privilege prefix credentials and cannot create buckets, change lifecycle/KMS policy or access another Stack prefix |
| `ImageAdmissionPolicy`, `CapabilityProfile`, `SandboxQuotaPolicy`, `LeaseReaperPolicy`, `StoragePolicy` | Sandbox security operator; Stack/profile; admitted images, trust, stores | each default/ceiling/queue/retry/lease/GC value finite; policy repository/operator owns restore; removal fails closed then retains effected policy digests | Stack reconciler; runtime can read resolved policy only and cannot widen policy/defaults or activate an unproved profile |
| `TelemetryResource`, `AuditSinkRef`, `AlertPolicy` | Observability operator; Stack/role; collector credentials and outbox | cardinality, retention, export queue and alert window finite; observability owner restores; delete drains/redacts outbox then tombstones sink config | external telemetry controller; control/host cannot reconfigure exporters, add secret fields or erase audit evidence |
| `TemporalSandboxReference` | Runtime platform operator; Stack namespace/task-queue reference only; declared Temporal namespace and credentials | workflow retention and task limits are finite in the referenced runtime Stack; Temporal operator owns backup/restore; removal first stops new submissions and waits/reconciles operations | Temporal/operator tooling; sandbox control/host have no namespace/search-attribute/schedule provisioning authority |

The renderer emits a resource catalog, ownership/lifecycle matrix, effective
manifests and migration plan for every Stack/profile. Render/check/diff/policy
reject implicit namespaces, ambient credentials, mutable image tags, undeclared
ports/prefixes, missing finite limits, missing owner/lifecycle cells and drift.
`sandbox reconcile --stack <declared-id>` is an audited operator action that
only reconciles the rendered catalog; it is not a process-startup side effect.
CI renders local/CI/production profiles and two distinct Stack IDs, proves
schema/policy/ownership, migration upgrade and declared rollback, RBAC-negative
behavior, NetworkPolicy admission and absence of cross-stack resources. The
operator runbook records the render digest, apply/reconcile actor, rollback
target, backup/restore owner and safe teardown evidence.

### 3.5 Desired policy objects

The following policy objects are nested typed inputs to `SandboxStack/v1`; they
are not an alternative source of infrastructure state.

| Desired-state object | Required declaration | Effective state / drift action |
| --- | --- | --- |
| SandboxControlDeployment | image/digest, replica/role, control API version, ledger/outbox/auth, retention, audit, quotas, reaper | effective digest, ready version, migration and reconciliation health |
| HostAgentPool | agent/image/kernel/Firecracker versions, KVM prerequisite, cgroup v2, jailer policy, selector, capacity, lease policy | capability snapshot, allocatable capacity, agent generation, cordon/drift |
| CapabilityProfile | version, enforcement contract, required policies/images, suite and activation | desired/negotiated digest; regression fails closed |
| ImageAdmissionPolicy | sources/signatures, guest protocol, numeric identity, special-file/daemon rules, architectures | admitted evidence or rejection |
| NetworkPolicy | proxy version, domain rules, resolver, denied ranges and TLS limitation | active rules, effective domain set, bypass status |
| StoragePolicy | volume/snapshot class, quota, schema, encryption/integrity, retention/GC | applied class, capacity, manifest state |
| SandboxQuotaPolicy | per-sandbox/process and principal/global limits, finite defaults, queue | resolved limits, usage, admission/deadline |
| LeaseReaperPolicy | leases, generations, retry, cleanup deadline, lost policy | owner/expiry, backlog, cleanup state |

Each object has a schema version and canonical digest. Control persists effective
policy digest in each Effective Spec and records observed state, drift reason
and last successful reconciliation. Desired-state changes do not mutate a
running sandbox implicitly: they have a documented compatible reconciliation,
apply to new resources, or mark work IncompatiblePersistedPolicy. Operators can
inspect desired, effective and observed state.

Reconciliation is idempotent, fenced and auditable. It may provision only
declared effective resources. KVM/kernel/cgroups/jailer prerequisite failures
make HostAgentPool unready; they never fall back to unsafe execution.

### 3.6 Authority boundary

The following authorities are intentionally non-overlapping. A failure to
enforce any row is a profile/security failure, not a fallback permission.

| Concern | Control plane | Sandbox core | Host agent | Jailer/share/proxy |
| --- | --- | --- | --- | --- |
| Tenant, policy, grant, Effective Spec | authenticates, authorizes, persists assignment | validates, freezes and enforces non-widening dispatch | receives immutable scope only | receives no tenant/policy authority |
| Cgroups/process tree | declares finite result and reaper intent | validates required precision | starts only declared Jailer | Jailer alone places/kills child tree in assigned cgroup; no host-wide cgroup access |
| Network | persists granted policy/profile | rejects widening and routes output state | cannot install arbitrary route | proxy is sole egress enforcer; Jailer/guest has no direct route |
| Image admission | records admitted image evidence | normalizes admitted digest/identity | fetches only admitted digest | Jailer boots only verified admitted image; cannot resolve names |
| Mounts/volumes | grants resource/lease and records identity | validates canonical targets and taint | may request pre-opened declared share | share/Jailer use only pre-opened descriptors; cannot resolve arbitrary host paths |
| Output | owns durable sequence/result visibility | redacts/bounds/persists public output | proposes bounded chunks only | cannot write output store or public events |
| Cleanup | fences, assigns reaper and records proof | validates cleanup command | performs only current fenced cleanup directive | Jailer/share/proxy delete only assigned resource set; cannot tombstone ledger |

The local-unsafe adapter implements the same envelope and refusal protocol but
never passes this authority-boundary security proof. Negative deployment tests
must prove that role credentials cannot bypass every row above.

### 3.7 Principal and authorization

Client construction performs a no-sandbox-side-effect authenticated bind
handshake and pins one internal non-forgeable `PrincipalBinding`. Control
authenticates the construction credential, derives the canonical authentication
authority/issuer, tenant and subject itself, and returns a finite-lived opaque
server-authenticated binding assertion. The Client stores that assertion only
inside its transport. No public type, config field, callback, label or request
contains the binding, tenant or subject; callers cannot choose, read, parse,
replace or serialize it. The assertion alone is not authorization and cannot
be used without a currently authenticated credential.

Every request, retry, same-origin redirect, stream reconnect and binding-
assertion renewal applies a fresh credential. Before object lookup,
idempotency-ledger access, policy evaluation or any operation/audit side
effect, control authenticates that credential and compares its canonical
authority/issuer, tenant and subject to the pinned assertion. Ordinary token,
certificate or signing-key rotation is allowed only when all identity fields
are exactly the same. A tenant, subject or authority change returns the same
non-enumerating `FailureNotFoundOrDenied` as an unauthorized object, has no
sandbox/control operation effect, never retries under the new identity and
never replaces or widens the binding. A later credential for the original
identity may still be used while the binding is valid. Assertion renewal also
requires the old valid assertion plus an exactly matching current identity; an
expired assertion cannot be rebound and requires a new Client construction.

The bind/renew/mismatch path retains a bounded safe audit fact using an opaque
binding correlation, attempt class and outcome. It contains no credential,
authorization header, raw tenant, raw subject, issuer claim, token version or
authentication response. Audit persistence does not precede or create a
sandbox operation; binding mismatch is rejected before the operation's
attempted/authorized sequence.

Requests cannot choose tenant, owner, host, raw resolver or authority through
labels. Every object, ledger key, output cursor, image lookup, volume/snapshot
action, audit record and dispatch is Principal-scoped. Cross-principal access
returns non-enumerating NotFoundOrDenied. Opaque IDs are log-safe references,
never bearer capabilities.

Internal control/host roles use separate service Principals. Dispatch envelopes
include resource/operation IDs, Principal scope, lease generation, Effective
Spec digest and expiry. Agents may perform only that envelope.

## 4. Public durable control interface

The public Go module exposes one Principal-bound Client construction path and
generated transport types but no backend types. Its complete compileable type
reference—including `NewClient`, every stream and all tagged unions—is section
4.3; no abbreviated shadow interface is normative.

Submit is the sole public mutation/control entry point. The tagged Kind is:
create-sandbox, restore-sandbox, exec-process, signal-process, kill-process,
copy-in, copy-out, snapshot-sandbox, close-sandbox, reconcile-sandbox,
create-volume, attach-volume, detach-volume, delete-volume, delete-snapshot
or approve-sensitive-operation.

Every Kind carries Operation ID, targets where applicable and one canonical
request body. Submit returns only after durable acceptance. Signal, kill, close,
storage and approval actions have the same ledger, authorization, audit and
reconciliation semantics as create/exec. Client Close never closes durable
resources.

`NewClient(ctx, ClientConfig)` is the only public construction path. It creates
the runtime-owned HTTP/event client for a validated HTTPS endpoint, TLS server
name/trust-bundle reference and non-nil credential source, then completes the
section 3.7 authenticated bind handshake before returning a Client. The
service, never the caller or source, derives and pins the Principal.
`ClientConfig` never accepts a Principal, binding assertion, tenant, subject,
host agent, backend, plaintext credential, insecure-TLS override or default
global transport. A caller that needs a test transport uses an explicitly
test-only composition adapter, not a second public client contract.
Construction authentication/authorization failure is non-enumerating
`FailureNotFoundOrDenied`; local validation, cancellation, deadline and service
failures are the classifiable safe `FailureInvalidArgument`,
`FailureCancelled`, `FailureDeadlineExceeded` or `FailureUnavailable`.
Construction never falls back to an ambient endpoint, credential, TLS setting,
identity or local adapter.

`CredentialSource.Apply` runs once for the construction bind handshake and once
for every later outbound HTTP attempt, including binding renewal, retry,
same-origin redirect and stream handshake/reconnect. It is never cached once
for later header reuse. The transport supplies a new initially empty request-
scoped sink bound to the exact configured HTTPS origin and TLS server name. A
successful Apply calls `SetAuthorization` exactly once; returning success
without a value, calling it twice, supplying an empty/invalid scheme or value,
or attempting to set after sink revocation is a safe credential-source failure.
Redirects to a different origin are refused. Every permitted later attempt has
a new sink, a new Apply call and server-side re-authentication against the
pinned PrincipalBinding before an operation can be observed or mutated.

Credential sources are caller-owned, concurrent-safe, and may serve concurrent
Apply calls. An expiring implementation uses an injected clock and finite
refresh timeout, permits at most one refresh writer for one credential version,
and lets concurrent waiters observe only the atomically published complete
version. The request context bounds that caller's wait, not a refresh shared by
other live waiters; cancelling one request cannot publish a partial value or
cancel a refresh still needed elsewhere. An expired value is never applied.
A rejected refresh invalidates that candidate and does not reuse it; an
ambiguous refresh publishes neither candidate nor assumed rotation, preserves
the previous value only while independently known valid, and otherwise fails
safe. Source errors and refresh diagnostics never escape: the Client maps them
to bounded `FailureUnavailable`, or to the two context codes when the request
context is the cause. A successfully refreshed credential is not accepted
merely because refresh succeeded: control must authenticate it to the exact
pinned authority/tenant/subject. Identity mismatch is
`FailureNotFoundOrDenied`, never an implicit rebind or refresh retry.

The transport copies the authorization value into only that request's header,
then calls `ClearAuthorization` and revokes the sink immediately after the
header is committed to the configured connection, or on every error/cancel
path. It clears the header before response waiting and never stores it in a
redirect record, connection-pool key, retry body, log, error, event or trace.
Client `Close` does not close the caller-owned source. It atomically rejects new
calls, cancels this Client's request/stream and Apply waiter contexts, revokes
all outstanding sinks, and begins local transport shutdown. Its context bounds
only waiting for that shutdown: on deadline it returns a classified deadline
error while cleanup continues, and a later concurrent/idempotent Close can wait
for completion. A successful Close guarantees that no Apply call or sink owned
by that Client remains, no later source invocation can occur, and the in-memory
binding assertion is cleared.

Construction has one binding linearization point: validation of the
authenticated bind response and installation of its opaque assertion. One
`NewClient` never races two candidate bindings. If context cancellation wins
before installation, construction cancels its Apply/handshake, clears the sink
and returns no Client; any response-lost assertion is non-authorizing by itself
and expires. If installation wins first, `NewClient` returns that bound Client
even if the construction context is cancelled immediately afterward, and the
caller closes it normally. Close cannot race the first bind because no Client
is published before installation; an immediate Close after return follows the
ordinary Close rules. Concurrent `NewClient` calls sharing one concurrent-safe
source create independent handshakes/Clients and cannot compete to rebind one
another. Concurrent first requests occur only after the single construction
binding and all compare against it.

### 4.1 Operations and results

SandboxID, ProcessID, VolumeID, SnapshotID, OperationID, HostID, ArtifactID and
cursors are distinct typed opaque IDs. An HTTP idempotency key maps once to
Principal-scoped Operation ID and is not reusable across Principals.

An Operation persists identity, Principal, Kind, target, canonical
digest/schema/policy, ordered state sequence, injected timestamps, retention,
safe result/output references, reconciliation facts and safe Failure.

~~~text
accepted -> queued -> dispatched -> started
                     -> succeeded | failed | cancelled | uncertain
terminal outcome     -> cleanup-pending -> cleanup-confirmed
retention elapsed    -> expired -> tombstoned
~~~

Uncertain is terminal for automatic replay. Callers must reconcile or use an
application external-idempotency protocol before a new external-effect request.

### 4.2 Exported value semantics

| Value | Zero/absence | Cancellation/concurrency | Required behavior |
| --- | --- | --- | --- |
| Operation ID | invalid/rejected | same ID concurrent is safe | same canonical request reconnects; different is OperationConflict |
| Sandbox Spec | no usable production zero | copied/frozen before auth | validation/policy failure has no host effect |
| Command | empty path/argv invalid | one Process for successful exec | startup/lifetime cancellation differ |
| Grant selection | zero is none | frozen with Command | omission never inherits sensitive authority |
| Transfer | unknown-size reader invalid | upload cancellable | accepted source is immutable artifact/digest |
| Cursor/page | first retained/finite default | cancellation abandons observation | retention loss is CursorExpired or OutputGap |
| Client Close | local transport only | idempotent/context-bounded; revokes request credential sinks and clears opaque binding assertion | no resource lifetime effect and no source invocation after successful return |

### 4.3 Compileable public API reference

The following is the complete v1 public type location and compile-on-paper
reference for `github.com/0x63616c/agent-runtime/sandbox`. Implementation must
place these declarations (with the same exported names and no backend imports)
in `sandbox/api.go`, then compile the examples in `sandbox/api_example_test.go`.
The generated strict `sandbox.control/v1` codec is the wire implementation;
ordinary `encoding/json` tags must not be treated as the canonical codec.

~~~go
package sandbox

import (
	"context"
	"errors"
	"io"
	"time"
)

// All ID types are opaque, validated strings with distinct JSON/database forms.
type SandboxID string
type ProcessID string
type VolumeID string
type SnapshotID string
type OperationID string
type ArtifactID string
type HostID string
type OperationCursor string
type OutputCursor string
type PageCursor string
type Digest string

// ClientConfig is the backend-agnostic public construction input. It contains
// no Principal, backend handle, host address, certificate private key, or
// credential value. NewClient authenticates Credentials and the service pins
// one internal opaque Principal binding before returning a Client.
type ClientConfig struct {
	Endpoint Endpoint
	TLS TLSConfig
	Credentials CredentialSource
	RequestTimeout time.Duration
}
type Endpoint struct { URL string }
type TLSConfig struct { ServerName string; TrustBundleRef string }
type CredentialSource interface { Apply(context.Context, CredentialSink) error }
type CredentialSink interface {
	SetAuthorization(scheme string, value string) error
	ClearAuthorization()
}

// NewClient constructs and authenticates the Principal-bound public HTTP/event
// client. This declaration body is a compile-only reference stub; a real
// package replaces it with the checked transport implementation and tests.
func NewClient(context.Context, ClientConfig) (Client, error) {
	panic("sandbox API reference stub")
}

type Client interface {
	Submit(context.Context, OperationRequest) (OperationRef, error)
	GetOperation(context.Context, OperationID) (Operation, error)
	WaitOperation(context.Context, OperationID) (Operation, error)
	WatchOperation(context.Context, OperationID, OperationCursor) (OperationStream, error)
	GetSandbox(context.Context, SandboxID) (SandboxInfo, error)
	GetProcess(context.Context, ProcessID) (ProcessInfo, error)
	ReplayOutput(context.Context, ProcessID, OutputCursor) (OutputStream, error)
	GetVolume(context.Context, VolumeID) (VolumeInfo, error)
	ListVolumes(context.Context, Page) (VolumePage, error)
	GetSnapshot(context.Context, SnapshotID) (SnapshotInfo, error)
	ListSnapshots(context.Context, Page) (SnapshotPage, error)
	Close(context.Context) error
}

type OperationKind string
const (
	OperationCreateSandbox OperationKind = "create-sandbox"
	OperationRestoreSandbox OperationKind = "restore-sandbox"
	OperationExecProcess OperationKind = "exec-process"
	OperationSignalProcess OperationKind = "signal-process"
	OperationKillProcess OperationKind = "kill-process"
	OperationCopyIn OperationKind = "copy-in"
	OperationCopyOut OperationKind = "copy-out"
	OperationSnapshotSandbox OperationKind = "snapshot-sandbox"
	OperationCloseSandbox OperationKind = "close-sandbox"
	OperationReconcileSandbox OperationKind = "reconcile-sandbox"
	OperationCreateVolume OperationKind = "create-volume"
	OperationAttachVolume OperationKind = "attach-volume"
	OperationDetachVolume OperationKind = "detach-volume"
	OperationDeleteVolume OperationKind = "delete-volume"
	OperationDeleteSnapshot OperationKind = "delete-snapshot"
	OperationApproveSensitive OperationKind = "approve-sensitive-operation"
)

// Exactly one body must be non-nil and it must match Kind.
type OperationRequest struct {
	ID OperationID
	Kind OperationKind
	CreateSandbox *CreateSandboxRequest
	RestoreSandbox *RestoreSandboxRequest
	ExecProcess *ExecProcessRequest
	SignalProcess *SignalProcessRequest
	KillProcess *KillProcessRequest
	CopyIn *CopyInRequest
	CopyOut *CopyOutRequest
	SnapshotSandbox *SnapshotSandboxRequest
	CloseSandbox *CloseSandboxRequest
	ReconcileSandbox *ReconcileSandboxRequest
	CreateVolume *CreateVolumeRequest
	AttachVolume *AttachVolumeRequest
	DetachVolume *DetachVolumeRequest
	DeleteVolume *DeleteVolumeRequest
	DeleteSnapshot *DeleteSnapshotRequest
	ApproveSensitive *ApproveSensitiveOperationRequest
}

type CreateSandboxRequest struct { Spec SandboxSpec }
type RestoreSandboxRequest struct { SnapshotID SnapshotID; Overrides SandboxOverrides }
type ExecProcessRequest struct { SandboxID SandboxID; Command Command }
type SignalProcessRequest struct { ProcessID ProcessID; Signal Signal }
type KillProcessRequest struct { ProcessID ProcessID }
type CopyInRequest struct { SandboxID SandboxID; Source ArtifactRef; Destination GuestPath; Options TransferOptions }
type CopyOutRequest struct { SandboxID SandboxID; Source GuestPath; Options TransferOptions }
type SnapshotSandboxRequest struct { SandboxID SandboxID; RiskAttestation *SnapshotRiskAttestation }
type CloseSandboxRequest struct { SandboxID SandboxID }
type ReconcileSandboxRequest struct { SandboxID SandboxID }
type CreateVolumeRequest struct { Spec VolumeSpec }
type AttachVolumeRequest struct { SandboxID SandboxID; VolumeID VolumeID; Target GuestPath; Mode AttachmentMode }
type DetachVolumeRequest struct { SandboxID SandboxID; VolumeID VolumeID }
type DeleteVolumeRequest struct { VolumeID VolumeID }
type DeleteSnapshotRequest struct { SnapshotID SnapshotID }
type ApproveSensitiveOperationRequest struct { SensitiveOperationID OperationID; Decision ApprovalDecision; ExpiresAt time.Time }

type SandboxSpec struct {
	Image ImageRef
	Resources ResourceLimits
	Environment map[string]string
	SecretBindings []SecretBinding
	VolumeAttachments []VolumeAttachment
	Mounts []MountRequest
	Tmpfs []TmpfsMount
	Capabilities CapabilityRequirements
	Labels map[string]string
}
type SandboxOverrides struct { Resources *ResourceLimits; Capabilities *CapabilityRequirements }
type ImageRef struct { Digest Digest }
type ResourceLimits struct {
	MilliCPU uint32; MemoryBytes uint64; RootDiskBytes uint64; TmpfsBytes uint64
	PIDs uint32; ProcessCount uint32; OpenFiles uint32; Inodes uint64; Files uint64
	Lifetime time.Duration; ProducedOutputBytes uint64; RetainedOutputBytes uint64
	TransferBytes uint64; NetworkConnections uint32; VolumeBytes uint64; SnapshotBytes uint64
}
type SecretBinding struct { Name string; Purpose string }
type VolumeAttachment struct { VolumeID VolumeID; Target GuestPath; Mode AttachmentMode }
type MountRequest struct { Name string; Target GuestPath; Mode MountMode; View MountView }
type TmpfsMount struct { Target GuestPath; SizeBytes uint64; Mode FileMode }
type CapabilityRequirements struct { Required []CapabilityRequirement }
type CapabilityRequirement struct { Feature CapabilityFeature; Minimum CapabilityState }
type CapabilityFeature string
const (
	CapabilityIsolation CapabilityFeature = "isolation"
	CapabilityEgress CapabilityFeature = "egress"
	CapabilityMounts CapabilityFeature = "mounts"
	CapabilityVolumes CapabilityFeature = "volumes"
	CapabilitySnapshots CapabilityFeature = "snapshots"
	CapabilitySecrets CapabilityFeature = "command-secrets"
	CapabilityTransfer CapabilityFeature = "transfer"
	CapabilityReconnect CapabilityFeature = "reconnect"
)
type GuestPath string
type FileMode uint32
type AttachmentMode string
const ( AttachmentReadOnly AttachmentMode = "read-only"; AttachmentReadWrite AttachmentMode = "read-write" )
type MountMode string
const ( MountReadOnly MountMode = "read-only"; MountReadWrite MountMode = "read-write" )
type MountView string
const ( MountLive MountView = "live"; MountFrozen MountView = "frozen" )

type Command struct {
	Executable GuestPath
	Argv []string
	WorkDir GuestPath
	User NumericIdentity
	Umask FileMode
	Environment map[string]string
	Grant Grant
	StartDeadline time.Duration
	RuntimeLimit time.Duration
	BindLifetimeToOperation bool
}
type NumericIdentity struct { UID uint32; GID uint32; Groups []uint32 }
type Grant struct { Secrets GrantSelection; Mounts GrantSelection; Network NetworkGrantSelection }
type GrantSelection struct { Mode GrantMode; Names []string }
type NetworkGrantSelection struct { Mode GrantMode; Rules []NetworkRule }
// NetworkRule grants one canonical domain pattern, protocol and port set.
// Literal IP destinations are never grant authority.
type NetworkRule struct { Protocol NetworkProtocol; Domain DomainPattern; Ports []PortRange }
type NetworkProtocol string
const ( NetworkTCP NetworkProtocol = "tcp"; NetworkUDP NetworkProtocol = "udp" )
type DomainPattern string
type PortRange struct { First uint16; Last uint16 }
type GrantMode string
const ( GrantNone GrantMode = "none"; GrantSelect GrantMode = "select"; GrantInherit GrantMode = "inherit" )
type Signal string
const ( SignalInterrupt Signal = "interrupt"; SignalTerminate Signal = "terminate"; SignalKill Signal = "kill"; SignalHangup Signal = "hangup" )

type ArtifactRef struct { ID ArtifactID; MediaType string; SizeBytes uint64; Digest Digest }
type TransferOptions struct { Overwrite OverwriteMode; Mode FileMode; Owner *NumericIdentity; Durable bool }
type OverwriteMode string
const ( OverwriteFailIfExists OverwriteMode = "fail-if-exists"; OverwriteAtomicReplace OverwriteMode = "atomic-replace" )
type SnapshotRiskAttestation struct { Risk string; Owner string }
type VolumeSpec struct { SizeBytes uint64; Inodes uint64; Labels map[string]string }
type ApprovalDecision string
const ( ApprovalApproved ApprovalDecision = "approved"; ApprovalDenied ApprovalDecision = "denied" )

type OperationRef struct { ID OperationID; AcceptedAt time.Time }
type Operation struct {
	Ref OperationRef; Kind OperationKind; State OperationState; Target OperationTarget
	CanonicalDigest Digest; EffectiveSpecDigest Digest; CapabilityDigest Digest
	Result *OperationResult; Failure *Failure; RetentionExpiresAt time.Time
	LatestCursor OperationCursor
}
type OperationTargetKind string
const ( TargetSandbox OperationTargetKind = "sandbox"; TargetProcess OperationTargetKind = "process"; TargetVolume OperationTargetKind = "volume"; TargetSnapshot OperationTargetKind = "snapshot"; TargetOperation OperationTargetKind = "operation"; TargetNone OperationTargetKind = "none" )
type OperationTarget struct { Kind OperationTargetKind; SandboxID SandboxID; ProcessID ProcessID; VolumeID VolumeID; SnapshotID SnapshotID; OperationID OperationID }
type OperationState string
const (
	OperationAccepted OperationState = "accepted"; OperationQueued OperationState = "queued"
	OperationDispatched OperationState = "dispatched"; OperationStarted OperationState = "started"
	OperationSucceeded OperationState = "succeeded"; OperationFailed OperationState = "failed"
	OperationCancelled OperationState = "cancelled"; OperationUncertain OperationState = "uncertain"
	OperationCleanupPending OperationState = "cleanup-pending"; OperationCleanupConfirmed OperationState = "cleanup-confirmed"
	OperationExpired OperationState = "expired"; OperationTombstoned OperationState = "tombstoned"
)
type OperationResultKind string
const ( ResultSandbox OperationResultKind = "sandbox"; ResultProcess OperationResultKind = "process"; ResultArtifact OperationResultKind = "artifact"; ResultVolume OperationResultKind = "volume"; ResultSnapshot OperationResultKind = "snapshot"; ResultControl OperationResultKind = "control" )
// Exactly one field is non-nil and must match Kind and Operation.Kind.
type OperationResult struct { Kind OperationResultKind; Sandbox *SandboxResult; Process *ProcessResult; Artifact *ArtifactResult; Volume *VolumeResult; Snapshot *SnapshotResult; Control *ControlResult }
type SandboxResult struct { ID SandboxID }
type ArtifactResult struct { Artifact ArtifactRef }
type VolumeResult struct { ID VolumeID; Attachment *VolumeAttachmentInfo }
type SnapshotResult struct { ID SnapshotID }
type ControlResult struct { Action ControlAction; Cleanup TreeCleanupState }
type ControlAction string
const ( ControlSignaled ControlAction = "signaled"; ControlKilled ControlAction = "killed"; ControlCopiedIn ControlAction = "copied-in"; ControlClosed ControlAction = "closed"; ControlReconciled ControlAction = "reconciled"; ControlAttached ControlAction = "attached"; ControlDetached ControlAction = "detached"; ControlDeleted ControlAction = "deleted"; ControlApproved ControlAction = "approved" )
type Failure struct { Code FailureCode; Message string; Retry RetryClass; Details []FailureDetail }
// Error is the immutable, backend-agnostic synchronous error returned by the
// public client. It exposes only a safe Failure and, for context cancellation,
// one standard context sentinel; it never unwraps a backend or credential error.
type Error struct { failure Failure; contextCause error }
func (e *Error) Error() string {
	if e == nil { return "sandbox: <nil>" }
	return "sandbox: " + string(e.failure.Code) + ": " + e.failure.Message
}
func (e *Error) Failure() Failure {
	if e == nil { return Failure{} }
	failure := e.failure
	failure.Details = append([]FailureDetail(nil), e.failure.Details...)
	return failure
}
func (e *Error) Unwrap() error {
	if e == nil { return nil }
	return e.contextCause
}
// AsFailure extracts a safe Failure from Error even through ordinary %w
// wrappers. It returns false for arbitrary errors and context sentinels that
// were not returned by this client.
func AsFailure(err error) (Failure, bool) {
	var classified *Error
	if !errors.As(err, &classified) || classified == nil { return Failure{}, false }
	return classified.Failure(), true
}
type FailureDetail struct { Key FailureDetailKey; Value string }
type FailureDetailKey string
const ( DetailField FailureDetailKey = "field"; DetailLimit FailureDetailKey = "limit"; DetailResource FailureDetailKey = "resource"; DetailCapability FailureDetailKey = "capability"; DetailPolicyVersion FailureDetailKey = "policy-version"; DetailEarliestCursor FailureDetailKey = "earliest-cursor"; DetailOperationState FailureDetailKey = "operation-state"; DetailRetryAfterMillis FailureDetailKey = "retry-after-millis" )
type FailureCode string
const (
	FailureInvalidArgument FailureCode = "invalid-argument"
	FailureNotFoundOrDenied FailureCode = "not-found-or-denied"
	FailureOperationConflict FailureCode = "operation-conflict"
	FailureAlreadyTerminal FailureCode = "already-terminal"
	FailureCursorExpired FailureCode = "cursor-expired"
	FailureOutputGap FailureCode = "output-gap"
	FailureGrantWideningDenied FailureCode = "grant-widening-denied"
	FailureNetworkGrantInvalid FailureCode = "network-grant-invalid"
	FailureCapabilityUnavailable FailureCode = "capability-unavailable"
	FailureCapabilityRegressed FailureCode = "capability-regressed"
	FailureResourceLimitExceeded FailureCode = "resource-limit-exceeded"
	FailureControlQuotaExceeded FailureCode = "control-quota-exceeded"
	FailureIncompatiblePersistedPolicy FailureCode = "incompatible-persisted-policy"
	FailureOutcomeUncertain FailureCode = "outcome-uncertain"
	FailureCancelled FailureCode = "cancelled"
	FailureDeadlineExceeded FailureCode = "deadline-exceeded"
	FailureUnavailable FailureCode = "unavailable"
)
type RetryClass string
const ( RetryNever RetryClass = "never"; RetryAfterReconcile RetryClass = "after-reconcile"; RetryCallerControlled RetryClass = "caller-controlled" )

type OperationStream interface { Next(context.Context) (OperationEvent, error); Close() error }
type OperationEventKind string
const ( OperationEventUpdate OperationEventKind = "update"; OperationEventGap OperationEventKind = "gap" )
// Exactly one field is non-nil and must match Kind.
type OperationEvent struct { Kind OperationEventKind; Cursor OperationCursor; Update *Operation; Gap *OperationGap }
type OperationGap struct { EarliestRetained OperationCursor; Reason string }
type OutputStream interface { Next(context.Context) (OutputEvent, error); Close() error }
type OutputEventKind string
const ( OutputEventChunk OutputEventKind = "chunk"; OutputEventGap OutputEventKind = "gap"; OutputEventFinal OutputEventKind = "final" )
// Exactly one payload is non-nil and must match Kind.
type OutputEvent struct { Kind OutputEventKind; Cursor OutputCursor; Stream OutputKind; Chunk *OutputChunk; Gap *OutputGap; Final *OutputFinal }
type OutputChunk struct { Bytes []byte; Redacted bool }
type OutputFinal struct { Result ProcessResult }
type OutputKind string
const ( OutputStdout OutputKind = "stdout"; OutputStderr OutputKind = "stderr" )
type OutputGap struct { EarliestRetained OutputCursor; Reason string }

type SandboxInfo struct {
	ID SandboxID; Desired SandboxDesiredState; Actual SandboxActualState
	Image ImageInfo; Resources ResourceLimits; Capabilities CapabilitySnapshot
	Host HostRoute; Failure *Failure
}
type SandboxDesiredState string
const ( SandboxActive SandboxDesiredState = "active"; SandboxClosed SandboxDesiredState = "closed" )
type SandboxActualState string
const ( SandboxPending SandboxActualState = "pending"; SandboxProvisioning SandboxActualState = "provisioning"; SandboxReady SandboxActualState = "ready"; SandboxQuiescing SandboxActualState = "quiescing"; SandboxCleaning SandboxActualState = "cleaning"; SandboxFailed SandboxActualState = "failed"; SandboxUnreachable SandboxActualState = "unreachable"; SandboxLost SandboxActualState = "lost"; SandboxDeleted SandboxActualState = "deleted" )
type ImageInfo struct { Digest Digest; Architecture string; Identity NumericIdentity; GuestProtocol string; AdmissionPolicyVersion string }
type CapabilityState string
const ( CapabilityUnavailable CapabilityState = "unavailable"; CapabilityDeclared CapabilityState = "declared"; CapabilityEnforced CapabilityState = "enforced" )
type CapabilityDescriptor struct { State CapabilityState; ContractVersion string; ConformanceVersion string; DataPlane string; LimitPrecision []string }
// CapabilitySnapshot is canonical, immutable and structured. It is not a
// feature-string bag; every field is evaluated during negotiation and restore.
type CapabilitySnapshot struct {
	Digest Digest; SchemaVersion string
	ControlProtocol CapabilityDescriptor; Isolation CapabilityDescriptor; Guest CapabilityDescriptor
	Resources CapabilityDescriptor; Reconnect CapabilityDescriptor; ImageAdmission CapabilityDescriptor
	Output CapabilityDescriptor; Transfer CapabilityDescriptor; Mounts CapabilityDescriptor
	Volumes CapabilityDescriptor; Snapshots CapabilityDescriptor; Egress CapabilityDescriptor
	Secrets CapabilityDescriptor; Signals []Signal; Trust KeyLifecycle
}
type KeyLifecycle struct { TrustBundleVersion string; ControlSigningKeyID string; ControlSigningAlgorithm string; RevocationEpoch uint64; NotBefore time.Time; NotAfter time.Time; RotationGrace time.Duration }
type HostRoute struct { HostID HostID; Generation uint64; LeaseExpiresAt time.Time }
type ProcessInfo struct { ID ProcessID; SandboxID SandboxID; State ProcessState; Result *ProcessResult; Stdout OutputRetention; Stderr OutputRetention }
type ProcessState string
const ( ProcessAccepted ProcessState = "accepted"; ProcessStarting ProcessState = "starting"; ProcessRunning ProcessState = "running"; ProcessTerminating ProcessState = "terminating"; ProcessTerminal ProcessState = "terminal" )
type ProcessResult struct { StartedAt time.Time; FinishedAt time.Time; ExitCode *int; Signal *Signal; Reason TerminationReason; Usage ResourceUsage; Cleanup TreeCleanupState }
type TerminationReason string
const ( TerminationExited TerminationReason = "exited"; TerminationSignaled TerminationReason = "signaled"; TerminationTimedOut TerminationReason = "timed-out"; TerminationOOMKilled TerminationReason = "oom-killed"; TerminationOutputLimit TerminationReason = "output-limit"; TerminationCancelled TerminationReason = "cancelled"; TerminationKilledByCaller TerminationReason = "killed-by-caller"; TerminationSandboxClosed TerminationReason = "sandbox-closed"; TerminationSandboxLost TerminationReason = "sandbox-lost"; TerminationStartupFailed TerminationReason = "startup-failed"; TerminationInfrastructureFailed TerminationReason = "infrastructure-failed"; TerminationOutcomeUncertain TerminationReason = "outcome-uncertain" )
type ResourceUsage struct { CPUTime time.Duration; PeakMemoryBytes uint64; ReadBytes uint64; WrittenBytes uint64 }
type TreeCleanupState string
const ( TreeCleanupConfirmed TreeCleanupState = "confirmed"; TreeCleanupPending TreeCleanupState = "pending"; TreeCleanupNotRequired TreeCleanupState = "not-required"; TreeCleanupUnknown TreeCleanupState = "unknown" )
type OutputRetention struct { EarliestCursor OutputCursor; RetainedBytes uint64; Truncated bool }

type VolumeInfo struct { ID VolumeID; SizeBytes uint64; Inodes uint64; Attachment *VolumeAttachmentInfo; Tainted bool; RetentionExpiresAt time.Time }
type VolumeAttachmentInfo struct { SandboxID SandboxID; Generation uint64; LeaseExpiresAt time.Time; Mode AttachmentMode }
type SnapshotInfo struct { ID SnapshotID; SourceSandboxID SandboxID; Digest Digest; SizeBytes uint64; Tainted bool; RetentionExpiresAt time.Time }
type Page struct { Cursor PageCursor; Limit uint32 }
type VolumePage struct { Items []VolumeInfo; Next PageCursor }
type SnapshotPage struct { Items []SnapshotInfo; Next PageCursor }

var _ io.Closer = (OperationStream)(nil)
var _ io.Closer = (OutputStream)(nil)
var _ error = (*Error)(nil)
~~~

The two compile assertions above are illustrative only: production stream
implementations may return a typed closed error, but `Close` is always local
observation cleanup and never a durable control action.

### 4.4 Public API field and method semantics

Every type in 4.3 has these baseline rules: IDs are non-empty validated opaque
wire strings (and never authorization); `Digest` is lowercase SHA-256 text;
times are RFC3339 UTC; durations are non-negative integer nanoseconds; byte and
count fields are decimal unsigned integers; enums reject empty/unknown values;
strings are bounded NFC UTF-8 and reject NUL. The strict canonical codec rejects
unknown/duplicate fields and does not rely on Go zero values or `omitempty`.
Maps/slices/byte slices are copied before acceptance and returned snapshots must
not be mutable aliases. All reads/watches authorize the Client's bound
Principal; a foreign/missing ID is `NotFoundOrDenied`.

| API field or method family | Zero/validation and wire | Concurrency, cancellation and outcome |
| --- | --- | --- |
| `NewClient`, `ClientConfig`, endpoint/TLS/credential source | `NewClient` requires one HTTPS endpoint, non-empty TLS server name, declared trust-bundle reference, bounded positive request timeout and non-nil concurrent-safe credential source. Construction applies one credential for the authenticated bind handshake; every later attempt gets a fresh revocable sink and must authenticate to the same opaque pinned authority/tenant/subject. Binding, source, sinks and values have no public/canonical wire form and are never logged, persisted in sandbox state, returned, marshalled or reused by a Sandbox. | construction has the single install-vs-cancel linearization in section 4 and owns the resulting transport, not the caller-owned source. All `Client` calls are concurrent-safe; refresh/retry/redirect/reconnect/renewal cannot change identity. Apply/header clearing and `Close` follow section 4's exact lifecycle. Construction never falls back to ambient environment, endpoint, identity, credentials, insecure TLS or backend. |
| `OperationRequest.ID`, `Kind`, tagged bodies | ID and Kind are required; exactly one matching body is required; all targets are Principal-authorized. | same ID plus same canonical body returns the accepted operation; different body is `OperationConflict`; cancelled `Submit` before acceptance has no effect, after uncertain acknowledgement caller uses `GetOperation`. |
| `SandboxSpec`, `SandboxOverrides`, image, labels, resources, mounts/tmpfs, volume attachments, capability requirements | no usable production zero Spec; image digest/declared policies required; every zero resource resolves once to finite persisted policy default; override only narrows. | copied/frozen before authorization; create/restore failures have no host effect; unsupported profile/capability is a safe failure, never downgrade. |
| `Command`, identity, `Grant`, network rules and signals | executable/argv/workdir/identity valid and bounded; no PATH/inherited descriptors; Grant zero is explicit deny-all/none. `Grant.Network` uses only `NetworkGrantSelection`/`NetworkRule`; `Names` is never interpreted as network authority. | one successful exec starts one Process; Wait cancellation abandons observation only; signal/kill are separate durable Operations; timeout/close/lease control lifetime. |
| transfer, artifact, volume and snapshot request fields | artifact ID/media type/size/digest and guest paths are required; readers are not public wire values; archive/volume/snapshot limits are declared finite; attestation is required only for denied-risk override. | copy/snapshot/attach/delete cancellation follows its durable Operation and reports cleanup; result returns bounded reference/metadata, never bulk bytes. |
| `Operation`, target and result | `Operation.Target` is a tagged value and `Operation.Result` is an optional tagged pointer. A non-nil Result has exactly one payload and follows the exact Kind/state matrix below; nil is the sole absence representation and encodes as canonical `null`. | state sequence is monotonic; terminal `uncertain` is never auto-replayed; repeated terminal observations converge without constructing an invalid zero Result. |
| `Failure`, `Error`, `AsFailure` and typed limit outcome | `FailureCode` is one declared code below; Details is a canonically sorted unique bounded list using only declared `FailureDetailKey` values. `Error` returns a defensive Failure copy; its message/value are safe bounded text. `AsFailure` recognizes only this runtime-owned wrapper, including through ordinary `%w` wrappers. | every non-nil synchronous public-client error contains one `Error`; backend/source causes never unwrap. `errors.Is` reaches only `context.Canceled` or `context.DeadlineExceeded` when that context outcome caused the call. Validation/policy/resource failures are terminal before dispatch where possible; `OutcomeUncertain` requires reconciliation. |
| streams, cursors, operation/output events and `Page` | Event `Kind` is mandatory and exactly one matching payload is present. Empty cursor means first retained record; page limit zero resolves to documented finite limit, over-limit rejects; chunks are bounded already-redacted bytes. | `Next` context cancels only the next read; duplicate event/chunk cursors are safe; retention loss is explicit gap/expired cursor; stream `Close` abandons observation only. |
| `SandboxInfo`, `ProcessInfo`, `VolumeInfo`, `SnapshotInfo`, capabilities and page values | inspection contains only safe admitted metadata, finite retention and current safe state. `VolumeInfo.Attachment == nil` means unattached; non-nil means leased attachment. Capability Snapshot/KeyLifecycle are canonical safe metadata, not secrets/host handles. | snapshots are individually consistent, may become stale immediately, and require a new read for current state; unsupported/regressed capability is explicit failure. |

#### Result and event shape matrix

`OperationResult.Kind` has exactly one payload. This is the complete mapping;
an API decoder rejects any other result kind, more than one result payload, a
result on an Operation state that cannot carry one, or a `Control.Action` other
than the one listed. `Operation.Result == nil` is the only absent-result form;
an empty non-nil `OperationResult` is invalid.

The state matrix is exact. `accepted`, `queued`, `dispatched` and `started`
have nil Result and nil Failure. `succeeded` has one required Result from the
Kind table and nil Failure. `failed` has nil Result and one Failure;
`cancelled` has nil Result and nil Failure because the state is the complete
outcome; `uncertain` has nil Result and one `FailureOutcomeUncertain`.
`cleanup-pending` and `cleanup-confirmed` retain the Result/Failure pair of the
preceding terminal outcome unchanged while cleanup converges. `expired` and
`tombstoned` have nil Result and nil Failure after their finite detail retention
has elapsed; the state, identity, canonical digest and safe tombstone metadata
remain. The strict wire form always emits `result` and `failure`, using JSON
`null` for absence rather than omission or an invalid Go zero value.

| `OperationKind` | Required target | Required successful result |
| --- | --- | --- |
| create-sandbox | none | `ResultSandbox` / `SandboxResult` |
| restore-sandbox | snapshot | `ResultSandbox` / `SandboxResult` |
| exec-process | sandbox | `ResultProcess` / `ProcessResult` |
| signal-process | process | `ResultControl` / `ControlSignaled` |
| kill-process | process | `ResultControl` / `ControlKilled` |
| copy-in | sandbox | `ResultControl` / `ControlCopiedIn` |
| copy-out | sandbox | `ResultArtifact` / `ArtifactResult` |
| snapshot-sandbox | sandbox | `ResultSnapshot` / `SnapshotResult` |
| close-sandbox | sandbox | `ResultControl` / `ControlClosed` |
| reconcile-sandbox | sandbox | `ResultControl` / `ControlReconciled` |
| create-volume | none | `ResultVolume` / `VolumeResult` with nil attachment |
| attach-volume | volume | `ResultVolume` / `VolumeResult` with attachment |
| detach-volume | volume | `ResultControl` / `ControlDetached` |
| delete-volume | volume | `ResultControl` / `ControlDeleted` |
| delete-snapshot | snapshot | `ResultControl` / `ControlDeleted` |
| approve-sensitive-operation | operation | `ResultControl` / `ControlApproved` |

`OperationEventUpdate` carries exactly one `Update`; `OperationEventGap` carries
exactly one `Gap`. `OutputEventChunk` carries exactly one `OutputChunk`,
`OutputEventGap` exactly one `OutputGap`, and `OutputEventFinal` exactly one
`OutputFinal`. Chunk bytes are canonical base64 only in the strict wire codec,
never unbounded JSON text. Final events occur once per stream after its last
chunk/gap and copy the typed `ProcessResult`; they do not repeat a mutable live
process object.

#### Network grant canonical grammar and matching

`NetworkGrantSelection` is the only wire representation of command egress
authority. Its zero Go value or omitted wire field canonicalizes to
`{mode:"none",rules:[]}`. `none` requires no rules, `select` requires one to
64 rules, and `inherit` requires no rules and succeeds only where the frozen
Effective Spec marks the corresponding network rules inheritable. Nil and
empty are never two meanings. Unknown fields, legacy string names, duplicate
rules, zero/unknown protocol, empty domain or empty ports are
`FailureNetworkGrantInvalid` before authorization.

A rule has one lower-case IDNA2008 A-label `DomainPattern`: no trailing dot,
no Unicode alias in canonical form, no public suffix, and either an exact
domain or one leftmost whole-label wildcard (`*.example.com`). A wildcard does
not match its apex. DomainPattern is never an IP-literal escape hatch: dotted
IPv4, integer/short/obscure IPv4, bracketed or unbracketed IPv6, IPv4-mapped
IPv6, scoped addresses, CIDR and any string parsed as an IP address are
`FailureNetworkGrantInvalid`. Literal IP destinations have no public or
Effective-Spec grant representation.

Every rule has protocol `tcp` or `udp` and one to 16 sorted, non-overlapping,
non-adjacent `PortRange` values, each with `1 <= First <= Last <= 65535`.
Canonical rules sort by protocol, normalized domain, then first and last port.
A rule's normalized domain plus protocol and exact port-range set is its
identity; duplicates are invalid rather than silently merged. Canonical vectors
include IDNA input to A-label, wildcard/apex mismatch, IPv4 decimal/integer/
short/leading-zero forms, bracketed/unbracketed/scoped/mapped IPv6, CIDR and
`host:port` rejection, port boundary/range ordering, duplicates and
nil/empty/inherit forms.

The Effective Spec has an admitted network rule set. A selected exact domain is
allowed only by the same admitted exact rule or an admitted wildcard that
matches it; a selected wildcard needs the same admitted wildcard. A selected
protocol and every selected port range must be wholly contained by one admitted
rule with the same domain match. Inherit substitutes only the declared
inheritable admitted rules. At connect time the proxy applies the frozen
selected set using exact/wildcard domain matching and protocol/port
containment. The proxy alone resolves the selected domain, rejects prohibited
IPv4 and IPv6 results, and pins one permitted resolution only for that
connection. It never authorizes a guest-supplied IP, `Host`, SNI, DNS cache, IP
family conversion or string `host:port` parsing.

#### Public failure codes and details

The declared `FailureCode` constants are exhaustive for v1. Implementations
map schema/path/target failures to `invalid-argument`, authorization
non-enumeration to `not-found-or-denied`, duplicate-key conflicts to
`operation-conflict`, exhausted lifecycle to `already-terminal`, retention
outcomes to `cursor-expired` or `output-gap`, authority failures to
`grant-widening-denied` or `network-grant-invalid`, profile failures to
`capability-unavailable` or `capability-regressed`, finite limit/admission to
`resource-limit-exceeded` or `control-quota-exceeded`, persisted-policy
incompatibility to `incompatible-persisted-policy`, uncertain side effects to
`outcome-uncertain`, synchronous request cancellation to `cancelled`, deadline
expiry to `deadline-exceeded`, and retryable service/credential-source outage
to `unavailable`. Cancellation and deadline Failures use `RetryNever`; a caller
may make a new explicit call with a new context. New public codes require a
compatibility decision and an OpenAPI/SDK update.

Every non-nil error returned synchronously by `NewClient`, a `Client` method,
stream `Next`, stream `Close`, or Client `Close` is `*Error` or an ordinary
wrapper containing one. `AsFailure` returns its defensive safe Failure copy.
`var target *Error; errors.As(err, &target)` works through ordinary wrappers.
`errors.Is` does not
compare Failure codes and an Error never unwraps a backend, transport,
credential-source or diagnostic cause; it unwraps only the matching standard
context cancellation/deadline sentinel. Arbitrary source/transport errors and
bare context sentinels are translated before crossing the API. Callers branch
on `AsFailure`, and may additionally use `errors.Is` only for context control.

`Failure.Details` has at most eight `FailureDetail` entries, strictly sorted by
`Key`, one entry per key, and only the declared keys. Values are bounded safe
ASCII/UTF-8 scalar metadata (for example a resource name or opaque cursor),
not an error cause, URL, host path, secret, argv, captured output, policy body,
credential or backend identifier. Public failures contain no Diagnostic ID;
authorized diagnostic records remain a separate audited operator interface.

The following field index makes the preceding table exhaustive rather than a
set of illustrative type names. Every listed field uses the row named in the
last column in addition to the baseline rules above.

| Exact public fields | Semantics-table row |
| --- | --- |
| Every `*ID`, `Digest`, `*Cursor`, `Endpoint`, `TLSConfig`, `CredentialSource`, `CredentialSink`, `ClientConfig`, `OperationRef.ID`, `OperationRef.AcceptedAt`, `Page.Cursor`, `Page.Limit`, `VolumePage.Items`, `VolumePage.Next`, `SnapshotPage.Items`, `SnapshotPage.Next` | `NewClient`, `ClientConfig`, endpoint/TLS/credential source; streams/cursors/output events and `Page`. |
| `OperationRequest.ID`, `OperationRequest.Kind`, and its sixteen tagged body pointers; every `Create*`, `Restore*`, process, copy, snapshot, close, reconcile, attach/detach/delete and approval request target/body field | `OperationRequest.ID`, `Kind`, tagged bodies; transfer/artifact/volume/snapshot request fields. |
| `SandboxSpec.Image`, `Resources`, `Environment`, `SecretBindings`, `VolumeAttachments`, `Mounts`, `Tmpfs`, `Capabilities`, `Labels`; `SandboxOverrides`; every field of `ImageRef`, `ResourceLimits`, `SecretBinding`, `VolumeAttachment`, `MountRequest`, `TmpfsMount`, `CapabilityRequirements`, `CapabilityRequirement`, `CapabilityFeature`, `NumericIdentity`, `VolumeSpec` and `SnapshotRiskAttestation` | `SandboxSpec`, `SandboxOverrides`, image, labels, resources, mounts/tmpfs, volume attachments, capability requirements. `Environment` holds only ordinary non-secret values; secrets use `SecretBindings`. |
| Every `Command` field; every `Grant`, `GrantSelection`, `NetworkGrantSelection`, `NetworkRule`, `NetworkProtocol`, `DomainPattern`, `PortRange`, `TransferOptions`, `ArtifactRef`, `AttachmentMode`, `MountMode`, `MountView`, `GrantMode`, `Signal`, `OverwriteMode` and `ApprovalDecision` enum/value | `Command`, identity, `Grant`, network rules and signals; network canonical grammar and matching; transfer/artifact/volume/snapshot request fields. |
| Every `Operation`, `OperationTarget`, `OperationResult`, every `*Result`, `ControlAction`, `Failure`, `Error`, `AsFailure`, `FailureDetail`, `FailureDetailKey`, `OperationState`, `FailureCode`, `RetryClass`, `OperationEvent`, `OperationEventKind`, `OperationGap`, `OutputEvent`, `OutputEventKind`, `OutputChunk`, `OutputFinal`, `OutputGap`, `OutputKind`, `OperationStream` and `OutputStream` field/method | `Operation`, target and result; result and event shape matrix; `Failure`, `Error`, `AsFailure` and typed limit outcome; streams/cursors/operation/output events and `Page`. |
| Every `SandboxInfo`, `SandboxDesiredState`, `SandboxActualState`, `ImageInfo`, `CapabilitySnapshot`, `CapabilityState`, `CapabilityDescriptor`, `KeyLifecycle`, `HostRoute`, `ProcessInfo`, `ProcessState`, `ProcessResult`, `TerminationReason`, `ResourceUsage`, `TreeCleanupState`, `OutputRetention`, `VolumeInfo`, `VolumeAttachmentInfo` and `SnapshotInfo` field/enum | `SandboxInfo`, `ProcessInfo`, `VolumeInfo`, `SnapshotInfo`, capabilities and page values; `Operation`, target and result; `Failure` and typed limit outcome. |

The API compile fixture and these semantics are binding implementation input for
SBX-011/SBX-012; an implementation that changes a type, field or method updates
this reference, generated public API documentation, compile examples and the
two acceptance-ledger suites in the same change.

## 5. Immutable input and canonical wire

### 5.1 Acceptance pipeline

For every Submit, core must:

1. authenticate/bind Principal;
2. bound, decode and strictly validate wire request;
3. deep-copy maps, slices, pointers, labels and tagged unions;
4. consume bounded input bytes into immutable artifact and verify size/digest;
5. normalize paths, Unicode, domain/protocol/port network rules, image, identity and policy;
6. authorize profile and evaluate Grant;
7. resolve finite defaults, image admission and numeric identity;
8. create immutable Effective Spec/request and canonical digest;
9. atomically write ledger acceptance/audit outbox; and
10. dispatch only frozen internal request to routed host agent.

No caller map, slice, pointer, reader, interface value or unresolved default
survives. Backend rechecks security facts at dispatch because host/capability/
admission state may change.

### 5.2 Canonical schema

The durable format is sandbox.control/v1: strict canonical JSON independent of
Go JSON. It has explicit tagged unions for operation, operation target/result,
operation/output event, mount, copy, secret-delivery and capability request.
Go interfaces, credential sources/sinks and constructor transport state never
serialize directly.

It rejects unknown/duplicate keys, trailing values, floats, aliases and
ambiguous encodings. Durations are non-negative integer nanoseconds; byte sizes
and counts decimal unsigned integers; timestamps RFC 3339 UTC. Strings are NFC
UTF-8; NUL/invalid UTF-8 and security-sensitive normalization changes reject.
Object keys sort by normalized UTF-8 bytes. Empty collections have one defined
form.

It bounds bytes, nesting, labels, map entries, arguments, mount/secret/network
rule counts and strings before allocation. It normalizes IDNA2008 domains,
ports/ranges, guest paths and admitted image digests; it rejects every literal
IPv4/IPv6 form as grant input, while the proxy resolver separately validates
resolved IPv4/IPv6 addresses. It records schema/canonicalizer/policy/capability/
key-lifecycle versions. SHA-256 over exact canonical bytes is ledger digest.
Golden vectors cover maps, nil/empty, tagged unions and null Result, duplicate
keys, Unicode, domain/protocol/port grants, wildcard matching, literal-IP
rejection, paths, limits, key rotation and migration.

### 5.3 Effective Spec/defaults

Effective Spec persists canonical request, image/admission evidence, numeric
UID/GID/groups, umask, exact finite limits, capability snapshot, policy/
canonicalizer versions, authority envelope, snapshot ceiling and retention.
Public zero means current documented finite default only during initial
normalization. Retry/restore uses persisted value or returns
IncompatiblePersistedPolicy; it never takes changed defaults.

## 6. Ledger, atomicity, leases and reaper

### 6.1 Ledger identity and retention

Ledger key is Principal scope plus Operation ID. One serializable transaction
writes canonical digest, frozen request/Effective Spec reference, acceptance,
resource reservation, policy/capability versions and attempted audit outbox.

| Repeat | Result |
| --- | --- |
| same Principal/ID/canonical bytes | return existing Operation/state |
| same Principal/ID/different bytes | OperationConflict; no dispatch |
| other Principal/known ID | NotFoundOrDenied, no collision disclosure |
| ID after expiry/tombstone | OperationIDExpired; never silently reuse |

Terminal operation/result metadata retains 30 days by default, redacted output
7 days, tombstone 90 days. StoragePolicy may choose another finite documented
value; resolved value persists. GC/deletion is audited and never makes ID
reusable.

### 6.2 Commit order/reconciliation

Ledger, desired resource state and audit intent use a transactional outbox.
Host dispatch is at-least-once with Operation ID, canonical digest, host
generation and lease fence. Hosts persist per-resource receipts and return prior
receipt for duplicate dispatch.

If host creates VMM/completes work before acknowledgement, reconciliation reads
receipt journal and fenced tags. If acceptance commits but dispatch fails, work
stays queued/redelivers. No authoritative observation after bounded reconciliation
means uncertain; create then fences/reaps or retains cleanup state. A lost
response never invents a live handle.

One exec Operation deduplicates to one observed command start. It cannot make
external effects exactly once; tools require own idempotency key or surface
uncertain external effect.

### 6.3 Leases/reaper

Sandbox host ownership, volume attachments, snapshot readers and cleanup use
finite generation-numbered leases. Default host lease is 60 seconds. Durable
reaper is independent of client/activity: it records cleanup-pending, fences
new work, reaps VMM/process trees/proxy/shares/mounts/disks and records
cleanup-confirmed only after proof or documented lost state. It has bounded
injected-clock backoff and is eventual cleanup owner after worker/control/host
failure. A defer is best effort only.

## 7. Lifecycle, process control and termination

Sandbox desired state is active/closed. Actual state is pending, provisioning,
ready, quiescing, cleaning, failed, unreachable, lost or deleted. Process is
accepted, starting, running, terminating or terminal. Process failure normally
affects only Process; guest/host failure can fail/lost Sandbox.

| Action | Source | Serialized effect | Race result |
| --- | --- | --- | --- |
| create/restore | reservation only | pending then provisioning | duplicate reconnects |
| exec/copy | ready | non-exclusive lease | rejected while quiescing/cleaning/closed |
| snapshot | ready | quiescing exclusivity | unordered work gets SandboxBusy |
| close | any non-deleted | desired closed/fence/cleanup | calls converge on cleanup record |
| reconcile | non-deleted | inspect/repair under lease | never starts command |
| delete/tombstone | cleaned/expired | retained tombstone | lease/generation makes typed race |

Close is idempotent by Operation ID. Different wait deadlines observe same
cleanup; cancelling wait never cancels cleanup. Failed objects retain safe
failure through retention. Ready with no Process is idle; there is no unused
stopped state.

### 7.1 Commands and context

Secure Command requires absolute clean POSIX executable path, non-empty typed
argv, bounded args, declared existing workdir, numeric user/groups, fixed umask,
deterministic base environment and Grant. PATH lookup is absent. Host HOME/XDG/
tool config and inherited descriptors are never inherited.

StartDeadline covers acknowledgement only. RuntimeLimit, signal/kill, close,
lease/reaper and opt-in BindLifetimeToOperation own lifetime. Cancelling Wait
or Replay only abandons observation. Portable signals are interrupt, terminate,
kill and hangup; unsupported fail closed. Kill is durable Operation.

### 7.2 ProcessResult

ProcessResult has timestamps, exit code only if known, signal only if observed,
usage, separate stdout/stderr retention, tree cleanup and exactly one reason:

~~~text
exited                 signaled              timed-out
oom-killed             output-limit          cancelled
killed-by-caller       sandbox-closed        sandbox-lost
startup-failed         infrastructure-failed outcome-uncertain
~~~

Exited can have non-zero status and is not Go/control error. OutcomeUncertain
has no invented exit code. Tree cleanup is confirmed, pending, not-required or
unknown. Adapters cannot flatten timeout/OOM/signal to exit 137. First durable
terminal observation wins; later controls are typed already-terminal.

## 8. Output, redaction and replay

Core owns bounded spool/tee per stdout/stderr. Hosts send ordered raw chunks
over protected control; core redacts before bytes enter durable output, events,
tails, logs, errors or metrics. Raw chunks never enter output store.

Each stream stores sequence, retained count/tail, earliest retained and
independent truncation/gap. ReplayOutput returns ordered chunks, gap after
retention loss and completion/result marker. Reconnects deduplicate
at-least-once replay by sequence.

| Limit | Required behavior |
| --- | --- |
| MaxProducedOutputBytes | drain safely then kill complete tree with output-limit; no pipe deadlock |
| MaxRetainedOutputBytesPerStream | process continues; retention emits independent stream gap/truncation |

Wait progresses without reader. Slow consumers have bounded page/window and may
observe gap; they cannot backpressure guest. Core stores bounded redacted tails.

Redactor pins operation secret values. Empty patterns/total pattern bytes above
limit reject. Per stream it buffers at most longest pattern minus one byte,
uses longest then binding-order, replaces each with ASCII [REDACTED], and is
deterministic across chunks/binary/overlap. Rotation cannot change a running
process pattern set.

## 9. Filesystem, portable transfer and host mounts

### 9.1 Guest path/transfer

Guest paths are absolute clean POSIX beneath permitted roots. Empty, relative,
dot-dot, NUL, reserved roots, Unicode ambiguity and overlap reject. Production
uses descriptor-relative opened roots and rejects symlink/replacement/
mount-crossing escape.

Copy-in/out is required portable workspace path before mounts. It transfers
files or bounded directory archives via authorized immutable artifacts:

- source has known size/SHA-256; unknown/short/excess/mismatch rejects;
- archive bounds entries/depth/expanded bytes/files/inodes and rejects devices,
  sockets, FIFOs and escaping links;
- overwrite is fail-if-exists or atomic-replace; atomic replace stays same root
  and fsyncs when durable;
- ownership is numeric or inherit; mode is umask-masked and no special bits;
- cancellation removes staging, preserves previous atomic target and returns
  partial-cleanup observation.

Copy-out returns Artifact ID/size/digest/media type/owner/retention, never
unbounded byte slice.

### 9.2 Host-mount profile

RO/RW mounts are separately gated. Final release uses per-sandbox jailed share
agent and exact source identity. Source is from configured export root, opened
descriptor-first and pinned by filesystem/device/inode/generation throughout
lease; no later path resolution.

- symlink traversal, special files, sockets, devices and unsafe hard links reject;
- rename does not redirect; delete/replacement/identity change means
  source-invalid and all access fails closed;
- live view sees allowed mutations; frozen view is copy-on-attach;
- RW intentionally delegates create/modify/delete only within source view;
- execute needs explicit profile and Grant; trusted execution still needs
  immutable loader/configuration;
- guest cross-boundary rename/link rejects;
- share agent is unprivileged with pre-opened descriptors, mandatory access
  control and narrow protocol. Share compromise is explicit host-agent TCB.

Firecracker reports unsupported until identity/traversal/TOCTOU/special-file/
daemon suites pass. Local rejects mounts.

## 10. Grant truth table

Effective Spec declares maximum admitted authority. Command Grant selects subset
only. Each sensitive family is none, select or inherit; nil never inherits.

| Form | Secrets | Mounts | Network |
| --- | --- | --- | --- |
| omitted/Go zero/empty | none | none | deny all |
| none | none | none | deny all |
| select non-empty | named admitted bindings | named admitted mount/mode | named admitted domain/port |
| select empty | invalid | invalid | invalid |
| inherit | only explicit inheritable/policy-approved | same | same |
| unknown/duplicate | invalid | invalid | invalid |
| outside Effective Spec | GrantWideningDenied | GrantWideningDenied | GrantWideningDenied |

Canonical v1 normalizes absent/empty to none and rejects ambiguous legacy wire.
A command without Grant gets no secret/mount/network even if sandbox envelope
has them. Network `select` is the typed `NetworkGrantSelection` grammar in
section 4.4, never a string convention: every domain, protocol and port range
is canonical and can only narrow the frozen Effective Spec. This table is
conformance-tested for exact/wildcard domain matching, all literal IPv4/IPv6
forms failing closed, resolved private-range refusal, port containment,
duplicate equivalence and inherit.

## 11. Secrets, taint and elevated credentials

### 11.1 Contextual resolution

SecretResolver is internal composition. It receives signed Principal,
Sandbox/Process/Operation IDs, declared binding, purpose, policy and expiry. It
returns bounded non-empty value plus opaque version/expiry/audit metadata by
ephemeral channel. Undeclared binding cannot resolve. Control records safe
provenance only, never bytes/caller secret names.

Accepted exec pins version. Recovery obtains same version or becomes
IncompatibleSecretVersion before start; rotation never silently alters retry.
Duplicate/excess/non-revocable delivery rejects. Resolver calls audit. SDK
secrets are just-in-time in non-snapshotted tmpfs/equivalent and revoke after
confirmed complete tree reap. Bytes never enter spec/hash/ledger/log/error/
metric/event/volume/snapshot manifest.

### 11.2 Taint/snapshot limit

Delivery writes known-secret-exposed taint with safe binding/version class and
operation provenance. Writable tainted sandbox attachment writes persistent
volume taint; that volume taints every attached Sandbox. Taint stays in
manifest/tombstone through reconciliation.

Writable external/host storage and ordinary env, argv, stdin, image, network
and app credentials cannot be fully tracked. They set unknown-secret-path where
observable, but taint proves neither arbitrary byte presence nor absence.

Snapshots exclude SDK secret tmpfs, process memory, sockets, host mounts and
named-volume content. Default denies snapshot of tainted or writable external/
unknown path. Operator policy may require operation-bound
SnapshotRiskAttestation naming risk/owner; manifest preserves it. Never call a
snapshot secret-free.

### 11.3 Elevated credentials

Writable-guest helper pathname is never trust. High-value credentials use
external typed broker or proven trusted-exec: immutable admitted executable
digest, numeric identity, immutable workdir/mount view, sanitized environment,
verified loader dependencies and typed args. Mismatch rejects before resolve.
Until proved, Grant authorizes recipient process tree.

## 12. Egress profile invariant

With egress selected, only guest external TCP/UDP path is authenticated
mandatory host proxy. Guest has no routable interface/default route/direct DNS/
host/private/link-local/metadata/control-plane route. Guest requests one
normalized domain plus protocol/port; proxy validates, resolves and connects.

> For a Process with explicit network Grant, every external connection accepted
> by proxy originates from a currently allowed normalized destination domain
> and protocol/port from Grant. The proxy alone resolves that domain, rejects
> prohibited result addresses and pins the permitted resolution for that
> connection. No guest-supplied literal IP is authority and no other guest
> connection is routable.

This is destination restriction, not TLS/HTTP inspection, application identity
or DLP. Granted example.com:443 may use arbitrary SNI/ECH/Host; none authorizes
a different proxy destination. Redirect is new checked connection.

Rules: section 4.4's typed grammar is the authority. Domains use IDNA2008,
exact names or one leftmost whole non-public-suffix wildcard, with at most eight
CNAME hops. The proxy resolves a selected domain just before connecting,
normalizes every IPv4/IPv6 answer, rejects loopback, private, link-local,
multicast, unspecified, documentation, benchmark, reserved, metadata and
control-plane ranges, and pins only a permitted answer for that connection.
Any guest request whose destination parses as literal IPv4, bracketed or
unbracketed IPv6, IPv4-mapped IPv6, scoped IP, CIDR or `host:port` fails before
resolution as `FailureNetworkGrantInvalid`; the proxy never turns a domain
rule into literal-IP authority. The guest has no independent IP/DNS/cache
route; DNS/DoH have no route. Reuse is only exact domain/protocol/port/
Principal/Process policy. Proxy outage/auth/policy mismatch fails closed and is
quota-accounted; SNI/Host mismatch/ECH/shared IP are explicitly not validated.
DNS-to-IP firewall alone never qualifies.

## 13. Resources, quotas and admission

Every production Effective Spec is finite. Zero resolves through declared
finite default before acceptance. Limits constrain sandbox/process; admission
quotas constrain Principal/control/fleet.

| Class | Bounded dimensions | Exceed |
| --- | --- | --- |
| Sandbox | milliCPU/period, memory, root overlay, tmpfs, PIDs, process count, open files, inodes, files, lifetime | typed resource/timeout/admission |
| Process/I-O | runtime, produced/retained output, transfer bytes/count/depth, archive expansion, read/write bytes/IOPS | output/transfer/I-O limit |
| Network | connections, proxy streams, ingress/egress bytes/bandwidth | connection/rate limit |
| Storage | volume/snapshot count/bytes/inodes, attachments, leases, image conversion bytes | quota/admission |
| Control | request bytes, operations/watches, cursors/pages, logs/events, outbox, principal/global capacity | ControlQuotaExceeded before dispatch |

CPU uses integer millicores and cgroup period. Aggregate tmpfs is enforced with
per-mount limits. Adapter unable to enforce advertised precision rejects
request. Admission checks capacity/image/proxy/share budget/fair bounded queue
deadline before side effect.

## 14. Images, volumes and snapshots

### 14.1 Images/identity

Production images are immutable content identities admitted under declared
ImageAdmissionPolicy. Admission verifies signature/provenance, architecture,
guest protocol, numeric non-root user, special-file and daemon policy. Digest
is identity, not provenance proof. SandboxInfo reports safe digest,
architecture, UID/GID/groups, protocol, policy version, root overlay and
capabilities. Missing evidence rejects create/restore; names resolve at
admission, never command time.

### 14.2 Volumes

Volume manifest stores owner/ID, format/schema, encryption/integrity,
byte/inode quotas, taint, attachment generation, lease holder/expiry/mode,
timestamps and tombstone. VolumeInfo never uses racy Attached boolean.

Attach/detach are Operations. RW generation exclusive; RO concurrency only
when advertised coherent. Multi-volume create reserves leases transactionally;
reaper reconciles/rolls back. Delete fences attaches, waits/force-reaps per
explicit policy then tombstones. IDs do not silently reuse.

### 14.3 Snapshots

Snapshot is quiesced disk-only root-overlay artifact. Manifest has owner/ID,
source Sandbox, source Effective Spec/policy ceiling, image/admission,
capability/schema/format, creation operation/base, encryption/integrity,
root digest/size, taint/unknown path, attestation, retention/state/tombstone.

Production requires encryption at rest/integrity. Creation quiesces, stages,
verifies, atomically publishes manifest/ledger and reaps staging. Inspect/list/
lease/delete/tombstone/restore are Operations. Restore default uses source
Effective Spec/ceiling; override only narrows and passes current auth/admission/
capability. Image/guest/schema/integrity/encryption/capability/policy mismatch
fails explicitly. Delete/restore serialize by lease/generation.

## 15. Capabilities, SPI and adapters

Capabilities are a versioned structured Snapshot, not a boolean bag. The public
Snapshot has an immutable canonical digest and separately describes control
protocol, isolation, guest architecture/protocol, resource precision,
reconnect/reaper, image admission, output, transfer, mount mode/view/execute,
volume, snapshot/encryption, egress/proxy/rules, secret/trusted-exec proof,
signals and safe trust/signing-key lifecycle. Each `CapabilityDescriptor` has
an explicit unavailable/declared/enforced state, contract version, conformance
version, data-plane description and limit precision; `Features []string` is
not a public substitute.

Client declares typed feature/minimum-state requirements. Control negotiates,
canonicalizes and persists the Snapshot in Effective Spec, SandboxInfo and
snapshot manifest. Host rechecks its digest, every descriptor and
`KeyLifecycle` at dispatch/restore. Regression, missing state, weaker precision,
expired signing lifecycle or revoked trust epoch fails closed with
CapabilityUnavailable or CapabilityRegressed; no code branches on backend name.

| Profile | Delivered authority/proof |
| --- | --- |
| Foundation | Firecracker/KVM, jailed unprivileged VMM, cgroups v2, auth guest, immutable non-root image, bounded overlay/tmpfs, argv, deny-all, reaper |
| Portable workspace | section 9 transfer/path proof |
| Egress | section 12 proxy/bypass proof |
| Volumes | manifest/quota/encryption/integrity/lease/taint |
| Snapshots | quiesced manifest/encryption/integrity/ceiling/recovery |
| Host mounts | jailed descriptor-pinned RO/RW proof |
| Command secrets | contextual delivery/tree isolation/revocation/redaction/taint |
| Trusted execution/broker | external broker or immutable admitted proof |
| Local unsafe | explicit acknowledgement/refusal; not production evidence |
| Deterministic fake | scripted durable state/result/gap/fake clocks; no execution |

Backend SPI is internal. It gets NormalizedDispatch, effective digest, lease
fence, IDs and bounded artifacts only. It cannot get public Spec, decide Grant,
own ledger/output/audit or return public errors. Malicious adapter tests prove
core rejects widened Grant/input mutation/unredacted output/bad ordering/backend
error leakage.

Local needs IUnderstandLocalSandboxIsUnsafe acknowledgement. It sanitizes
environment only for convenience and rejects real secrets, egress, mounts,
volumes, snapshots and trusted-exec. Synthetic resolver is test-only.

## 16. Audit, errors, runtime integration and gates

Audit facts ordered per Operation: attempted, authorized, accepted, dispatched,
committed, terminal, reconciled. Ledger/resource acceptance plus attempted/
authorized audit outbox is one transaction: failed persistence prevents
dispatch. Export is at-least-once and dedupes operation/fact sequence.
Synchronous external audit outage queues work before dispatch; no false
cross-system atomicity claim. Reconciliation records that limitation.

Public Failure exposes stable code, safe message, retry class and bounded safe
details. Synchronous methods carry it through `Error`/`AsFailure`; only a
standard context cancellation/deadline sentinel may unwrap for `errors.Is`.
Backend, transport, credential-source and diagnostic causes never escape
through unwrap, formatting, JSON or logs. Operator DiagnosticID records are
separately authorized/audited. Logs, metrics/traces use safe IDs and redact
secret bytes, unsafe argv/content, host paths and proxy internals.

Temporal workflow stores domain/Operation IDs, effective policy/capability
references and bounded cursors only. Activities submit/heartbeat/recover by
Get/Wait/Replay/Submit same ID. Cancellation submits close/kill and watches
durable cleanup. Retry distinguishes validation/control/policy/result/host
loss/unknown external effect. Output event/blob sinks carry sequence/gap/final
markers; activity loss cannot silently lose output.

Foundation protects host availability, host filesystem/network credentials,
tenant isolation, SDK secret bytes and safe evidence assuming supported
Linux/KVM, patched host/hypervisor, correct control auth, admitted images and
uncompromised host-agent/proxy/share TCB. It does not promise host kernel/
hypervisor defense, intentional disclosure, DLP, application identity, live
memory snapshots, inbound network, PTYs, GPU/device/nested virtualization or
generic privileged escape.

Benchmark evidence names host/KVM/kernel/agent, image/overlay, desired-state/
admission, durability/profile/concurrency/quota/output/queue. Cold/warm create,
exec, output, copy, snapshot, close/reap/noisy neighbor include ledger/outbox,
proxy/share/admission/conversion/teardown and report p50/p95/p99, capacity,
cleanup lag and saturation. No vague latency objective is accepted.

The exhaustive requirements, profile evidence and tests are in
[sandbox-feature-inventory.md](sandbox-feature-inventory.md). All externally
visible tests use durable control interface except deliberate internal SPI tests.

## 17. Required implementation sequence

1. Principal-bound ledger/control client, canonical wire and fake create/
   lookup/reconnect/conflict slice.
2. Host routing/lease/reaper, typed process/output recovery and declarative
   infrastructure reconciliation.
3. Firecracker foundation plus portable transfer.
4. Egress, volume, snapshot, mount and command-secret/trusted-exec profiles,
   each with stated security suite.
5. All profiles wired into Workspace Agent and final release matrix.

This does not authorize omission of steps 4 or 5. Each slice records S9/S10
seam, three-to-five-case behavior matrix, red/green evidence and docs. Tests
use injected time/bounded synchronization, not sleeps/unbounded polling.
