# Sandbox host-control v1

`sandbox.host-control/v1` is the private protocol between `sandbox-control`
and enrolled execution hosts. It is not part of the public `sandbox` Go API;
public callers see only Principal-scoped Operations and runtime-owned states.
No host ID, certificate, assignment, lease, fence, or backend type crosses that
boundary.

The current control and host process declarations use configuration version 2.
That is separate from this stable private protocol identifier: version 2 is the
first declaration format that can express the complete versioned control trust
bundle. See the [operator migration procedure](../operations/sandbox-host-routing.md#configuration-format-v1-to-v2-migration)
for the deliberate non-mixed-version upgrade.

## Trust and enrollment

An infrastructure operator provisions each host generation in PostgreSQL
before it may connect. An enrollment binds a Host ID and generation to exactly
one tenant, pool, protocol version, mTLS leaf-certificate SHA-256 digest,
Ed25519 result-signing public key, capability digest, finite expiry, and
security state. The database never stores certificate bodies or private keys.

The private listener uses TLS 1.3 with a dedicated server identity and requires
a client certificate from its explicit client CA. The leaf must contain exactly
one URI of this form:

```text
spiffe://agent-runtime/sandbox-host/<host-id>/generation/<positive-generation>
```

The URI identity, certificate digest, generation, protocol, status, and expiry
must all match the durable enrollment. Missing, unenrolled, expired, revoked,
quarantined, incompatible, or wrong-generation identities receive the same
denial. The operator procedure permits old and next certificate generations to
overlap during a future rotation; revocation targets one generation and does
not reactivate or weaken another. M3 does not yet retain a live
certificate-rotation proof.

Provisioning receives raw bounded attestation evidence, its explicit profile,
and a verifier predicate. The durable store invokes the predicate itself and
atomically persists only a derived digest and safe outcome. It rejects a
caller-supplied verified state. Verification failure is durably
`attestation-failed` and cannot authenticate. The local-unsafe profile records
`metadata-only`; it does not claim hardware or runtime-integrity attestation.
Linux/KVM and Firecracker trust claims remain gated on M4.

## Signed assignment envelope

Before returning an assignment, control commits its operation routing, lease,
fence, exact canonical envelope bytes, digest, and outbox fact in one
serializable transaction. The envelope is canonical JSON signed by the
control-plane Ed25519 key and transported over mTLS. It binds:

- protocol, envelope, delivery and nonce identities;
- issue and finite expiry instants plus control signing-key ID/version and the
  monotonic revocation epoch;
- Host ID/generation, Assignment ID, lease epoch, and fencing token;
- the SHA-256 digest of the enrolled host observation key that control will
  use for result and output verification;
- tenant and Principal, Sandbox/Process/Operation identities and operation kind;
- Effective-Spec, capability-snapshot, canonical-request, and payload digests;
- the exact bounded canonical operation request; and
- `host-proposed/control-owned-v1` output sequencing.

The host strictly decodes the canonical bytes, atomically selects the declared
control key from the complete current/next trust snapshot, verifies its key
version, revocation epoch, signature, payload digest and declared key validity,
then checks host generation and envelope time before journaling. A strictly
newer snapshot may rotate current to next during overlap and later retire it.
Unknown fields, trailing JSON, altered bytes, legacy zero bindings, retired or
revoked keys, replay to another host/generation, and expired envelopes are
refused. The atomic snapshot primitive has unit coverage for this lifecycle;
the reference host does not yet implement a watched configuration reload, and
M3 has no retained live control-trust-rotation proof. Retirement lineage is
in-memory and lasts only for one running `AtomicTrust` instance; a restarted
host needs authenticated persisted trust history before it can make an
across-restart retirement claim, and M3 does not yet provide that persistence.

TLS supplies transport confidentiality. M3 does not add application-layer
envelope encryption beyond TLS and therefore makes no protection claim after a
legitimate endpoint receives plaintext.

## M3-to-M4 boot-probe composition

`internal/sandboxm4bridge` is the only private composition seam from a host
assignment into the fixed-purpose Firecracker boot-probe grant. It strictly
verifies the canonical control signature against the complete current trust
snapshot, Host ID/generation, signing-key validity, revocation epoch, lease,
fence, assignment, tenant/principal and immutable digest tuple. It additionally
derives the host observation public key from the host's injected signing key
and requires its SHA-256 digest to match the value signed into the assignment.
Only then can it produce the bounded M4 grant.

The bridge does not parse an arbitrary dispatch body, grant another operation
kind, select a host, start a Jailer, launch a VM, or accept a stale envelope.
The grant remains a private composition input; M4 still has to prove the
Linux/KVM execution boundary separately.

## Pull, receipt, heartbeat, output, and result

All methods are bounded `POST application/json` operations on the private
listener:

| Path | Contract |
| --- | --- |
| `/sandbox.host-control/v1/pull` | Authenticates the host and returns its current non-terminal persisted envelope verbatim, or atomically assigns the oldest tenant/capability-compatible accepted Operation. No work is `204`. |
| `/sandbox.host-control/v1/receipt` | Commits one receipt digest for the current assignment/fence. An exact retry is acknowledged as a duplicate; a changed receipt fails closed. |
| `/sandbox.host-control/v1/heartbeat` | Advances lease epoch and fencing token and commits a newly signed envelope. The old epoch/fence becomes stale immediately. |
| `/sandbox.host-control/v1/output` | Verifies a host-signed bounded stdout/stderr integrity header. Control accepts only the next sequence per assignment/stream; an exact duplicate is idempotent, while an altered duplicate or gap is a protocol violation. Chunk bytes belong to the separate output owner and are not stored in this table. |
| `/sandbox.host-control/v1/result` | Verifies the enrolled host signature and exact assignment, lease, fence, Principal, Operation, Effective-Spec and capability bindings before committing an allowed state transition. |

A malformed signed message, impossible receipt, stale binding, output gap, or
invalid result quarantines the generation and atomically fences its
non-terminal assignments as `uncertain`. A stale result can never overwrite a
newer lease or assignment.

## Recovery and reference-host limits

Pull replays the exact persisted envelope while its assignment remains current
and non-terminal, including after a receipt. Before an injected host executor
can cause an effect, the reference host fsyncs a stable signed `started`
observation. After restart, a receipt with durable `started` but no durable
terminal observation is never executed again: the host posts a signed
`uncertain` result so control's fenced cleanup/requeue path remains the sole
authority. Lost receipt, `started`, and terminal-result acknowledgements replay
their exact durable wires. This is protocol/idempotency evidence, not a promise
that arbitrary external effects are exactly once.

`cmd/sandbox-host` is a separately runnable, long-lived reference role. It
requires both `--config` and an explicit finite `--poll-interval`. A verified
no-work poll is a healthy bounded observation for its supervisor; transient
transport and control-server failures retry with a deterministic capped backoff.
Configuration, trust, journal, and protocol refusals remain terminal rather
than spinning. It proves mTLS, signature refusal, journal-before-effect
ordering, restart, receipt, and result behavior. It deliberately performs no
guest process or VM work and provides no deployment, isolation, cgroup,
network, image, mount, output-storage, Jailer, KVM, or Firecracker evidence.
Its default reference executor is deliberately unavailable and therefore
records `uncertain`, never a fabricated successful effect.
