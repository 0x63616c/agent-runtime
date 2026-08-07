# Sandbox host-control v1

`sandbox.host-control/v1` is the private protocol between `sandbox-control`
and enrolled execution hosts. It is not part of the public `sandbox` Go API;
public callers see only Principal-scoped Operations and runtime-owned states.
No host ID, certificate, assignment, lease, fence, or backend type crosses that
boundary.

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
denial. Old and next certificate generations may overlap during rotation;
revocation targets one generation and does not reactivate or weaken another.

`attestation_digest` is operator-supplied enrollment evidence metadata only.
M3 stores and binds that bounded reference but does not collect or verify a
hardware attestation. It must not be described as attestation proof. Linux/KVM
and Firecracker trust claims remain gated on M4.

## Signed assignment envelope

Before returning an assignment, control commits its operation routing, lease,
fence, exact canonical envelope bytes, digest, and outbox fact in one
serializable transaction. The envelope is canonical JSON signed by the
control-plane Ed25519 key and transported over mTLS. It binds:

- protocol, envelope, delivery and nonce identities;
- issue and finite expiry instants plus control signing-key ID;
- Host ID/generation, Assignment ID, lease epoch, and fencing token;
- tenant and Principal, Sandbox/Process/Operation identities and operation kind;
- Effective-Spec, capability-snapshot, canonical-request, and payload digests;
- the exact bounded canonical operation request; and
- `host-proposed/control-owned-v1` output sequencing.

The host strictly decodes the canonical bytes, selects the declared control
key from an explicit key set, verifies signature and payload digest, and checks
host generation and time interval before journaling. Unknown fields, trailing
JSON, altered bytes, unknown signing keys, replay to another host/generation,
and expired envelopes are refused.

TLS supplies transport confidentiality. M3 does not add application-layer
envelope encryption beyond TLS and therefore makes no protection claim after a
legitimate endpoint receives plaintext.

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
and non-terminal, including after a receipt. The reference host fsyncs its
receipt journal before its single simulated effect. After process restart, the
same envelope returns the same receipt and execution count; it can therefore
recover both a lost receipt acknowledgement and a lost result acknowledgement
without executing twice. This is protocol/idempotency evidence, not a promise
that arbitrary external effects are exactly once.

`cmd/sandbox-host` is a separately runnable, one-poll reference role. It proves
mTLS, signature refusal, journal-before-effect ordering, restart, receipt, and
result behavior. It deliberately performs no guest process or VM work and
provides no isolation, cgroup, network, image, mount, output-storage, Jailer,
KVM, or Firecracker evidence.
