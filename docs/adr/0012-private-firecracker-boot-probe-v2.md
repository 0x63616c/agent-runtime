---
status: accepted
---

# Private Firecracker boot-probe v2 protocol

The limited Firecracker boot probe is an operator-only, private control path.
It will use a new `sandbox.host-control/v2/firecracker-boot-probe` protocol
and durable lifecycle. It is neither a public sandbox API nor an authorization
for general sandbox create, exec, or restore work.

## Decision

M3 and the M4 host will implement this path as a distinct protocol vertical.
It does not modify, reinterpret, or fall back to
`sandbox.host-control/v1`.

The M3 control store owns a PostgreSQL-backed boot-probe session. Each session
binds exactly one authenticated host generation, host-instance session,
assignment, tenant/principal, Operation, Effective-Spec and capability
digests, and trusted M4 identity. It retains canonical v2 lease-chain state
under a compare-and-swap version and has a separate irreversible lifecycle:
prepared, launch-authorized, launch-started, cleanup-pending, and
cleanup-confirmed. Lease successor and fence changes occur in the same control
transaction as the session state. A session is never recreated to renew a
lease.

Before Jailer launch, the M4 host must fsync a host-instance-exclusive journal
recording the exact session, current delivery, trusted M4 identity, and
launch-start intent. After that point, ambiguity, restart, expiry, revocation,
or loss of a terminal observation converges to cleanup-pending; it never
authorizes a second launch. An acknowledgement by itself is insufficient. The
host must submit a signed boot-probe observation bound to the exact delivery,
identity, serial marker, and guest nonce PING/PONG result. Control classifies
only exact current or retained-superseded observations.

The M4 host stages the exact M4 resources and compiles its trusted identity
before accepting a grant. It validates the grant against that identity before
starting Jailer. M3 never parses generic dispatch payload into a Firecracker
plan or selects host paths, fixtures, Jailer arguments, or guest credentials.
The infrastructure operator owns reviewed fixture provenance, KVM/Jailer
environment, certificates, enrollment policy, and migrations. Enrollment must
declare the permitted M4 fixture/authority profile; a host's self-reported
identity alone is not authority to launch.

The current private codec boundary is
`internal/firecrackerbootprobeprotocol`. It accepts a command only when a
launch-authorized v2 session's exact envelope/delivery/nonce/lease/fence tuple
matches the existing launch grant, an enrollment resolver binds both command
and observation keys to that host generation, and a locally compiled M4
identity verifier accepts the grant tuple. The verifier is a sealed
Firecracker compiler output, not an injectable host assertion. It verifies an
M4 observation only through an opaque command-verification result. The contract proves no
PostgreSQL, network route, journal, Jailer, guest, or Linux/KVM execution;
those remain separate required evidence.

## Why v1 cannot carry this path

The current v1 host protocol remains the generic enrolled reference-host
protocol. Its delivery seed emits `nonce_...`, which is not the canonical raw
base64url nonce required by the v2 lease contract. It persists no host-instance
session, and its mTLS identity identifies a host generation rather than one
exclusive M4 boot session. Its renewal transaction updates the generic
assignment/envelope but has no v2 state CAS.

The reference-host journal is keyed by assignment and Operation and can accept
a higher lease before it records a start. It cannot retain v2
current-versus-superseded delivery history or prove a Firecracker serial
PING/PONG. Generic v1 results also have no binding for the trusted M4 identity
or serial observation. Configuration document version 2 is only v1 trust
configuration; it is not this wire protocol.

## Authority and evidence

| Owner | Authority | Prohibited action |
| --- | --- | --- |
| Infrastructure operator | Fixture/provenance acceptance, protected Linux/KVM and Jailer environment, CA material, enrollment profile, migrations. | Grant runtime startup migration or certificate authority. |
| M3 control | Authenticate the enrolled host, allocate the operator-only session, sign and persist grants/successors, own lease/fence, quarantine, and cleanup state. | Interpret generic dispatch payload as M4 input or launch a Jailer. |
| M4 host | Stage approved resources, compile/validate its exact trusted identity, fsync launch intent, observe signed boot result. | Choose tenant, principal, assignment, capability, fixture policy, or a new lease. |
| Jailer | Enforce the already compiled Jailer configuration. | Renew control authority or infer cleanup. |

Implementation evidence must include contract refusal tests for wrong session,
identity, nonce, delivery, fence, delayed acknowledgement, and serial result;
PostgreSQL CAS/restart/quarantine/cleanup tests; and a multi-process host
journal recovery test. A Linux/amd64 protected runner with `/dev/kvm`, the
accepted immutable fixture set, and retained M3-to-M4 evidence is required
before claiming Firecracker execution or isolation. This decision itself is
not that evidence.

## Rejected alternatives

- Extend v1 in place or treat its configuration version as protocol v2. That
  would weaken or silently reinterpret its stable generic host contract.
- Add only a PostgreSQL v2 state table. Durable but unreachable state is not a
  boot-probe path and cannot fence an irreversible launch.
- Use `HostExecutor` or parse the generic dispatch body as a Firecracker plan.
  This lets generic host routing choose M4 authority and violates the M3/M4
  seam.
- Accept a self-reported M4 identity without an operator-declared enrollment
  profile, or launch before the host records durable start intent.
- Expose this protocol through the public Go SDK or public sandbox HTTP API.
  The boot probe remains a narrow operator prerequisite, not a public runtime
  capability.
