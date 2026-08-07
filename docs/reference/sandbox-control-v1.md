# Sandbox control v1

`sandbox.control/v1` is the declared public contract for durable sandbox
control. Its Go types are in [`sandbox`](../../sandbox/api.go); its complete
semantic authority is the accepted [sandbox specification](../specs/sandbox.md).

## Current implementation boundary

The package provides a deterministic in-memory control fixture and a strict
public HTTPS operation transport backed by the separately runnable
`sandbox-control` role.
`NewClient` resolves an explicit named trust bundle, parses private cloned TLS
roots, refuses redirects and ambient system trust, applies a request-scoped
credential, and completes the strict `/sandbox.control/v1/bind` handshake
before returning. `Submit`, `GetOperation`, `WaitOperation`, and
`WatchOperation` use canonical, bounded `sandbox.control/v1` envelopes. The
role durably accepts those operations in PostgreSQL, reconnects after a
separate-process restart, and optionally exposes a distinct mutually
authenticated listener to durably enrolled reference hosts. Resource queries,
output/artifact content storage, a real process adapter, and Firecracker are
not implemented. This is durable control and host-protocol evidence, not
evidence of guest isolation or VM execution.

## Client and identity

Construct a client with an HTTPS origin, explicit TLS server name, opaque trust
bundle reference plus a `TrustBundleSource`, a credential source, and a
positive timeout no greater than one minute. Trust resolution returns bounded
versioned cloned public PEM roots; missing or invalid roots fail without system
root, file-path, or insecure-TLS fallback. `NewStaticTrustBundleSource` is the
ordinary finite in-memory adapter. A credential source applies exactly one
request-scoped authorization value to a revocable sink; it must not be
serialized or retained in a public operation.

The control bind envelope has version `sandbox.control/v1`. A bind response is
an exact JSON object with `version`, `kind`, `assertion`, and `expires_at`.
Unknown fields, duplicate keys, trailing JSON values, invalid versions, blank
assertions, and non-UTC expiry values are rejected before authorization. The
assertion remains transport-private.

Sandbox, process, volume, snapshot, and operation IDs are opaque identifiers,
not authorization. The ledger key is the authenticated principal plus
`OperationID`. A repeated ID with byte-equivalent canonical input reconnects;
a changed request conflicts. Another principal receives the same
`not-found-or-denied` outcome for guessed IDs whether or not they exist.

## Operations and Effective Spec

Every mutation is an `OperationRequest` with exactly one of sixteen tagged
bodies selected by `Kind`: create/restore sandbox, exec, signal/kill, copy
in/out, snapshot, close/reconcile, create/attach/detach/delete volume, delete
snapshot, and approve-sensitive-operation.

Before acceptance, control deep-copies all maps, slices, pointers, and tagged
bodies; validates the selected form; resolves zero resource values to finite
policy defaults; and records an immutable Effective Spec. The Effective Spec
includes the canonical request digest, finite resource limits, policy version,
canonicalizer version, capability snapshot version/digest, image-admission
version and safe admitted image metadata. Retry keeps that recorded value; it
never adopts new defaults. If a later policy can no longer admit it, retry
returns `incompatible-persisted-policy`.

The canonical form is `sandbox.control/v1`: all fields and nil/empty collection
forms are distinguished, maps are sorted, tagged body presence is explicit,
and SHA-256 over the exact owned bytes becomes the request digest. Caller
mutation after `Submit` cannot change the accepted request, authority, or
digest.

## Lifecycle, process result, and output

`WaitOperation` observes a durable terminal state; cancelling its context only
ends that observation. It does not cancel the accepted operation. Process
results retain a typed reason (`exited`, `signaled`, `timed-out`, `oom-killed`,
`output-limit`, `cancelled`, `killed-by-caller`, `sandbox-closed`,
`sandbox-lost`, `startup-failed`, `infrastructure-failed`, or
`outcome-uncertain`) rather than flattening all failures to an exit code. The
first terminal observation wins; later controls receive `already-terminal`.

Stdout and stderr each flow through a core-owned tee/spool. Output is redacted
before it is retained, replayed, or exposed. Each stream has independent
produced and retained byte limits, ordered cursors, retention gap records, and
one final result event. A slow or disconnected reader cannot block process
progress: replay returns retained chunks, any explicit gap, then the final
marker. Exceeding the produced limit produces the typed output-limit terminal
outcome; exceeding retained output only truncates replay.

## Limits, admission, images, and security

Every resource value is finite after acceptance. Limits bound one sandbox or
process; admission separately limits principal/control capacity. A per-resource
breach is `resource-limit-exceeded`; an admission breach is
`control-quota-exceeded`, both before any backend dispatch in the fixture.

Images use immutable SHA-256 content identities. A digest alone is not
provenance: image admission supplies safe inspectable metadata—architecture,
numeric identity, guest protocol, and admission-policy version—and rejects
unadmitted or incompatible content. The fixture's generic image metadata is
only deterministic test data, not an admission attestation.

The security posture is deny-by-default. Omitted command grants mean no secret,
mount, or network authority. Public failures contain only runtime-owned safe
classification and may unwrap a matching context cancellation/deadline
sentinel; they never expose transport, credential, backend, host, argv, or
output causes. A backend SPI is intentionally absent from the public package:
real adapters must receive only normalized internal dispatch data and cannot
replace ledger, grant, lifecycle, redaction, or error semantics.

## Operator process

`cmd/sandbox-control` consumes one strict JSON document, mounted TLS identity,
and explicitly named secret environment values for PostgreSQL, public
development authentication, bind assertions, and optional host-envelope
signing. The public listener is server-authenticated TLS; the distinct private
listener is TLS 1.3 with required client certificates from its declared CA.
The role never creates or migrates infrastructure and exposes `/healthz` and
`/readyz`. The declaration rejects unknown fields, relative TLS paths,
implicit secret names, unbounded lifetimes, overlapping listeners, and invalid
addresses. See
[`deploy/sandboxcontrol/control.example.json`](../../deploy/sandboxcontrol/control.example.json).

The static authenticator is for an isolated development or single-service
identity and requires a high-entropy credential. Multi-principal issuer
integration remains later work.

## Contract status

The in-memory fixture and PostgreSQL control role cover principal scoping,
operation identity, freeze and canonicalization, finite defaults/admission,
strict HTTPS acceptance/read/watch, durable restart reconnect, and bounded
outbox observation. Exact input identity is stored separately from resolved
policy digests, so a retry reconnects to the previously accepted Effective
Spec after operator defaults change. Private host dispatch now includes
durable mTLS enrollment, control-signed assignment envelopes, lease/fence
renewal, host-signed result and output-sequence metadata, quarantine, explicit
cleanup, and reassignment. See
[`sandbox.host-control/v1`](sandbox-host-control-v1.md). Output/artifact content
stores, production execution, and Linux/KVM enforcement remain separate work
and require their own evidence lanes.
