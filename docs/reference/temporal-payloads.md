# Temporal payload and blob codec

Status: M2 complete. The local codec, S3-compatible adapter, UI handler,
focused conformance suite, and disposable MinIO integration harness exist.
Runtime role composition and declarative production deployment remain separate
work.

`temporalpayload` is a root-module public package. A runtime Temporal client
and every worker created from it use the same local DataConverter; workers do
not make HTTP calls to the codec service.

## Selection contract

For each normal Temporal payload, version 1 deterministically compares the
actual serialized byte count of three complete representations:

1. the normal Temporal payload, unchanged;
2. a `binary/zstd` wrapper containing a zstd-compressed deterministic protobuf
   encoding of that normal payload; and
3. a `binary/remote-payload` wrapper containing a 41-byte version/digest/size
   reference to the currently smallest inner representation.

Compression is selected only when its complete wrapper is strictly smaller.
Remote storage is used only when its complete reference wrapper is strictly
smaller than that winner. The remote object therefore contains either the
normal or zstd inner payload. Application and workflow code never makes a size
branch.

Remote keys are content-addressed:

```text
<declared-prefix>/temporal-payload/v1/sha256/<hex-digest>
```

The reference is storage-neutral: it contains no endpoint, bucket, credential,
workflow ID, or user content. Decode verifies both byte count and SHA-256
before unmarshalling. Missing, oversized, corrupt, unsupported-version, and
malformed payloads fail visibly.

## Compatibility and encryption

The emitted format is `agent-runtime-payload-v=1`. Version 1 accepts ordinary
pre-codec Temporal payloads unchanged and decodes v1 zstd and remote forms.
Frozen inline, zstd, and remote complete-wire vectors are part of the test
suite; the remote vector includes its frozen stored-inner payload. Before a
runtime-owned Temporal client is created, the factory decodes those retained
vectors and separately verifies current emission against them. The factory
does not expose its converter as a startup-gate bypass. A version outside this
window is rejected; changing the format needs retained-history, golden, UI,
and two-consumer compatibility evidence.
Seeding the frozen remote vector uses the codec's configured finite I/O timeout,
the same bound used by ordinary remote encode/decode I/O.

The codec does **not** encrypt payloads. It offers compression, integrity, and
storage indirection only. No encryption configuration, key reference, or
confidentiality claim exists until a separately designed cryptographic layer
has lifecycle, rotation, and UI compatibility proof.

## Blob storage and retention

Pass any implementation of `temporalpayload.BlobStore` to `NewCodec`. The
package provides a concurrent in-memory test store and the
`temporalpayload/s3` adapter for a configured MinIO/S3-compatible client and
one explicit bucket. The adapter requires conditional create (`If-None-Match:
*` through MinIO's optimistic-locking API); a conflicting existing object is
read within the requested bound and rejected unless bytes match exactly.

The runtime and codec do not create buckets, prefixes, credentials, lifecycle
rules, or retention policies. Those are declarative operator-owned
infrastructure. The development integration harness uses the pinned MinIO
image in `deploy/temporalpayload/minio/compose.yaml` and is deliberately
disposable.

Normal `Codec` encode/decode has no delete capability. Deletion is a separate
`GarbageCollector` seam requiring one durable `RetentionCoordinator` operation.
That operation fences authoritative reference creation, proves the object has
no authoritative reference, and conditions deletion on the listed object
creation identity. It only deletes an object after its explicit UTC minimum
age; referenced and young content are retained. A cache, an eventually
consistent listing, or scanning Temporal history is not safe deletion
authority.

The reference ledger and object store are distinct systems, so this is not a
claim of cross-store atomicity. If a coordinator cannot safely complete the
external conditional delete while its durable fence/tombstone is current, it
returns not-deleted and retains a durable reconciliation record rather than
guessing. Reference creation and reaping must use that same durable protocol.

## Temporal UI handler

`NewUIHandler` wraps Temporal's `/encode` and `/decode` handler with sealed
`WithTemporalUINamespaces`, `WithTemporalUIRequestAuthorizer`, and optional
`WithTemporalUIOrigins` options. The authorizer must establish a trusted identity
(for example through verified OIDC middleware or mTLS) and authorize that
identity for the requested namespace. `X-Namespace`, `Origin`, a
NetworkPolicy, and source address are routing or perimeter inputs—not
authentication—and must never be trusted as identity. The handler does not log
or retain credentials. Browser preflight permits Temporal UI's `Authorization`
and `authorization-extras` headers without enabling ambient browser credentials.
It reuses the exact local Codec, making it an inspection
adapter for Temporal UI only. Runtime workers use `Codec.DataConverter()`
directly and never instantiate Temporal's remote codec client.

The integration follows Temporal's documented
[PayloadCodec HTTP handler](https://pkg.go.dev/go.temporal.io/sdk/converter#NewPayloadCodecHTTPHandler)
and the S3 adapter uses MinIO's documented
[S3-compatible Go client](https://minio-go.min.io/).

## Verification

Focused deterministic proof:

```text
go test -race ./temporalpayload/... ./internal/temporalpayloadruntime
go test -tags=integration ./temporalpayload/... ./internal/temporalpayloadruntime
```

The integration suite starts a real Temporal development server and proves
that a startup-gated Factory client and worker write inline, zstd, and remote
results which a separately constructed public codec consumer and the
authorized UI handler can inspect.

The real disposable MinIO proof requires Docker and runs the S3-compatible
adapter against the declared pinned container:

```text
deploy/temporalpayload/minio/run-integration.sh
```

The harness creates only its test bucket under a throwaway Docker project and
removes the project, network, temporary credentials, and volume on exit.
