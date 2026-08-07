# Issue #13 evidence — Temporal payload/blob pipeline (M2)

Status: implementation evidence only. The retained MinIO artifact records one
bounded S3 integration run; it must not be reused as proof for unrelated
handler, worker, GC, or two-consumer requirements. Ledger promotion requires
the exact checked revision and the acceptance proof for each row.

## Implemented evidence

| Requirement | Evidence |
| --- | --- |
| PAY-001/PAY-002 | `temporalpayload.Codec` compares complete deterministic protobuf wires and selects normal, zstd, then remote only on strict size improvement. |
| PAY-003 | The public bounded `BlobStore`, content-addressed key format, local converter, authenticated UI handler, bounded metrics observer, and MinIO/S3 adapter have focused conformance tests. |
| PAY-004 | `NewUIHandler` requires a trusted-identity authorizer plus namespace/origin allowlists and reuses the exact local codec; the runtime-owned factory configures clients locally without an HTTP dependency. |
| PAY-005 | Missing, corrupt, oversized, incompatible, and malformed content fail visibly; `GarbageCollector` requires conditional retention storage, finite UTC age, and current `DeleteEligibility`. |
| PAY-006 | The architecture guard rejects raw Temporal client/worker construction and caller-owned payload-size branching outside the one runtime factory and codec package. |
| PAY-007 | Source and documentation guards reject encryption configuration or claims; the codec promises compression, integrity, and indirection only. |
| PAY-008 | Frozen inline/zstd/remote vectors, an independent in-repo consumer, and authenticated UI inspection prove representation exchange through the public codec seam. |
| TMP-005/TMP-006 | The one runtime factory gates client creation on retained compatibility vectors and creates workers only from that checked client. |

## Compatibility sources checked

- Temporal's official Go SDK documents `PayloadCodec`,
  `NewCodecDataConverter`, and `NewPayloadCodecHTTPHandler`:
  <https://pkg.go.dev/go.temporal.io/sdk/converter>.
- The current declared Go SDK version is `v1.47.0`. Its source confirms that a
  worker inherits its data converter from the Temporal client, rather than
  `worker.Options`.
- MinIO's official Go client documentation describes its S3-compatible API:
  <https://minio-go.min.io/>.

## Commands and expected proof

```text
go test -race ./temporalpayload/... ./internal/temporalpayloadruntime
go test -tags=integration ./temporalpayload/... ./internal/temporalpayloadruntime
go test ./tests/architecture
deploy/temporalpayload/minio/run-integration.sh
go vet ./temporalpayload/... ./internal/temporalpayloadruntime
git diff --check
```

The MinIO harness uses the pinned disposable service in
`deploy/temporalpayload/minio/compose.yaml`. It verifies actual S3-protocol
round trips, concurrent identical content-addressed writes, and conflicting
same-key writes. It removes its temporary project, credentials, volume, and
network on exit.

## Deliberate boundaries

- No encryption, key management, or confidentiality claim is introduced.
- The M2 handler is reusable UI inspection plumbing, not a deployed codec
  runtime role.
- Bucket provisioning, credentials, lifecycle configuration, retention
  authority, and production object-store deployment remain explicit operator
  responsibilities.
