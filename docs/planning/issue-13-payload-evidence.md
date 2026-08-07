# Issue #13 evidence — Temporal payload/blob pipeline (M2)

Status: M2 acceptance complete for reviewed implementation revision
`676f69ecc8fd02260e247cb08e2cae3fa7814753`. The bounded machine-readable
artifact records a clean repository check, real Temporal all-representation
exchange, disposable MinIO/S3 integration and cleanup, and documentation check.
Independent review revision `d834cc3105347a9cc5a62ff7567fb2d2b7a030b3`
records PASS with no P0/P1/P2 findings. Corrective hosted main CI revision
`d18f0a1d9263cd0c40b2fae5d8f99b8df318e1e2` passed both repository and
documentation checks in GitHub Actions run `31155032954`. Together these
complementary proofs complete `PAY-001` through `PAY-008` and `TMP-005` through
`TMP-006`. Issue #13 remains open and no completion notification is authorized
until this ledger-promotion revision has immutable main-CI evidence.

## Implemented evidence

| Requirement | Evidence |
| --- | --- |
| PAY-001/PAY-002 | `temporalpayload.Codec` compares complete deterministic protobuf wires and selects normal, zstd, then remote only on strict size improvement. |
| PAY-003 | The public bounded `BlobStore`, content-addressed key format, local converter, authenticated UI handler, bounded metrics observer, and MinIO/S3 adapter have focused conformance tests. |
| PAY-004 | `NewUIHandler` requires a trusted-identity authorizer plus namespace/origin allowlists and reuses the exact local codec; the runtime-owned factory configures clients locally without an HTTP dependency. The architecture guard rejects Temporal remote-codec constructor symbol references through normal, aliased, dot-imported, and function-value forms outside the factory. |
| PAY-005 | Missing, corrupt, oversized, incompatible, and malformed content fail visibly; `GarbageCollector` delegates deletion to one durable `RetentionCoordinator` operation that fences authoritative reference creation and conditions object identity. A reference-created-after-listing race returns not-deleted, and a deterministic concurrent-delete harness proves one successful deletion without unbounded waits. This is not a cross-store atomicity claim: an incomplete external delete remains a durable tombstone/reconciliation outcome. |
| PAY-006 | The architecture guard rejects raw Temporal client/worker construction and caller-owned payload-size branching outside the one runtime factory and codec package. |
| PAY-007 | Source and documentation guards reject encryption configuration or claims; the codec promises compression, integrity, and indirection only. |
| PAY-008 | A startup-gated runtime Factory client and actual Temporal worker exchange inline, zstd, and remote representations through server history. An independent public-package consumer decodes each stored result, and the authorized UI handler returns the corresponding plain payload. |
| TMP-005/TMP-006 | The one runtime factory gates client creation on retained compatibility vectors and creates workers only from that checked client; no raw converter accessor bypass exists. An AST guard rejects all current raw Temporal client constructors, including `NewNamespaceClient`, import aliases, dot imports, and constructor symbols assigned as function values, outside the factory. |

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
just check
go test -tags=integration ./internal/temporalpayloadruntime -run '^TestFactoryWorkerExchangesEveryPayloadRepresentationAgainstTemporal$' -count=1
deploy/temporalpayload/minio/run-integration.sh
docker container/network/volume label inspection for the disposable Compose project
just docs-check
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
