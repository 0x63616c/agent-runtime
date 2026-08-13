# Firecracker fixture inputs

This directory contains the project-owned inputs for the protected Firecracker
smoke fixture. They are **not** a real rootfs, a reviewed fixture lock, or
Linux/KVM proof.

`firecracker.fixtures/v2` has five logical artifacts:

1. a Firecracker executable extracted from one verified release tar.gz;
2. the matching Jailer extracted from that same verified tar.gz;
3. an uncompressed x86_64 guest kernel;
4. a minimal ext4 rootfs; and
5. the static guest-agent binary embedded in that rootfs as `/sbin/init`.

The lock must record every source URL and source-kind-specific immutable
reference, source and member/output SHA-256 and size, Linux/amd64 architecture,
SPDX/license data, and the rootfs/agent build recipe, source revision,
toolchain, input-manifest and SBOM member SHA-256/size pairs. Release archives use an exact
`release:vX.Y.Z` URL identity, object sources use the URL's exact
`version-id:...`. Firecracker's public CI bucket is the one documented
assembly exception: it publishes an exact build-scoped kernel object and
returns its version ID in a response header, but rejects an anonymous GET with
that version-ID query. The assembler accepts only that canonical object path
while recording the observed version ID in its input manifests. A reviewer may
then retain those exact verified bytes as the
sole `kernel-vmlinux` asset on this project's `commit:<40-lowercase-hex>`
release. That project-controlled release asset is an immutable mirror, not a
rebuilt kernel, and is accepted only for the kernel. Project build outputs use
the same exact `github.com/0x63616c/agent-runtime` `commit-<revision>`
release-asset trust root. Project outputs are tar.gz bundles: each has an exact artifact
member plus bounded, separately verified input-manifest and SBOM members. A
digest assertion without its corresponding bounded bytes is not accepted.
Project-bundle traversal permits only its lock-declared regular members (at most
eight) and stops before the smaller of the lock-derived uncompressed-member
budget or the independent 4 GiB ceiling can be exceeded.
`latest`, `main`, floating release URLs, and cross-kind identities are refused.
Fixture URLs are also log-safe identities: userinfo, fragments, and all query
parameters are refused, except for exactly one `versionId` matching a
versioned-object reference. Presigned URLs and embedded credentials cannot enter
the lock.

The internal `ParseFixtureLock` boundary accepts only one complete v2 JSON
document up to 256 KiB, disallows unknown fields and trailing documents, and
runs the complete provenance validator before any fetch is possible. Its token
walk rejects duplicate keys at every nested object and refuses case aliases, so
JSON's last-key-wins and case-insensitive decoder behavior cannot change a
reviewed identity. It does not supply a lock file or authorize a fetch by itself.

The rootfs project-build source is a verified tar.gz containing the ext4 member,
bounded input-manifest and SBOM sidecars, and a bounded
`rootfs-attestation.json` sidecar. The guest-agent source is likewise a
verified tar.gz bundle with exact binary, input-manifest, and SBOM members.
Before staging the image, the fixture validator verifies every provenance member
against its exact lock digest/size, then verifies that the rootfs attestation's rootfs digest/size and
`/sbin/init` digest/size equal the separately verified static Linux/amd64
guest-agent artifact. This checks the immutable build bundle, not the contents
of a booted ext4 image. No command in this directory updates a lock
automatically.

## Guest protocol

The static `guest-agent` prints this serial marker first:

```text
AGENT_RUNTIME_FC_SMOKE <vm-id> <fixture-version> agent-runtime-firecracker-guest/v1
```

It then listens only on the private guest AF_VSOCK port `10777` and accepts a
peer only from the host CID. The one accepted connection must send
`CONNECT <vm-id> <fixture-version>` and receives `OK <vm-id> <fixture-version>`
before it may send `PING <nonce>` and receive `PONG <vm-id> <nonce>`. Every
control line is capped at 1024 bytes; the full connection and frame exchange
has a five-second deadline, and malformed, mismatched, and timed-out frames
fail closed without echoing control input. The guest requests controlled
power-off only after that PONG has been written; a bounded guest protocol test
does not prove that the kernel completed a reboot. The kernel must invoke
`/sbin/init` with this closed argument sequence:

```text
console=ttyS0 reboot=k panic=1 init=/sbin/init -- <vm-id> <fixture-version>
```

The guest listener is not a host transport, proxy, or authorization boundary:
the protected M3 host-control bridge must bind this byte protocol to a private
per-VM vsock endpoint and authenticate/fence the request before launch. The
protected smoke command composes the private host-side vsock endpoint only for
its exact boot PING; no enrolled M3 launch or public runtime-command path is
implemented here.
There is no guest NIC, shell, package manager, inherited environment, or secret
fixture.

`build-guest-agent.sh` builds the binary with Linux/amd64, CGO disabled and
deterministic Go flags. `build-rootfs.sh` accepts only that explicit binary,
an exact ext4 byte size, UUID, and new attestation output path. It requires a
fixed `SOURCE_DATE_EPOCH`, rejects a
non-ELF64/non-x86_64 or dynamically linked init, creates `/sbin/init`, then
emits the attestation for lock-bundle assembly. It does not download a distro
or install packages. The output still requires a reviewed final SHA-256, SBOM,
reproducible build evidence and a real Linux/KVM/Jailer boot before it can enter
a lock or count as evidence.

## Reviewed fixture assembly

`assemble-fixtures.sh` is the only supported assembly path for a candidate
lock. It accepts already-downloaded bytes for an immutable upstream Firecracker
release archive, a kernel object whose URL has one exact `versionId`, and a
rootfs built with the two project recipes. It builds the static guest agent,
records measured input manifests/SBOMs, creates deterministic project bundles,
and derives every candidate lock digest/size from those bytes. It never fetches
a floating artifact, uploads an asset, changes `fixtures.lock`, or starts a
guest.

Run it on Linux with GNU tar and e2fsprogs, using an empty output directory.
For a normal versioned object, use its exact query URL. For the Firecracker CI
bucket exception, use the canonical query-free object URL and the exact
`x-amz-version-id` observed from its HTTPS response:

```text
SOURCE_DATE_EPOCH=1704067200 ./tools/firecracker/build-rootfs.sh ...
./tools/firecracker/assemble-fixtures.sh OUT REVISION vX.Y.Z FIRECRACKER.tgz \
  'https://object.example/vmlinux?versionId=EXACT' EXACT KERNEL ROOTFS ATTESTATION 1704067200
```

Assembly refuses a dirty worktree or a revision other than `HEAD`; run it from
a clean detached checkout so the recorded source-tree digest and source
revision describe the bytes that built the guest agent.

Review the emitted `fixtures.lock.candidate.json`, the input manifests and
SBOMs, the original versioned-kernel identity, and the exact archive/member
identities. Then publish the byte-identical `kernel-vmlinux` mirror and two
project bundles to the exact `commit-<revision>` GitHub release URLs named in
the candidate. A separate review must verify those uploaded bytes before the
candidate is copied to `tools/firecracker/fixtures.lock`; without that review
and publication the smoke command remains correctly blocked.

Before printing the candidate path, the assembler runs a local
`firecracker-fixture-preflight`: it parses the candidate with the strict lock
parser and provisions solely the just-assembled local files through the same
digest, tar-member, provenance, and rootfs-to-agent binding checks used by the
protected smoke runner. It is a reproducibility check, not publication or
Linux/KVM boot evidence.
