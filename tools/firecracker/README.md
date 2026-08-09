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
toolchain, input-lock and SBOM digests. Release archives use an exact
`release:vX.Y.Z` URL identity, object sources use the URL's exact
`version-id:...`, and project outputs use `commit:<40-lowercase-hex>`.
`latest`, `main`, floating release URLs, and cross-kind identities are refused.
Fixture URLs are also log-safe identities: userinfo, fragments, and all query
parameters are refused, except for exactly one `versionId` matching a
versioned-object reference. Presigned URLs and embedded credentials cannot enter
the lock.

The rootfs project-build source is a verified tar.gz containing the ext4 member
and a bounded `rootfs-attestation.json` sidecar. Before staging the image, the
fixture validator verifies that the sidecar's rootfs digest/size and
`/sbin/init` digest/size equal the separately verified static Linux/amd64
guest-agent artifact. This checks the immutable build bundle, not the contents
of a booted ext4 image. No command in this directory updates a lock
automatically.

## Guest protocol

The static `guest-agent` prints this serial marker first:

```text
AGENT_RUNTIME_FC_SMOKE <vm-id> <fixture-version> agent-runtime-firecracker-guest/v1
```

It then accepts exactly one line, `PING <nonce>`, and returns
`PONG <vm-id> <nonce>`. Its bounded lifecycle contract attempts controlled
power-off within five seconds only after that PONG has been written. The kernel
must invoke `/sbin/init` with this closed argument sequence:

```text
console=ttyS0 reboot=k panic=1 init=/sbin/init -- <vm-id> <fixture-version>
```

The real host transport is intentionally not implemented here: the protected M3
host-control bridge must bind this byte protocol to a private per-VM vsock
endpoint and authenticate/fence the request before launch.
There is no guest NIC, shell, package manager, inherited environment, or secret
fixture.

`build-guest-agent.sh` builds the binary with Linux/amd64, CGO disabled and
deterministic Go flags. `build-rootfs.sh` accepts only that explicit binary,
an exact ext4 byte size, UUID, and new attestation output path. It rejects a
non-ELF64/non-x86_64 or dynamically linked init, creates `/sbin/init`, then
emits the attestation for lock-bundle assembly. It does not download a distro
or install packages. The output still requires a reviewed final SHA-256, SBOM,
reproducible build evidence and a real Linux/KVM/Jailer boot before it can enter
a lock or count as evidence.
