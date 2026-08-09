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

The lock must record every source URL and immutable reference, source and
member/output SHA-256 and size, architecture, SPDX/license data, and the
rootfs/agent build recipe, source revision, toolchain, input-lock and SBOM
digests. It must bind the rootfs provenance to the exact guest-agent digest.
No command in this directory updates a lock automatically.

## Guest protocol

The static `guest-agent` prints this serial marker first:

```text
AGENT_RUNTIME_FC_SMOKE <vm-id> <fixture-version> agent-runtime-firecracker-guest/v1
```

It then accepts exactly one line, `PING <nonce>`, and returns
`PONG <vm-id> <nonce>`. The real host transport is intentionally not implemented
here: the protected M3 host-control bridge must bind this byte protocol to a
private per-VM vsock endpoint and authenticate/fence the request before launch.
There is no guest NIC, shell, package manager, inherited environment, or secret
fixture.

`build-guest-agent.sh` builds the binary with Linux/amd64, CGO disabled and
deterministic Go flags. `build-rootfs.sh` accepts only that explicit binary,
an exact ext4 byte size and UUID; it does not download a distro or install
packages. The output still requires a reviewed final SHA-256, SBOM, reproducible
build evidence and a real Linux/KVM/Jailer boot before it can enter a lock or
count as evidence.
