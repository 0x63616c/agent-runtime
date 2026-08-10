# Firecracker foundation status

The internal `firecracker.host/v1` compiler is a declarative, fail-closed
launch-plan boundary. It requires immutable paths and SHA-256 identities for
the Firecracker binary, Jailer, kernel, root filesystem, and project-owned
guest agent; requires the Jailer to use an unprivileged identity and cgroups
v2; requires finite CPU, memory, disk, process and output limits; and permits
no guest NIC, egress allow-list, or host mount.

The fixture boundary refuses the prior four-artifact `firecracker.fixtures/v1`
shape rather than guessing a migration. A reviewed v2 lock is required before
any source can be staged.

It is not Firecracker evidence. Every capability in its returned profile is
`unavailable` until the protected Linux/KVM lane verifies the exact plan,
fixtures, Jailer cleanup, a booted guest marker, and the durable public
sandbox-control path. `cmd/firecracker-e2e` presently records an explicit
Linux/KVM environmental refusal report. It records Linux, usable KVM, Jailer,
cgroups v2, and pinned-artifact checks separately; `available` is their
fail-closed composite. Opening `/dev/kvm` alone is not usable-KVM proof.
`-require-kvm` fails unless that composite is available, and the command does
not launch a VMM on a developer machine.

## M3 integration gap

The current `origin/main` baseline does not contain the unpushed M3 enrolled,
fenced host-control protocol. This compiler deliberately imports no M3 work
tree package and cannot dispatch a launch plan until that protocol is present
on the integration base. The eventual bridge must submit an authenticated,
lease-fenced M3 envelope and retain receipt, serial, Jailer, cgroup, and
cleanup evidence. It must not route through a local fake host or convert a
macOS check into an isolation claim.

## Remaining M4 evidence

The following are still required before any Firecracker foundation claim:

- a reviewed `firecracker.fixtures/v2` lock with source-bundle/member and
  project-build provenance, final release URLs and SHA-256 values, then
  host-side digest verification before launch;
- a dedicated Linux x86_64 `/dev/kvm` runner with a real Jailer/guest-marker
  smoke run and cleanup proof;
- a public-control E2E for create, exec, output, cancellation, timeout,
  restart/reconcile, file transfer, and destruction; and
- separate certified profiles for mounts, volumes/snapshots, command-scoped
  secrets, and mediated egress. Unsupported requests must continue to fail
  closed.

## Protected-runner commands

`just firecracker-smoke` and `just firecracker-integration` deliberately fail
closed on an ordinary developer host. Both retain a redacted `blocked` report
instead of emitting simulated success. The dispatch-only `firecracker-kvm`
workflow is restricted to the protected self-hosted `linux`, `x64`, `kvm`, and
`firecracker-protected` runner contract and uploads that report even on failure.
It cannot become `linux_kvm_e2e` evidence until a reviewed fixture lock and the
enrolled M3 host-control bridge drive `SmokeHarness` through a real Jailer,
guest serial marker, control request, and cleanup proof.

## Fixture-lock v2 groundwork

The internal fixture validator now understands five logical identities and can
verify a downloaded tar.gz source bundle before extracting separately hashed
Firecracker and Jailer members. It requires a source-kind-specific immutable
identity: a release version that matches the release-download URL, an
object-store version ID that matches the URL, or a project commit matching the
build provenance. Floating `latest`, `main`, and cross-kind references are
refused. Fixture URLs reject userinfo, fragments, presigned parameters and every
query other than one matching `versionId` on an object-store source. Every
bootable artifact must declare Linux/amd64 before staging.

The project-built rootfs and guest-agent sources are tar.gz bundles from the
exact `github.com/0x63616c/agent-runtime` `commit-<revision>` release-asset
trust root. Each carries a separately verified artifact member plus bounded
input-manifest and SBOM members with exact lock digest/size identities.
Provisioning rejects an arbitrary project HTTPS origin, missing/duplicate/
oversized provenance member, or a source-verified bundle whose provenance bytes
do not match the lock. It also rejects every project tar.gz header outside the
lock-declared member set, caps traversal at eight regular members, and applies
the smaller of its lock-derived total uncompressed-member budget or the
independent 4 GiB ceiling. It then
parses the rootfs attestation and checks its
rootfs digest/size and `/sbin/init` digest/size against the verified static
guest-agent artifact. This is stronger than a lock assertion, but is still not
an ext4 filesystem inspection or proof that a guest has booted.

The v2 lock parser accepts a single bounded 256 KiB JSON document only. It
rejects unknown fields, duplicate keys at every nesting level, case aliases, and
trailing data before applying the same fixture validator. The parser is a
fail-closed intake boundary; no real lock is checked in and parsing alone cannot
authorize a fixture fetch or launch.

`LinuxJailerHost` now provides the internal real-backend seam for the protected
runner. It accepts injected Jailer-process, private Firecracker REST, and guest
serial/vsock ports only after a Linux/amd64 KVM preflight and verified fixtures.
Its prepared request is deep-copied and must retain the exact plan Jailer argv.
A required resource stage carries a SHA-256 binding over the VM, fixture
version, Jailer/Firecracker/kernel/guest-agent identities, the digest-bound
private rootfs copy, and every jailed destination. The host refuses a
substituted source, stale binding, duplicate destination, or any root that is
not the exact per-VM Jailer namespace before it starts a port. Jailer start
receives that complete stage record and the REST boot/root-drive/vsock requests
and guest bind use its mapped paths. This validates the record contract; it does
not itself establish a real Jailer mapping.

`LinuxJailerResourceStager` is the corresponding internal on-disk staging
adapter. It accepts only a complete verified fixture set and a distinct private
rootfs copy, rechecks every pinned artifact through a no-symlink regular-file
descriptor, and rejects a reused, changed, or symlinked input before creating a
Jailer namespace. The private rootfs must fit the plan's finite root-disk limit.
The compiler permits only the declared `/srv/agent-runtime/jailer` Jailer base.
The production stager checks that this base, every ancestor to `/`, and an
existing executable directory are root-owned, non-symlinked, and not group- or
world-writable; those operator-owned paths are its trusted filesystem root, so
an unprivileged actor cannot race path checks or cleanup. It creates only the fresh Jailer layout
`<chroot-base>/<firecracker-executable-name>/<vm-id>/root`, then copies the
verified kernel and private rootfs to their fixed jailed destinations and binds
that result, including the plan's exact unprivileged UID/GID, into the stage
digest. Guest-visible child directories and files are owned by that identity
with no group or world access. The stager keeps those directories root-owned
while it creates, verifies, and finalizes the kernel and rootfs, transferring
their ownership only as its last successful staging step. The Jailer retains
ownership of copying its own Firecracker executable into the chroot. The stager does not start a Jailer,
infer a fixture lock, or certify KVM isolation.
Its fixed REST order configures machine limits, the closed boot source, writable
root drive, vsock, then `InstanceStart`; it declares no guest NIC. Every process,
REST, and guest-port call is context-fenced before and after I/O. A cancellation
after start aborts and performs bounded cleanup without reporting launch.
Cleanup is single-flight/idempotent, clears its process reference before blocking
I/O, and requires guest close, process termination, wait, and Jailer resource
proof, including when a starter returns both a process and an error. The
private REST adapter is constrained to one configured Unix socket and the five
fixed JSON requests above; it rejects proxy, TCP, redirect, arbitrary-route,
and arbitrary-body use. It is not yet composed with a Jailer starter or guest
transport. The host-contract tests still use recording ports, and the Unix
adapter tests use a temporary local socket only. Neither starts a Jailer, opens
`/dev/kvm`, nor counts as Linux/KVM evidence.

`tools/firecracker/` contains a static Linux/amd64 guest-agent source and a
minimal no-download ext4 recipe. The recipe rejects dynamically linked or
non-x86_64 ELF init input and emits a rootfs-attestation sidecar for lock-bundle
assembly. The guest's closed boot-input contract is
`init=/sbin/init -- <vm-id> <fixture-version>`; it writes the marker, answers
one bounded PING/PONG, then attempts controlled power-off using a five-second
deadline. These are deliberately only build and lifecycle inputs: there is no
checked-in final lock, rootfs image, SBOM, fixture digest, guest transport
implementation, or boot evidence yet. The lease-fenced authenticated M3-to-vsock
transport remains a required bridge. Neither unit tests nor attestation checks
establish a guest boot, actual controlled shutdown, or hardware-isolation claim.
