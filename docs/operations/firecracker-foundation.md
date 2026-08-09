# Firecracker foundation status

The internal `firecracker.host/v1` compiler is a declarative, fail-closed
launch-plan boundary. It requires immutable paths and SHA-256 identities for
the Firecracker binary, Jailer, kernel, and root filesystem; requires the
Jailer to use an unprivileged identity and cgroups v2; requires finite CPU,
memory, disk, process and output limits; and permits no guest NIC, egress
allow-list, or host mount.

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

- a reviewed fixture lock with release URLs and SHA-256 values, then host-side
  digest verification before launch;
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
