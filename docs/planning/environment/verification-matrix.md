# Verification matrix

This is the acceptance matrix for the environment design. A check is not
"green" merely because its command exited: every row states the observable
evidence that must be retained by CI or the developer command.

## Delivery gates

| Capability | Environment | Entrypoint | Required evidence | Gate |
| --- | --- | --- | --- | --- |
| Tool bootstrap | Any developer machine | `just dev-preflight` | Tilt, Docker, Kubernetes client, selected context, runtime architecture, cluster architecture, free disk, and actionable install/launch diagnosis. No config mutation and no secret output. | Blocks `just dev` |
| Context refusal | Unit test plus local command test | `go test ./tools/dev/...`; `just dev-preflight` | `admin@prod`, `home-server`, empty context, and an arbitrary context all fail before manifest rendering or Kubernetes writes. `orbstack` is the sole first-release allow-list member. | Required on every PR |
| Namespace derivation | Unit test | `go test ./tools/dev/...` | Distinct canonical worktree paths produce distinct valid namespaces; overrides validate; values longer than 63 characters, bad DNS labels, and state mismatches fail. | Required on every PR |
| Manifest scope | Static render test | `just verify-manifests` | Render has exactly one instance Namespace; every workload is namespaced; no cluster-scoped resource, hard-coded `default`, or foreign namespace exists. Required labels and resource requests/limits are present. | Required on every PR |
| Image isolation | Render/unit test and disposable cluster | `just verify-dev-images` | Two instance ids produce different image refs for every built component. The rendered Pod specs retain the matching instance-qualified ref/digest. | Required on every PR |
| Developer stack | Local OrbStack | `just dev` | Tilt dashboard reports all selected resources healthy; API health check succeeds; Temporal starts; a blob round trip and one example turn complete. The printed namespace and dashboard port match state. | Required before local release sign-off; documented manual proof |
| Parallel stack isolation | Local OrbStack and disposable CI cluster | `just verify-parallel-dev` | Two different instance ids run simultaneously. Database rows, Temporal namespaces/task queues, blob prefixes, labels, and image refs do not cross. Dashboard ports differ; an endpoint forward succeeds for each stack. | Required before the multi-worktree feature is accepted |
| Teardown containment | Disposable CI cluster | `just verify-dev-cleanup` | `dev-down` deletes only its recorded `ar-<instance>` namespace. A sibling namespace, `default`, and every cluster-scoped object remain unchanged. A second teardown is safe and reports "already absent". | Required on every PR touching dev tooling or manifests |
| Tilt health gate | Disposable Linux Kubernetes cluster | `tilt ci --context <ephemeral> --namespace ar-ci-<run> --port 0 -- --instance ci-<run> --profile ci` | `tilt ci` finishes before its timeout with all services healthy; snapshot and selected logs are uploaded on failure. Namespace is removed in an `always` cleanup step. | Required on every PR once the stack exists |
| Go SDK/API contracts | Standard CI | `just test` and generated-contract checks | Unit, integration, race, and public SDK compatibility checks; checked-in OpenAPI and Go reference outputs have no diff after regeneration. | Required on every PR |
| Documentation contract | Standard CI | `just docs-check` | Docusaurus production build, internal/external link check, generated-reference check, and executable code snippets/example commands. | Required on every PR |
| Production sandbox policy | Linux test environment | `just sandbox-policy-test` | Default-deny network policy, allow-list handling, resource/time limits, no host-path mounts, no privilege escalation, and policy-to-audit-event mapping. The test uses a fake driver and does not pretend to prove KVM. | Required on every PR touching sandbox code |
| Firecracker microVM boot | Dedicated Linux KVM runner | `just firecracker-smoke` | A real guest boots under Firecracker, emits a unique serial marker, responds over the chosen guest channel, shuts down, and exits within the time limit. Artifact digests, Firecracker version, guest kernel/rootfs identity, and serial log are retained. | Required on protected-branch push and manual dispatch; not an untrusted-fork job |
| Firecracker runtime contract | Dedicated Linux KVM runner | `just firecracker-integration` | The production Firecracker driver performs one real command/turn in a jailed microVM, returns stdout/stderr/exit state through the public sandbox interface, enforces timeout and filesystem boundary, and emits lifecycle events. | Required on protected-branch push and release candidate |

## Real Firecracker Linux/KVM proof path

The KVM jobs are intentionally separate from normal GitHub-hosted CI. Firecracker
requires read/write access to Linux `/dev/kvm`; the project machine is macOS and
does not have it. GitHub's own documentation confirms that self-hosted jobs can
be routed by labels, but labels alone do not attest to actual hardware, so the
job runs an in-job capability check. See [GitHub runner
routing](https://docs.github.com/en/actions/reference/runners/self-hosted-runners)
and Firecracker's [KVM requirements](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md).

### Runner contract

Provision one resettable, dedicated Linux x86_64 runner and register it with all
of these labels:

```yaml
runs-on: [self-hosted, linux, x64, kvm]
```

It must meet these requirements before it may accept a job:

1. Linux kernel has KVM loaded; `/dev/kvm` is a character device and the runner
   user has both read and write access.
2. Hardware virtualization is enabled. The setup script runs Firecracker's
   environment check and records only its pass/fail diagnostics.
3. The runner has enough free CPU, memory, and disk for one microVM plus its
   fixtures. The initial smoke VM is deliberately small: one vCPU and 256 MiB;
   final values are measured and committed with the test.
4. The runner is either ephemeral or reset to a known image after the job. It
   is not a shared developer workstation and it holds no production secrets.
5. Guest networking starts **disabled** for the boot proof. A later networked
   test uses an explicit, default-deny host firewall/allow-list. Firecracker
   does not itself filter guest egress, so this is a host responsibility. See
   [Firecracker production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md#filtering-guest-egress-network-traffic).

The job runs only on protected-branch pushes, release-candidate workflows, or
an explicitly approved manual dispatch. It must not run on `pull_request_target`
and must not execute code from untrusted forks on self-hosted hardware. Ordinary
pull requests retain mock-driver and manifest tests so feedback remains fast.

### Pinned fixture and boot protocol

The future `tools/firecracker/fixtures.lock` is the single reviewed manifest
for:

- one verified source bundle plus separately hashed Firecracker and matched
  Jailer members, with a release version that matches the release-download URL,
  Linux/amd64 architecture, source/member SHA-256 and license data;
- an uncompressed x86_64 guest `vmlinux` source/object and SHA-256;
- a project-owned minimal ext4 root filesystem source bundle, SHA-256, SBOM
  digest, reproducible recipe/toolchain/input provenance, and a bounded
  attestation member whose `/sbin/init` digest/size verifies against the static
  guest-agent artifact; and
- a project-owned static guest-agent source/object with the same provenance,
  bound into the rootfs by digest, and its serial/control protocol version.

The lock must use `firecracker.fixtures/v2`; it has no final real entries yet.
The checked-in validator and `tools/firecracker/` recipes are only groundwork.
They do not make a rootfs, artifact download, Linux/KVM runner, guest boot or
guest-control result available.

The fixture fetcher verifies every digest before execution, rejects mutable or
cross-kind source references and non-Linux/amd64 boot artifacts before staging,
parses the rootfs attestation bundle, writes a private copy of the writable
rootfs under the job's temporary directory, and never updates the lock file
automatically. It does not prove the ext4 contents at runtime. Firecracker
documents the kernel/rootfs requirements and recommends its Jailer for
production execution. See
[getting started](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md)
and [Jailer operation](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md).

The `firecracker-smoke` test performs these concrete steps:

1. Assert the runner contract and fail with `KVM_UNAVAILABLE` before downloading
   or launching anything if it cannot be met.
2. Verify the pinned source bundle, extracted binary/Jailer members, kernel,
   rootfs, and guest-agent digests and provenance.
3. Allocate a unique VM id and job-temporary directory; copy the rootfs there.
4. Start the Jailer with a dedicated unprivileged uid/gid and cgroup for that
   VM. Configure Firecracker through its Unix API socket with exactly one vCPU,
   bounded memory, the pinned kernel/rootfs, serial console, no network device,
   and a bounded process timeout.
5. Boot a tiny guest init program. It writes
   `AGENT_RUNTIME_FC_SMOKE <vm-id> <fixture-version>` to the serial console,
   answers one host-initiated request over the configured guest channel, then
   powers off.
6. Fail unless the exact marker and response are observed and the VM exits
   cleanly before the deadline. Upload redacted configuration, version/digests,
   serial log, and Jailer/Firecracker logs as CI artifacts on both success and
   failure.
7. Remove the job directory and verify the Jailer cgroup/chroot for that VM id
   has gone. A cleanup failure is a test failure, not a warning.

This is a real KVM proof: a Firecracker process alone is insufficient; the
guest kernel must boot and execute the marker program. It is also intentionally
not a complete production-security attestation. Firecracker's guidance calls
out host kernel, microcode, side-channel, and egress responsibilities that a
runtime test cannot establish. See [production host
recommendations](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md).

### Runtime integration protocol

`firecracker-integration` builds on the smoke fixture but calls the project's
public sandbox driver API. It must prove the behavior agents actually need:

- create sandbox for a session/turn;
- write an allowed input blob and reject a path outside the allowed workspace;
- execute a command and return exit status, stdout, stderr, duration, and
  resource accounting through the public event/codec path;
- terminate a deliberately non-terminating command at its configured deadline;
- destroy the sandbox and verify that a subsequent read cannot recover its
  ephemeral workspace; and
- emit the expected audit events without including blob contents or secret
  material.

The test uses a distinct VM id for every attempt and does not reuse a warm
microVM across tenant/session identities. Firecracker's production guidance
recommends one Firecracker process per tenant/workload boundary; the runtime
model should preserve that property rather than treating a long-lived VM pool
as a shortcut. [Firecracker production host
setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md).

## Failure triage rules

| Signal | Classification | Required response |
| --- | --- | --- |
| `/dev/kvm` missing or inaccessible | Runner capability failure | Mark KVM job unavailable; do not downgrade it to a mock pass. Repair/replace the runner before accepting a release proof. |
| Fixture digest mismatch | Supply-chain/fixture failure | Stop before launch, retain the expected/actual digest values, and update the lock only through review. |
| Guest marker absent or timeout | Real microVM failure | Upload serial/Jailer/Firecracker logs and fail the job. Do not infer a guest boot from a Firecracker process starting. |
| Jailer or cgroup cleanup remains | Isolation cleanup failure | Fail the job and quarantine/reset the runner. |
| Tilt stack works but KVM gate fails | Split-environment failure | Treat local development as healthy but do not claim production sandbox verification. |

## Evidence retention

CI retains a compact test report for each required row: command, immutable
revision, environment/architecture, start/end time, exit state, and relevant
redacted logs. It never uploads kubeconfig files, cloud credentials, private
container configuration, raw sandbox input/output blobs, or development secret
values.
