# Environment audit

**Audit date:** 2026-08-06
**Scope:** read-only inspection of the workstation and public repository. No
machine configuration, Kubernetes object, GitHub object, credential, or cluster
context was changed.

This document separates observations made on this workstation from vendor facts
and the decisions proposed for `agent-runtime`. It is not a portability claim for
other developer machines.

## Confirmed local facts

| Area | Observation | Consequence |
| --- | --- | --- |
| Host | macOS (Darwin 25.3.0), ARM64, 12 logical CPUs, 32 GiB RAM | Local images and the development cluster are ARM64. The dev image build must not force `linux/amd64`. |
| Disk | 43 GiB free on the workspace volume at audit time | Enough headroom for a modest first stack, but the preflight should require a minimum free-space threshold and report actual usage. |
| Repo toolchain | Git v2.55.0, `just` v1.58.0, and Go v1.26.5 are installed | The proposed command surface and Go-first implementation have their baseline local tools. Project-specific version pins still belong in the repository. |
| Tilt | `tilt` v0.37.6 is installed | The local quick start can use Tilt immediately. |
| Kubernetes client | `kubectl` v1.33.9 is installed | The launcher can make scoped readiness and cleanup calls. |
| Local runtime | Docker client/server v29.4.0 are running through OrbStack; the server is Linux/aarch64, has 12 CPUs, about 15.7 GiB available to Docker, overlayfs, and cgroup v2 | Container builds and a local Kubernetes stack have a usable runtime. Capacity needs a stack-specific resource budget before calling it sufficient. |
| Local cluster | OrbStack v2.1.3 is running. Context `orbstack` is current. The cluster has one Linux/ARM64 node and reports Kubernetes v1.33.9+orb1. | `orbstack` is the only supported local development target in the first implementation. |
| Other cluster tools | `kind`, `k3d`, `minikube`, `skaffold`, `nerdctl`, `lima`, and `colima` were not found on the command path. Helm v4.2.3 is installed. | Do not make the local quick start depend on another cluster manager. CI can provision its own disposable Linux cluster. |
| Kubeconfig shape | The active context is `orbstack`. Other configured contexts include `admin@prod` and `home-server`; additional cluster and user entries exist but were not dereferenced. Endpoints, certificates, and credentials were intentionally not read or recorded. | The Tiltfile and launcher must hard-reject every context except the explicit local development context. A default-context launch is unsafe. |
| KVM | This is a Darwin host and `/dev/kvm` is absent. | A real Firecracker microVM cannot run on this Mac. Local development must use a non-Firecracker implementation of the sandbox contract; the real proof belongs on Linux with KVM. |
| GitHub | GitHub CLI authentication for account `0x63616c` is available. `0x63616c/agent-runtime` exists, is public, and has default branch `main`. | The requested single public monorepo already has an available, confirmed name. Authentication material was not inspected or recorded. |

The `orbstack` context is a fact at the audit time only. It is not a permission
grant: each development command must select and validate it again.

## Confirmed external facts

- Tilt accepts an explicit Kubernetes context and an explicit default namespace
  on `tilt up`; it also supports `--port 0` to disable its dashboard. Tiltfile
  arguments after `--` are available through `config.parse()`. See the [Tilt
  `up` reference](https://docs.tilt.dev/cli/tilt_up.html) and [Tiltfile
  configuration API](https://docs.tilt.dev/api.html#config-parse).
- Tilt's `allow_k8s_contexts` exists specifically to prevent accidental
  deployment to a non-development cluster. See the [Tiltfile
  API](https://docs.tilt.dev/api.html#allow-k8s-contexts).
- Tilt builds images with `docker_build` and selects a runtime-accessible image
  handoff strategy when it can identify the target runtime. See the
  [`docker_build` reference](https://docs.tilt.dev/api.html#docker-build).
- Firecracker requires Linux KVM and read/write access to `/dev/kvm`; a bootable
  guest also needs an uncompressed kernel image and an ext4 root filesystem.
  Firecracker supports Linux x86_64 and aarch64 hosts. See Firecracker's
  [getting-started guide](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md).
- Firecracker describes the Jailer as its production execution jail and notes
  that its integration tests use it. See the [same getting-started
  guide](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md#running-firecracker)
  and [Jailer operation](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md).
- GitHub routes a self-hosted job only to an online, idle runner matching all
  requested labels. A self-hosted runner is therefore a valid way to reserve a
  KVM-capable Linux host for one job class, but a label is not proof of hardware
  capability. See [GitHub's self-hosted runner
  reference](https://docs.github.com/en/actions/reference/runners/self-hosted-runners).

## Proposed decisions

1. The first local quick start targets **OrbStack Kubernetes only**. It has one
   intentionally small host boundary: source control, `just`, Tilt, Docker, and
   the existing OrbStack Kubernetes cluster. Databases, Temporal, blob storage,
   and observability dependencies run inside the selected namespace, not as
   background host services.
2. Every development instance gets an explicit, unique Kubernetes namespace and
   unique image references. It never targets `default`, a shared development
   namespace, `admin@prod`, or `home-server`.
3. The launcher chooses a free dashboard port for each Tilt process. Service
   access uses a per-instance, OS-selected `kubectl port-forward`, rather than
   fixed host ports that collide between worktrees.
4. The supported local sandbox driver is a clearly labelled development/test
   driver that implements the sandbox interface but does **not** claim
   Firecracker isolation. The product's production driver and its proof live on
   Linux/KVM.
5. Firecracker verification runs on a dedicated, ephemeral or resettable Linux
   x86_64 self-hosted runner labelled `kvm`, never on GitHub-hosted runners and
   never on untrusted fork pull-request code.

The full implementation design is in [Tilt isolation design](tilt-design.md);
the required proof is in [Verification matrix](verification-matrix.md).

## Deliberately unverified

- Whether OrbStack's current Kubernetes image handoff accepts every proposed
  image reference. This becomes an implementation acceptance test, not an
  assumption.
- The CPU/memory/disk budget required by Temporal, PostgreSQL, blob storage,
  observability, and all example applications together. The first working stack
  must publish requests/limits and measure a cold start.
- Availability and operating-system hardening of a Linux KVM runner. No runner
  was provisioned or changed during this audit.

## Safe repeat audit

The eventual `just dev-preflight` should repeat only the necessary checks:

```text
tilt version
kubectl --context orbstack version
kubectl --context orbstack get nodes
docker info
test -r /dev/kvm && test -w /dev/kvm     # Linux KVM job only
```

It must print versions, architecture, selected context, namespace, and resource
headroom. It must not print kubeconfig contents, registry credentials, GitHub
tokens, or secret values.
