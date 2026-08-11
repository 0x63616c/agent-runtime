# M4 Firecracker readiness map

Status date: 2026-08-10. This map records implementation and evidence status;
it is not a Firecracker isolation or release claim.

| Requirement | Locally proved control/refusal | Remaining code gap | External evidence blocker |
| --- | --- | --- | --- |
| SBX-021 / DEP-007 / TST-005 | Fail-closed Linux/amd64/KVM preflight, deny-all plan compiler, pinned-artifact validator, Jailer resource/cleanup contract, signed M3/M4 preparation handoff. | Real staged-host implementation, launch-started/terminal-observation/recovery chain, final fixture lock. | Protected Linux/amd64 runner with usable `/dev/kvm`, Jailer, cgroups v2, reviewed fixtures, retained guest boot and cleanup evidence. |
| SBX-022 | No local adapter is allowed to claim isolation; unsupported profiles are refused. | Explicit acknowledgement-gated, sanitized `local-unsafe` adapter. | None for the acknowledgement/refusal contract; it must never satisfy security evidence. |
| SBX-023 | In-memory deterministic control tests use injected time and do not execute a command. | Scriptable fake backend states/results/gaps with a published test-adapter contract. | None. |
| SBX-024 | Create requests now negotiate minimum capability requirements and reject unavailable secret, mount and volume authority. Firecracker foundation advertises every profile unavailable. | Restore binding and persisted capability-regression path; capability precision/architecture contract. | Firecracker states remain unavailable until their own suites run. |
| SBX-025 / TST-003 | Per-package refusal tests exist. | Shared black-box adapter conformance runner and CI activation report. | Linux/KVM adapter run once it advertises a capability. |
| SBX-026--027 | Request shapes are bounded; no transfer is advertised. | Descriptor-relative transfer implementation, checksum/archive/cancel/partial cleanup and adversarial path tests. | None for portable transfer; Firecracker transfer needs its data-plane proof. |
| SBX-028 | Firecracker compiler rejects host mounts and reports mount capability unavailable. | Jailed sharing daemon and complete traversal/TOCTOU/special-file conformance suite. | Linux/KVM daemon-boundary tests. |
| SBX-029--032 | Volume/snapshot authority profiles are unavailable; no attachment or snapshot data plane is claimed. | Durable volume/snapshot manifests, leases, generations, taint provenance, restore/delete reconciliation and snapshot exclusions. | Linux/KVM crash, corruption, deletion-race and artifact-canary evidence. |
| SBX-033--036 | Request-level grant shape validation and chunk redaction exist; no secret profile is advertised. | Contextual resolver, audit, ephemeral injection/reap, trusted broker/provenance and adversarial process-isolation suite. | Linux/KVM proc/FD/ptrace/daemon evidence before enabling secrets. |
| SBX-037--038 | Direct IP and malformed egress grants are rejected; foundation profile has no NIC and egress is unavailable. | Mandatory proxy control/data plane plus DNS/IDNA/CNAME/address-lifecycle semantics. | Linux/KVM no-direct-route and proxy-bypass matrix. |
| SBX-039 | Unsupported profiles remain unavailable. | Release gate aggregating all profile evidence. | Every required profile suite and its retained evidence. |

The local `cmd/firecracker-e2e` capability report currently refuses execution on
Darwin because it is not Linux, has no `/dev/kvm` or cgroups v2, and has no
reviewed final fixture plan. Do not replace this block with a simulated pass.
