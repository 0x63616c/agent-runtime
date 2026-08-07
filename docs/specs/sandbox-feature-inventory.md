# Sandbox feature inventory

Status: planned, binding delivery checklist. Nothing is checked until its linked
acceptance evidence is real and green. This inventory is deliberately broader
than a foundation MVP: every requested authority profile is a final-release
item. A security profile may be unavailable until its own rows pass, but no
unchecked row is an authorized scope cut.

Each item names the binding requirement(s), specification section and evidence
family. SBX evidence identifiers refer to the acceptance ledger. Public
behavior is proven through S9/S10 durable control seams unless the item says
internal SPI or declarative infrastructure.

## A. Ownership, control plane and declared infrastructure

- [ ] INV-001 Single monorepo owns sandbox client, control, core, host agents, adapters, deploy assets, examples and docs. Requirements: MON-002, SBX-001. Spec: [1](sandbox.md#1-binding-decision-and-release-scope). Evidence: SBX-001.
- [ ] INV-002 Control is durable service, not activity-local live handle. Requirements: SBX-001. Spec: [1](sandbox.md#1-binding-decision-and-release-scope). Evidence: SBX-001.
- [ ] INV-003 Per-host agents own execution resources. Requirements: SBX-001, TMP-007. Spec: [3.1](sandbox.md#31-modules-and-roles). Evidence: SBX-001.
- [ ] INV-004 Runtime integration uses principal-bound control client only. Requirements: SBX-003, S9. Spec: [4](sandbox.md#4-public-durable-control-interface). Evidence: SBX-003, SBX-011.
- [ ] INV-005 Public packages cannot import backend/VM/KVM/jailer/vsock types. Requirements: SBX-010, SBX-011. Spec: [3.1](sandbox.md#31-modules-and-roles). Evidence: SBX-011.
- [ ] INV-006 Control records host route and generation before dispatch. Requirements: SBX-002, SBX-005. Spec: [3.2](sandbox.md#32-durable-routing-and-recovery). Evidence: SBX-002.
- [ ] INV-007 Worker retry reconnects and routes by durable ID from another worker. Requirements: SBX-003, TMP-010. Spec: [3.2](sandbox.md#32-durable-routing-and-recovery). Evidence: SBX-003, TST-005.
- [ ] INV-008 Host-unreachable state, lease fencing and lost/uncertain outcomes are inspectable. Requirements: SBX-002, SBX-006, SBX-014. Spec: [3.2](sandbox.md#32-durable-routing-and-recovery). Evidence: SBX-002, SBX-014.
- [ ] INV-009 SandboxControlDeployment is typed/versioned desired state. Requirements: DEP-004, SBX-002. Spec: [3.4](sandbox.md#34-declarative-stack-resource-ownership-and-reconciliation). Evidence: SBX-001, DEP-004, INF-001 through INF-004.
- [ ] INV-010 HostAgentPool declares KVM/kernel/Firecracker/cgroup/jailer/capacity prerequisites. Requirements: SBX-021, DEP-007. Spec: [3.4](sandbox.md#34-declarative-stack-resource-ownership-and-reconciliation). Evidence: SBX-021, DEP-007, INF-001 through INF-005.
- [ ] INV-011 Capability profiles are typed/versioned desired state with activation status. Requirements: SBX-024, SBX-039. Spec: [3.5](sandbox.md#35-desired-policy-objects). Evidence: SBX-024, SBX-039, INF-001 through INF-004.
- [ ] INV-012 Image/network/storage/quota/reaper policies are typed/versioned desired state. Requirements: SBX-018 through SBX-020, SBX-037. Spec: [3.5](sandbox.md#35-desired-policy-objects). Evidence: SBX-018, SBX-020, SBX-037, INF-001 through INF-004.
- [ ] INV-013 Desired, effective, observed and drift/reconciliation state is inspectable to authorized operators. Requirements: SBX-002, DEP-006. Spec: [3.4](sandbox.md#34-declarative-stack-resource-ownership-and-reconciliation). Evidence: SBX-002, DEP-006, INF-004.
- [ ] INV-014 Declared-state reconciliation is idempotent, fenced, auditable and has no hidden fallback. Requirements: SBX-002, SBX-014. Spec: [3.4](sandbox.md#34-declarative-stack-resource-ownership-and-reconciliation). Evidence: SBX-014, INF-002 through INF-005.
- [ ] INV-015 KVM prerequisite drift makes host pool unready rather than unsafe-local fallback. Requirements: SBX-021, SBX-022, DEP-007. Spec: [3.4](sandbox.md#34-declarative-stack-resource-ownership-and-reconciliation). Evidence: SBX-021, SBX-022, DEP-007, INF-004.
- [ ] INV-016 Control and host role credentials are separated. Requirements: TMP-008, DEP-005, SBX-040. Spec: [3.3](sandbox.md#33-host-enrollment-authenticated-envelopes-and-fencing), [3.4](sandbox.md#34-declarative-stack-resource-ownership-and-reconciliation). Evidence: DEP-005, SBX-040, INF-003.
- [ ] INV-017 Client construction performs an authenticated no-operation bind handshake and pins an opaque non-forgeable authority/tenant/subject binding that is neither caller-selected nor public. Requirements: SBX-007. Spec: [3.7](sandbox.md#37-principal-and-authorization). Evidence: SBX-007.
- [ ] INV-018 Every sandbox object/ledger/resolver/store/audit/route is Principal scoped. Requirements: SBX-007, INV-ID-002. Spec: [3.7](sandbox.md#37-principal-and-authorization). Evidence: SBX-007.
- [ ] INV-019 Guessed/leaked IDs and cross-tenant request-ID collision return non-enumerating denial. Requirements: SBX-007. Spec: [3.7](sandbox.md#37-principal-and-authorization). Evidence: SBX-007.
- [ ] INV-020 Host dispatch envelopes contain scoped ID, digest, lease generation and expiry. Requirements: SBX-002, SBX-007, SBX-041. Spec: [3.3](sandbox.md#33-host-enrollment-authenticated-envelopes-and-fencing). Evidence: SBX-002, SBX-041.

## B. Public control API, immutable inputs and canonical operations

- [ ] INV-021 `NewClient` is the backend-agnostic public construction path, completes authenticated Principal binding before publication and exposes submit, inspect, wait, watch, reconnect, output replay, process control and resource inspection by ID; every synchronous error supports safe `AsFailure` inspection without backend causes. Requirements: SBX-003, SBX-007, SBX-011. Spec: [4](sandbox.md#4-public-durable-control-interface). Evidence: SBX-003, SBX-007, SBX-011.
- [ ] INV-022 Client bind construction, per-attempt concurrent credential application/refresh/re-authentication/header clearing and Close have bounded local transport semantics with no ambient endpoint/identity/credential/TLS/backend fallback, no cross-request/origin/Principal credential reuse and no durable resource lifetime effect. Requirements: SBX-007, SBX-011, SBX-012, SBX-013. Spec: [4](sandbox.md#4-public-durable-control-interface). Evidence: SBX-007, SBX-011, SBX-012, SBX-013.
- [ ] INV-023 Every listed mutator has Operation ID: create/restore/exec/copy/snapshot/close/reconcile/storage/delete/approval. Requirements: SBX-004. Spec: [4](sandbox.md#4-public-durable-control-interface). Evidence: SBX-004.
- [ ] INV-024 Public IDs are typed opaque, globally non-parseable and safe to log but not authorization. Requirements: ENG-002, SBX-011. Spec: [4.1](sandbox.md#41-operations-and-results). Evidence: SBX-011.
- [ ] INV-025 Operation includes canonical/schema/policy identity, state sequence, retention, result/output and reconciliation. Requirements: SBX-005, SBX-006. Spec: [4.1](sandbox.md#41-operations-and-results). Evidence: SBX-005.
- [ ] INV-026 Operation transitions accepted through tombstoned, including uncertain and cleanup states. Requirements: SBX-005, SBX-013. Spec: [4.1](sandbox.md#41-operations-and-results). Evidence: SBX-013.
- [ ] INV-027 Exported types, pointer-optional tagged results, tagged targets/events, optional volume attachment and stable Failure/Error codes/details have zero, validation, wire, authorization, concurrency, cancellation and failure semantics. Requirements: ENG-006, SBX-012, SBX-015, SBX-018. Spec: [4.2](sandbox.md#42-exported-value-semantics). Evidence: SBX-012, SBX-015, SBX-018.
- [ ] INV-028 Caller maps/slices/pointers/unions/labels are deep-copied and frozen before authorization. Requirements: SBX-008. Spec: [5.1](sandbox.md#51-acceptance-pipeline). Evidence: SBX-008.
- [ ] INV-029 Caller readers become bounded immutable verified artifacts before acceptance. Requirements: SBX-008, SBX-026. Spec: [5.1](sandbox.md#51-acceptance-pipeline). Evidence: SBX-008, SBX-026.
- [ ] INV-030 Backends independently recheck security facts at dispatch. Requirements: SBX-010, SBX-024. Spec: [5.1](sandbox.md#51-acceptance-pipeline). Evidence: SBX-010, SBX-024.
- [ ] INV-031 Wire format is strict sandbox.control/v1 canonical JSON and tagged unions never use Go interfaces. Requirements: SBX-008. Spec: [5.2](sandbox.md#52-canonical-schema). Evidence: SBX-008.
- [ ] INV-032 Decoder rejects unknown/duplicate/ambiguous input and bounds parsing before allocation. Requirements: SBX-008, TST-001. Spec: [5.2](sandbox.md#52-canonical-schema). Evidence: SBX-008.
- [ ] INV-033 Canonicalization specifies integer duration/count, UTF-8/NFC, map order, nil/empty, paths, IDNA domain/protocol/ports, literal IPv4/IPv6 grant rejection, image and key-lifecycle normalization. Requirements: SBX-008, SBX-034, SBX-037, SBX-038. Spec: [5.2](sandbox.md#52-canonical-schema). Evidence: SBX-008, SBX-034, SBX-037, SBX-038.
- [ ] INV-034 Canonical hash has golden vectors for pointer-optional tagged result/event unions, domain-only network rules, literal-IP rejection and signing-key lifecycle and never hashes Go structs. Requirements: SBX-008, SBX-011, SBX-012. Spec: [5.2](sandbox.md#52-canonical-schema). Evidence: SBX-008, SBX-011, SBX-012.
- [ ] INV-035 Effective Spec persists admission, numeric identity, finite defaults, capabilities, policy/canonicalizer, authority/retention. Requirements: SBX-009. Spec: [5.3](sandbox.md#53-effective-specdefaults). Evidence: SBX-009, SBX-019.
- [ ] INV-036 Retry/restore reuses persisted effective values or fails incompatibly. Requirements: SBX-009. Spec: [5.3](sandbox.md#53-effective-specdefaults). Evidence: SBX-009.

## C. Ledger, recovery, lifecycle and process behavior

- [ ] INV-037 Ledger key is Principal scope plus Operation ID. Requirements: SBX-005, INV-ID-003. Spec: [6.1](sandbox.md#61-ledger-identity-and-retention). Evidence: SBX-005.
- [ ] INV-038 Same canonical ID request reconnects; different canonical body conflicts. Requirements: SBX-004, SBX-005. Spec: [6.1](sandbox.md#61-ledger-identity-and-retention). Evidence: SBX-004, SBX-005.
- [ ] INV-039 Terminal result, output and tombstone have finite configured retention/expiry behavior. Requirements: SBX-005, SBX-006. Spec: [6.1](sandbox.md#61-ledger-identity-and-retention). Evidence: SBX-005.
- [ ] INV-040 Ledger/resource desired state/audit intent share transaction and outbox. Requirements: SBX-005, DAT-006. Spec: [6.2](sandbox.md#62-commit-orderreconciliation). Evidence: SBX-005, DAT-006.
- [ ] INV-041 Host dispatch and receipt journal deduplicate using ID/digest/host generation/lease fence. Requirements: SBX-002, SBX-004. Spec: [6.2](sandbox.md#62-commit-orderreconciliation). Evidence: SBX-002, SBX-004.
- [ ] INV-042 Crash at every acceptance/dispatch/start/commit/acknowledgement boundary reconciles explicitly. Requirements: SBX-006, TST-005. Spec: [6.2](sandbox.md#62-commit-orderreconciliation). Evidence: SBX-006, TST-005.
- [ ] INV-043 Lost observation becomes visible uncertain rather than false success. Requirements: SBX-006, TOL-006. Spec: [6.2](sandbox.md#62-commit-orderreconciliation). Evidence: SBX-006.
- [ ] INV-044 External command effects remain application-idempotent despite sandbox exec deduplication. Requirements: SBX-006, TMP-009. Spec: [6.2](sandbox.md#62-commit-orderreconciliation). Evidence: SBX-006, TMP-009.
- [ ] INV-045 Host, attachment, snapshot and cleanup leases are finite/generation-fenced. Requirements: SBX-002, SBX-013. Spec: [6.3](sandbox.md#63-leasesreaper). Evidence: SBX-002, SBX-013.
- [ ] INV-046 Reaper survives worker/control/host crash and proves cleanup pending versus confirmed. Requirements: SBX-014. Spec: [6.3](sandbox.md#63-leasesreaper). Evidence: SBX-014.
- [ ] INV-047 Reaper timing/retry use injected clock and bounded backoff. Requirements: ENG-003, ENG-004, SBX-014. Spec: [6.3](sandbox.md#63-leasesreaper). Evidence: SBX-014.
- [ ] INV-048 Sandbox desired/actual states and Process states are explicit and independently meaningful. Requirements: SBX-013. Spec: [7](sandbox.md#7-lifecycle-process-control-and-termination). Evidence: SBX-013.
- [ ] INV-049 Exec/copy/snapshot/close/reconcile/delete races have transition-table outcomes. Requirements: SBX-013, INV-SBX-005. Spec: [7](sandbox.md#7-lifecycle-process-control-and-termination). Evidence: SBX-013.
- [ ] INV-050 Close is durable, concurrent-idempotent and cleanup survives abandoned waiters. Requirements: SBX-013, SBX-014. Spec: [7](sandbox.md#7-lifecycle-process-control-and-termination). Evidence: SBX-013, SBX-014.
- [ ] INV-051 Secure command requires absolute path, typed argv, numeric identity, workdir, umask, deterministic environment and Grant. Requirements: SBX-011, SBX-012. Spec: [7.1](sandbox.md#71-commands-and-context). Evidence: SBX-011, SBX-012.
- [ ] INV-052 PATH lookup, host env/config and inherited descriptors are excluded. Requirements: SBX-021, SBX-035. Spec: [7.1](sandbox.md#71-commands-and-context). Evidence: SBX-021, SBX-035.
- [ ] INV-053 Start acknowledgement lifetime and wait-observation cancellation are separate. Requirements: SBX-016. Spec: [7.1](sandbox.md#71-commands-and-context). Evidence: SBX-016.
- [ ] INV-054 Signal/kill are typed durable controls with already-terminal and unsupported outcomes. Requirements: SBX-003, SBX-016. Spec: [7.1](sandbox.md#71-commands-and-context). Evidence: SBX-003, SBX-016.
- [ ] INV-055 ProcessResult distinguishes exit/signal/timeout/OOM/output/cancel/kill/loss/uncertain. Requirements: SBX-015. Spec: [7.2](sandbox.md#72-processresult). Evidence: SBX-015.
- [ ] INV-056 Exit code never flattens typed termination and tree cleanup is observed separately. Requirements: SBX-015. Spec: [7.2](sandbox.md#72-processresult). Evidence: SBX-015.
- [ ] INV-057 Process terminal race matrix uses durable ordering/fake time. Requirements: SBX-016. Spec: [7.2](sandbox.md#72-processresult). Evidence: SBX-016.

## D. Output, filesystem and portable workspace

- [ ] INV-058 Core owns bounded per-stream spool/tee; adapter cannot bypass it. Requirements: SBX-010, SBX-017. Spec: [8](sandbox.md#8-output-redaction-and-replay). Evidence: SBX-010, SBX-017.
- [ ] INV-059 Raw output is redacted before durable output/events/tails/logs/errors/metrics. Requirements: SBX-017, OBS-003. Spec: [8](sandbox.md#8-output-redaction-and-replay). Evidence: SBX-017, OBS-003.
- [ ] INV-060 Stdout/stderr each have sequence, tail, retention, truncation and gap. Requirements: SBX-017. Spec: [8](sandbox.md#8-output-redaction-and-replay). Evidence: SBX-017.
- [ ] INV-061 Replay supports reconnect, at-least-once sequence dedupe, retention gap and final result. Requirements: SBX-003, SBX-006, SBX-017. Spec: [8](sandbox.md#8-output-redaction-and-replay). Evidence: SBX-003, SBX-017.
- [ ] INV-062 Produced output limit kills safely; retained limit produces visible stream truncation without pipe deadlock. Requirements: SBX-015, SBX-017. Spec: [8](sandbox.md#8-output-redaction-and-replay). Evidence: SBX-015, SBX-017.
- [ ] INV-063 Wait completion does not require user drain and reader lag is bounded. Requirements: SBX-017. Spec: [8](sandbox.md#8-output-redaction-and-replay). Evidence: SBX-017.
- [ ] INV-064 Literal redaction handles chunk boundary, binary/overlap, maximum patterns and pinned secret versions deterministically. Requirements: SBX-017, SBX-033. Spec: [8](sandbox.md#8-output-redaction-and-replay). Evidence: SBX-017, SBX-033.
- [ ] INV-065 Guest paths are absolute/clean/root-confined and descriptor-relative. Requirements: SBX-027. Spec: [9.1](sandbox.md#91-guest-pathtransfer). Evidence: SBX-027.
- [ ] INV-066 Paths reject symlink/replacement/mount crossing/reserved/ambiguous escapes. Requirements: SBX-027. Spec: [9.1](sandbox.md#91-guest-pathtransfer). Evidence: SBX-027.
- [ ] INV-067 Portable copy-in/out is available before mounts. Requirements: SBX-026. Spec: [9.1](sandbox.md#91-guest-pathtransfer). Evidence: SBX-026.
- [ ] INV-068 Transfer validates size/digest/archive expansion/links and resource bounds. Requirements: SBX-026, SBX-018. Spec: [9.1](sandbox.md#91-guest-pathtransfer). Evidence: SBX-026, SBX-018.
- [ ] INV-069 Transfer overwrite, mode/owner, fsync, cancellation and partial cleanup semantics are typed. Requirements: SBX-026. Spec: [9.1](sandbox.md#91-guest-pathtransfer). Evidence: SBX-026.
- [ ] INV-070 Copy-out emits authorized immutable artifact metadata, not unbounded byte slice. Requirements: SBX-026, DAT-002. Spec: [9.1](sandbox.md#91-guest-pathtransfer). Evidence: SBX-026.
- [ ] INV-071 Host mounts are final-release separately gated RO/RW profile, never silently emulated. Requirements: SBX-028, SBX-039. Spec: [9.2](sandbox.md#92-host-mount-profile). Evidence: SBX-028, SBX-039.
- [ ] INV-072 Mount source identity is descriptor-first and pinned across attachment. Requirements: SBX-028. Spec: [9.2](sandbox.md#92-host-mount-profile). Evidence: SBX-028.
- [ ] INV-073 Mount link/special file/rename/replacement/live/frozen/RW/execute semantics are explicit. Requirements: SBX-028. Spec: [9.2](sandbox.md#92-host-mount-profile). Evidence: SBX-028.
- [ ] INV-074 Sharing daemon boundary is jailed, narrow and named as TCB risk. Requirements: SBX-028. Spec: [9.2](sandbox.md#92-host-mount-profile). Evidence: SBX-028.
- [ ] INV-075 Local adapter mechanically rejects mounts. Requirements: SBX-022. Spec: [9.2](sandbox.md#92-host-mount-profile). Evidence: SBX-022.

## E. Grants, secrets, taint and elevated actions

- [ ] INV-076 Sensitive Grant is explicit none/select/inherit rather than ambiguous nil; network uses a separate typed domain/protocol/port rule selection with no literal-IP authority. Requirements: SBX-034, SBX-037, SBX-038. Spec: [10](sandbox.md#10-grant-truth-table). Evidence: SBX-034, SBX-037, SBX-038.
- [ ] INV-077 Omitted/zero/empty Grant means no secrets/mounts and deny-all network. Requirements: SBX-034, INV-SEC-002. Spec: [10](sandbox.md#10-grant-truth-table). Evidence: SBX-034.
- [ ] INV-078 Empty select, unknown/duplicate, ambiguous string network authority and widening grant are rejected. Requirements: SBX-034, SBX-037, SBX-038. Spec: [10](sandbox.md#10-grant-truth-table). Evidence: SBX-034, SBX-037, SBX-038.
- [ ] INV-079 Inheritance is distinguishable, policy-approved and never expands Effective Spec; every selected network domain/protocol/port is contained by it and literal IP input fails closed. Requirements: SBX-034, SBX-037. Spec: [10](sandbox.md#10-grant-truth-table). Evidence: SBX-034, SBX-037.
- [ ] INV-080 Resolver receives authenticated contextual Principal/resource/operation/binding/purpose/expiry. Requirements: SBX-033. Spec: [11.1](sandbox.md#111-contextual-resolution). Evidence: SBX-033.
- [ ] INV-081 Resolver values are bounded, non-empty, versioned, expiring, ephemeral and audited. Requirements: SBX-033. Spec: [11.1](sandbox.md#111-contextual-resolution). Evidence: SBX-033.
- [ ] INV-082 Retry pins secret version or fails before start; rotation cannot silently change side effect. Requirements: SBX-033, SBX-009. Spec: [11.1](sandbox.md#111-contextual-resolution). Evidence: SBX-033, SBX-009.
- [ ] INV-083 SDK secrets are just-in-time non-snapshotted delivery, revoked after tree reap, never persisted. Requirements: SBX-033, SBX-035. Spec: [11.1](sandbox.md#111-contextual-resolution). Evidence: SBX-033, SBX-035.
- [ ] INV-084 Known-secret taint records sandbox provenance and persists through volume attachment/tombstone. Requirements: SBX-032. Spec: [11.2](sandbox.md#112-taintsnapshot-limit). Evidence: SBX-032.
- [ ] INV-085 Taint limitation is honest about ordinary env/argv/stdin/image/network/host storage secret channels. Requirements: SBX-031, SBX-032. Spec: [11.2](sandbox.md#112-taintsnapshot-limit). Evidence: SBX-031, SBX-032.
- [ ] INV-086 Snapshot excludes only stated SDK tmpfs/memory/socket/mount/volume content and never claims arbitrary secret absence. Requirements: SBX-031. Spec: [11.2](sandbox.md#112-taintsnapshot-limit). Evidence: SBX-031.
- [ ] INV-087 Tainted/unknown snapshot is denied or requires bound attestation with manifest provenance. Requirements: SBX-032. Spec: [11.2](sandbox.md#112-taintsnapshot-limit). Evidence: SBX-032.
- [ ] INV-088 High-value credentials use external broker or proven immutable trusted-exec, never helper path alone. Requirements: SBX-036. Spec: [11.3](sandbox.md#113-elevated-credentials). Evidence: SBX-036.
- [ ] INV-089 Trusted-exec fixes executable digest, identity, workdir/mounts, loader/env and argument schema. Requirements: SBX-036. Spec: [11.3](sandbox.md#113-elevated-credentials). Evidence: SBX-036.

## F. Egress profile

- [ ] INV-090 Guest has no direct routable external/DNS/metadata/private/control-plane route. Requirements: SBX-037. Spec: [12](sandbox.md#12-egress-profile-invariant). Evidence: SBX-037.
- [ ] INV-091 All guest egress uses authenticated mandatory host proxy. Requirements: SBX-037. Spec: [12](sandbox.md#12-egress-profile-invariant). Evidence: SBX-037.
- [ ] INV-092 Proxy enforces normalized granted destination domain plus protocol/port, resolves and pins the permitted address itself, and refuses every guest-supplied literal IP or string `host:port`. Requirements: SBX-037, SBX-038. Spec: [12](sandbox.md#12-egress-profile-invariant). Evidence: SBX-037, SBX-038.
- [ ] INV-093 Egress claim is destination restriction only, not TLS/HTTP identity or DLP. Requirements: SBX-037, SBX-038. Spec: [12](sandbox.md#12-egress-profile-invariant). Evidence: SBX-037, SBX-038.
- [ ] INV-094 Rules define IDNA/wildcard/CNAME, protocol/port ranges, proxy-only IPv4/IPv6 result normalization/prohibited-range refusal and per-connection address pinning. Requirements: SBX-038. Spec: [12](sandbox.md#12-egress-profile-invariant). Evidence: SBX-038.
- [ ] INV-095 Direct DNS/DoH/guest IP/cache and cross-destination reuse are impossible. Requirements: SBX-037, SBX-038. Spec: [12](sandbox.md#12-egress-profile-invariant). Evidence: SBX-037, SBX-038.
- [ ] INV-096 Proxy outage/auth/policy failure is fail closed and quota-accounted. Requirements: SBX-037, SBX-018. Spec: [12](sandbox.md#12-egress-profile-invariant). Evidence: SBX-037, SBX-018.
- [ ] INV-097 SNI/Host mismatch, ECH, shared IP and redirects have precise no-overclaim behavior/tests. Requirements: SBX-038. Spec: [12](sandbox.md#12-egress-profile-invariant). Evidence: SBX-038.
- [ ] INV-098 DNS-to-IP firewall alone cannot advertise egress profile. Requirements: SBX-037. Spec: [12](sandbox.md#12-egress-profile-invariant). Evidence: SBX-037.

## G. Limits, images, volumes and snapshots

- [ ] INV-099 All zero resource values resolve to finite Effective Spec values. Requirements: SBX-019. Spec: [13](sandbox.md#13-resources-quotas-and-admission). Evidence: SBX-019.
- [ ] INV-100 Per-sandbox limits cover CPU/memory/root/tmpfs/PIDs/processes/open files/inodes/files/lifetime. Requirements: SBX-018. Spec: [13](sandbox.md#13-resources-quotas-and-admission). Evidence: SBX-018.
- [ ] INV-101 I-O limits cover runtime/output/transfer/archive/read-write bytes and IOPS. Requirements: SBX-018. Spec: [13](sandbox.md#13-resources-quotas-and-admission). Evidence: SBX-018.
- [ ] INV-102 Network limits cover connections/proxy streams/bytes/bandwidth. Requirements: SBX-018. Spec: [13](sandbox.md#13-resources-quotas-and-admission). Evidence: SBX-018.
- [ ] INV-103 Storage limits cover volume/snapshot count/bytes/inodes/attachments/leases/image conversion. Requirements: SBX-018. Spec: [13](sandbox.md#13-resources-quotas-and-admission). Evidence: SBX-018.
- [ ] INV-104 Control admission bounds request/operation/watch/cursor/log/event/outbox/principal/global capacity. Requirements: SBX-018. Spec: [13](sandbox.md#13-resources-quotas-and-admission). Evidence: SBX-018.
- [ ] INV-105 Limits and fleet admission are distinct and have typed breach outcome. Requirements: SBX-018. Spec: [13](sandbox.md#13-resources-quotas-and-admission). Evidence: SBX-018.
- [ ] INV-106 CPU precision, aggregate tmpfs and unsupported adapter precision are explicit. Requirements: SBX-018, SBX-024. Spec: [13](sandbox.md#13-resources-quotas-and-admission). Evidence: SBX-018, SBX-024.
- [ ] INV-107 Images are immutable admitted content with verified safe metadata. Requirements: SBX-020. Spec: [14.1](sandbox.md#141-imagesidentity). Evidence: SBX-020.
- [ ] INV-108 Digest is not a provenance claim; admission evidence is inspectable in SandboxInfo. Requirements: SBX-020. Spec: [14.1](sandbox.md#141-imagesidentity). Evidence: SBX-020.
- [ ] INV-109 Numeric identity/group/protocol resolve at admission and incompatible images reject. Requirements: SBX-020. Spec: [14.1](sandbox.md#141-imagesidentity). Evidence: SBX-020.
- [ ] INV-110 Volume manifest includes format, encryption/integrity, quota, taint, generation lease and tombstone. Requirements: SBX-029. Spec: [14.2](sandbox.md#142-volumes). Evidence: SBX-029.
- [ ] INV-111 Volume attachment is leased/generation-numbered with RW exclusivity and coherent RO rule. Requirements: SBX-029. Spec: [14.2](sandbox.md#142-volumes). Evidence: SBX-029.
- [ ] INV-112 Volume create/attach crash/delete race and multi-attach rollback reconcile. Requirements: SBX-029. Spec: [14.2](sandbox.md#142-volumes). Evidence: SBX-029.
- [ ] INV-113 Snapshot manifest includes provenance/effective ceiling/owner/schema/capability/encryption/integrity/taint/lease/tombstone. Requirements: SBX-030. Spec: [14.3](sandbox.md#143-snapshots). Evidence: SBX-030.
- [ ] INV-114 Snapshot is quiesced disk-only, staged/verified/atomically published and crash-reaped. Requirements: SBX-030. Spec: [14.3](sandbox.md#143-snapshots). Evidence: SBX-030.
- [ ] INV-115 Production snapshot encryption/integrity is mandatory and reported. Requirements: SBX-030. Spec: [14.3](sandbox.md#143-snapshots). Evidence: SBX-030.
- [ ] INV-116 Snapshot inspect/list/lease/delete/tombstone/restore are durable Principal-scoped operations. Requirements: SBX-003, SBX-030. Spec: [14.3](sandbox.md#143-snapshots). Evidence: SBX-030.
- [ ] INV-117 Restore default uses recorded policy ceiling; override only narrows and revalidates. Requirements: SBX-009, SBX-030. Spec: [14.3](sandbox.md#143-snapshots). Evidence: SBX-009, SBX-030.
- [ ] INV-118 Corruption/manifest swap/concurrent delete/restore/version incompatibility have typed recovery. Requirements: SBX-030. Spec: [14.3](sandbox.md#143-snapshots). Evidence: SBX-030.

## H. Profiles, adapters, audit and runtime

- [ ] INV-119 Capabilities are canonical structured/versioned/digested descriptors, not a boolean or feature-string bag. Requirements: SBX-024, SBX-011, SBX-012. Spec: [15](sandbox.md#15-capabilities-spi-and-adapters). Evidence: SBX-024, SBX-011, SBX-012.
- [ ] INV-120 Snapshot declares control protocol, isolation, guest, resource precision, reconnect, admission, output, transfer, mounts, storage, egress, secrets, signals and safe trust/signing-key lifecycle. Requirements: SBX-024, SBX-040, SBX-041. Spec: [15](sandbox.md#15-capabilities-spi-and-adapters). Evidence: SBX-024, SBX-040, SBX-041.
- [ ] INV-121 Typed capability requirements select minimum state; canonical snapshot is negotiated/persisted/rechecked on dispatch/restore. Requirements: SBX-024. Spec: [15](sandbox.md#15-capabilities-spi-and-adapters). Evidence: SBX-024.
- [ ] INV-122 Capability regression, expired signing lifecycle or unsupported request fails closed with no silent degradation. Requirements: SBX-024, SBX-025, SBX-040, SBX-041. Spec: [15](sandbox.md#15-capabilities-spi-and-adapters). Evidence: SBX-024, SBX-025, SBX-040, SBX-041.
- [ ] INV-123 Foundation profile is Firecracker/KVM jailed non-root deny-all bounded durable execution. Requirements: SBX-021. Spec: [15](sandbox.md#15-capabilities-spi-and-adapters). Evidence: SBX-021.
- [ ] INV-124 Each requested profile has its own contract and black-box activation suite; final matrix requires all. Requirements: SBX-025, SBX-039. Spec: [15](sandbox.md#15-capabilities-spi-and-adapters). Evidence: SBX-025, SBX-039.
- [ ] INV-125 Backend SPI is expert-only normalized input and cannot own public security semantics. Requirements: SBX-010. Spec: [15](sandbox.md#15-capabilities-spi-and-adapters). Evidence: SBX-010.
- [ ] INV-126 Malicious adapter proves core enforcement against Grant widening/mutation/output/state/error abuse. Requirements: SBX-010. Spec: [15](sandbox.md#15-capabilities-spi-and-adapters). Evidence: SBX-010.
- [ ] INV-127 Local adapter requires acknowledgement, sanitizes convenience state and mechanically refuses unprovable authority. Requirements: SBX-022. Spec: [15](sandbox.md#15-capabilities-spi-and-adapters). Evidence: SBX-022.
- [ ] INV-128 Fake control/adapter scripts durable states/results/gaps with fake clocks and claims no execution. Requirements: SBX-023. Spec: [15](sandbox.md#15-capabilities-spi-and-adapters). Evidence: SBX-023.
- [ ] INV-129 Audit attempted/authorized/accepted/dispatched/committed/terminal/reconciled facts are append-only/deduped. Requirements: DAT-006, SBX-005. Spec: [16](sandbox.md#16-audit-errors-runtime-integration-and-gates). Evidence: DAT-006.
- [ ] INV-130 Audit fail-closed acceptance boundary is durable outbox transaction; external sink limitation is honest. Requirements: DAT-007. Spec: [16](sandbox.md#16-audit-errors-runtime-integration-and-gates). Evidence: DAT-007.
- [ ] INV-131 Public synchronous errors expose only runtime-owned Failure classification and standard context sentinels; they cannot leak nested backend/source cause, secrets, argv, host paths or proxy internals. Requirements: OBS-003, SBX-011, SBX-012. Spec: [4.4](sandbox.md#44-public-api-field-and-method-semantics), [16](sandbox.md#16-audit-errors-runtime-integration-and-gates). Evidence: OBS-003, SBX-011, SBX-012.
- [ ] INV-132 Authorized operator diagnostics are separate audited records. Requirements: OBS-002, OBS-003. Spec: [16](sandbox.md#16-audit-errors-runtime-integration-and-gates). Evidence: OBS-002, OBS-003.
- [ ] INV-133 Temporal state stores only IDs/effective references/cursors, never handles/streams/secrets/backend config. Requirements: TMP-003. Spec: [16](sandbox.md#16-audit-errors-runtime-integration-and-gates). Evidence: TMP-010.
- [ ] INV-134 Temporal retry/reconnect/cancellation/output recovery follows durable operation state and external-effect policy. Requirements: TMP-009, TMP-010, SBX-006. Spec: [16](sandbox.md#16-audit-errors-runtime-integration-and-gates). Evidence: TMP-010, SBX-006.
- [ ] INV-135 Documentation distinguishes local evidence, KVM evidence, operator responsibility and unverified claims. Requirements: DOC-007. Spec: [16](sandbox.md#16-audit-errors-runtime-integration-and-gates). Evidence: DOC-007.

## I. Verification, performance and release gate

- [ ] INV-136 Canonical/mutation/race/tenant/operation-boundary/lease/reaper/process/output/resource/image/capability/SPI tests are present. Requirements: SBX-008 through SBX-020, TST-004. Spec: [16](sandbox.md#16-audit-errors-runtime-integration-and-gates). Evidence: SBX-008 through SBX-020, TST-004.
- [ ] INV-137 Linux/KVM foundation and each profile have adversarial integration evidence through public control interface. Requirements: SBX-021, SBX-025 through SBX-039, TST-005. Spec: [16](sandbox.md#16-audit-errors-runtime-integration-and-gates). Evidence: SBX-021, SBX-025 through SBX-039, TST-005.
- [ ] INV-138 Acknowledgement-boundary failure test routes retry to different worker and proves documented outcome. Requirements: TST-005. Spec: [16](sandbox.md#16-audit-errors-runtime-integration-and-gates). Evidence: TST-005.
- [ ] INV-139 Benchmark states host/version/image/policy/durability/profile/load/quota and covers full expensive paths. Requirements: SBX-018, DEP-007. Spec: [16](sandbox.md#16-audit-errors-runtime-integration-and-gates). Evidence: TST-008.
- [ ] INV-140 Benchmark reports percentiles, capacity denial, cleanup lag and saturation tail rather than unspecified latency. Requirements: SBX-018. Spec: [16](sandbox.md#16-audit-errors-runtime-integration-and-gates). Evidence: TST-008.
- [ ] INV-141 Every profile is integrated into Workspace Agent and final release matrix. Requirements: EX-002, SBX-039. Spec: [17](sandbox.md#17-required-implementation-sequence). Evidence: EX-002, SBX-039.
- [ ] INV-142 Each vertical slice records seam, behavior matrix, red/green evidence and docs. Requirements: ENG-005, DOC-005. Spec: [17](sandbox.md#17-required-implementation-sequence). Evidence: review record, DOC-005.
- [ ] INV-143 All sandbox inventory rows and acceptance-ledger evidence are reported by just verify without silently passing missing profile. Requirements: TST-009, TST-010. Spec: [16](sandbox.md#16-audit-errors-runtime-integration-and-gates). Evidence: TST-009, TST-010.

## J. Host trust boundary, Stack evidence and API certification

- [ ] INV-144 A production host has a durable enrolled HostID, mutually authenticated TLS transport, finite credential rotation, revocation, protocol compatibility and explicit attestation limits. Requirements: SBX-040. Spec: [3.3](sandbox.md#33-host-enrollment-authenticated-envelopes-and-fencing). Evidence: SBX-040.
- [ ] INV-145 Unenrolled, revoked, expired, wrong-pool, incompatible, failed-attestation and quarantined hosts cannot receive or complete operations. Requirements: SBX-040, SBX-044. Spec: [3.3](sandbox.md#33-host-enrollment-authenticated-envelopes-and-fencing). Evidence: SBX-040, SBX-044.
- [ ] INV-146 Every dispatch/control/result envelope is mutually-authenticated, encrypted in transit, control-signed, versioned, bounded and binds tenant/principal, operation, Effective Spec, capability digest, expiry, host assignment and lease fence. Requirements: SBX-041. Spec: [3.3](sandbox.md#33-host-enrollment-authenticated-envelopes-and-fencing). Evidence: SBX-041.
- [ ] INV-147 Host receipt journal distinguishes a safe authenticated lost-ack duplicate receipt from a refused altered, expired, invalid-signature or nonce-reused replay; neither executes a second effect. Requirements: SBX-041, SBX-044. Spec: [3.3](sandbox.md#33-host-enrollment-authenticated-envelopes-and-fencing). Evidence: SBX-041, SBX-044.
- [ ] INV-148 Control durably owns assignment, renewal, lease epoch/fencing, result acceptance and public output sequence integrity; stale/duplicate results cannot cross an assignment or overwrite newer state. Requirements: SBX-042. Spec: [3.3](sandbox.md#33-host-enrollment-authenticated-envelopes-and-fencing). Evidence: SBX-042.
- [ ] INV-149 Host loss/security violations fence, quarantine, reconcile/clean, retain uncertainty where required and only then permit reassignment. Requirements: SBX-042, SBX-044. Spec: [3.3](sandbox.md#33-host-enrollment-authenticated-envelopes-and-fencing). Evidence: SBX-042, SBX-044.
- [ ] INV-150 Control, core, host and Jailer/share/proxy have non-overlapping cgroup, network, image, mount, output and cleanup authority; negative deployment tests prove role denial. Requirements: SBX-043. Spec: [3.6](sandbox.md#36-authority-boundary). Evidence: SBX-043.
- [ ] INV-151 Public S9 durable-control acceptance runs replay, revocation, stale lease, wrong tenant, rogue host, lost acknowledgement, restart, output sequencing, quarantine cleanup and reassignment in M3 and Linux/KVM M4 lanes. Requirements: SBX-044. Spec: [3.3](sandbox.md#33-host-enrollment-authenticated-envelopes-and-fencing). Evidence: SBX-044.
- [ ] INV-152 `SandboxStack/v1` is the sole typed, versioned local/CI/production rendering input; Tilt only applies the same declared topology. Requirements: INF-001, INF-002. Spec: [3.4](sandbox.md#34-declarative-stack-resource-ownership-and-reconciliation). Evidence: INF-001, INF-002.
- [ ] INV-153 The Stack resource matrix declares control, hosts, trust/Secret references, enrollment/revocation, PostgreSQL/outbox/migration, RBAC, services/ports, NetworkPolicies, proxy, storage, telemetry and Temporal references with owner, lifecycle and runtime RBAC denial. Requirements: INF-001, INF-003. Spec: [3.4](sandbox.md#34-declarative-stack-resource-ownership-and-reconciliation). Evidence: INF-001, INF-003.
- [ ] INV-154 Renderer/catalog/check/diff/policy rejects missing ownership, implicit namespaces, mutable tags, ambient credentials, undeclared ports/prefixes, unlimited defaults and runtime/bootstrap mutation paths. Requirements: INF-001, INF-003, INF-004. Spec: [3.4](sandbox.md#34-declarative-stack-resource-ownership-and-reconciliation). Evidence: INF-001, INF-003, INF-004.
- [ ] INV-155 CI renders local/CI/production and two Stack IDs, proves migration upgrade/rollback, RBAC-negative behavior, NetworkPolicy admission and two-stack isolation; operator evidence records reconcile/rollback/restore/teardown. Requirements: INF-005. Spec: [3.4](sandbox.md#34-declarative-stack-resource-ownership-and-reconciliation). Evidence: INF-005.
- [ ] INV-156 The public API compile fixture contains every `Client` request, operation kind, ID, info, stream, cursor, page, result and safe failure value and imports no backend type. Requirements: SBX-011. Spec: [4.3](sandbox.md#43-compileable-public-api-reference). Evidence: SBX-011.
- [ ] INV-157 The API semantic table specifies every public method/value family’s zero/validation, strict wire, bounds, authorization, idempotency, concurrency, cancellation, uncertain outcome and failure behavior. Requirements: SBX-012, ENG-006. Spec: [4.4](sandbox.md#44-public-api-field-and-method-semantics). Evidence: SBX-012.
- [ ] INV-158 Completion reporting emits every inventory row’s requirement, section, evidence family, profile/seam, work-item owner, proof level and status; benchmarks use the stable CI evidence family rather than free text. Requirements: TST-008, TST-009. Spec: [16](sandbox.md#16-audit-errors-runtime-integration-and-gates). Evidence: TST-008, TST-009.
- [ ] INV-159 Network Grant has canonical typed domain/protocol/port rules with nil/empty/select/inherit, IDNA/wildcard, literal IPv4/IPv6/CIDR/host-port rejection and port-boundary hostile-input vectors; resolver tests cover prohibited IPv4/IPv6 answers and pinning without granting IP authority. Requirements: SBX-011, SBX-012, SBX-034, SBX-037, SBX-038. Spec: [4.4](sandbox.md#44-public-api-field-and-method-semantics). Evidence: SBX-011, SBX-012, SBX-034, SBX-037, SBX-038.
- [ ] INV-160 `NewClient` compile/API/race/fake-clock tests prove validated endpoint/TLS construction, authenticated single binding linearization, per-attempt concurrent credential Apply/re-authentication, single-writer refresh outcomes, cancellation, request-scoped header clearing, local-only Close and no ambient identity/backend/cross-origin fallback. Requirements: SBX-003, SBX-007, SBX-011, SBX-012. Spec: [3.7](sandbox.md#37-principal-and-authorization), [4](sandbox.md#4-public-durable-control-interface), [4.3](sandbox.md#43-compileable-public-api-reference). Evidence: SBX-003, SBX-007, SBX-011, SBX-012.
- [ ] INV-161 Pointer-optional tagged operation result, operation target/output events, optional attachment and exhaustive stable Failure/Error/AsFailure tests reject invalid combinations, distinguish every state/result absence, preserve context `errors.Is` and surface typed limit outcomes without backend causes. Requirements: SBX-011, SBX-012, SBX-015, SBX-017, SBX-018. Spec: [4.4](sandbox.md#44-public-api-field-and-method-semantics). Evidence: SBX-011, SBX-012, SBX-015, SBX-017, SBX-018.
- [ ] INV-162 Structured CapabilitySnapshot/key-lifecycle canonical vectors and regression tests cover declared/enforced state, precision, control key rotation/revocation/expiry and safe public metadata only. Requirements: SBX-024, SBX-040, SBX-041. Spec: [3.3](sandbox.md#33-host-enrollment-authenticated-envelopes-and-fencing), [15](sandbox.md#15-capabilities-spi-and-adapters). Evidence: SBX-024, SBX-040, SBX-041.
- [ ] INV-163 Principal-pinning acceptance/race vectors distinguish same-identity credential rotation from authority/tenant/subject switching across construction, concurrent first calls, refresh, retry, redirect, reconnect and binding renewal; mismatch is non-enumerating, audited without secret/subject exposure, has no operation effect and never rebinds, while bind install/cancel and immediate Close have one exact outcome. Requirements: SBX-007, SBX-011, SBX-012. Spec: [3.7](sandbox.md#37-principal-and-authorization), [4](sandbox.md#4-public-durable-control-interface). Evidence: SBX-007, SBX-011, SBX-012.

## Coverage rules

This checklist has 163 planned rows: 20 ownership/infrastructure, 16 public
API/immutability, 21 ledger/lifecycle/process, 18 output/filesystem, 14 grants/
secrets, 9 egress, 20 resources/images/storage, 17 profile/adapter/audit/runtime
and 28 verification/host-trust/Stack/API-certification rows. It is complete only when every row is checked
with linked evidence; a blocked KVM runner or unavailable external dependency
remains visible as blocked rather than checked.
