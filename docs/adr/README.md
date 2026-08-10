# Architecture decisions

Accepted ADRs, the master requirements, `CONTEXT.md`, and
[`../architecture/system.md`](../architecture/system.md) are the binding
implementation contract. Planning and copied/external drafts have no
implementation authority unless an accepted ADR explicitly promotes them.

| ADR | Decision |
| --- | --- |
| [0001](0001-source-of-truth-and-monorepo.md) | Source of truth and monorepo boundary |
| [0002](0002-declarative-infrastructure.md) | Declarative infrastructure ownership and rendering |
| [0003](0003-postgresql-event-outbox-authority.md) | PostgreSQL, product-event and outbox authority |
| [0004](0004-codex-subscription-support.md) | Codex subscription support policy |
| [0005](0005-sandbox-control-host-protocol.md) | Sandbox control and host-agent protocol |
| [0006](0006-go-module-and-release-topology.md) | Go module and release topology |
| [0007](0007-milestone-status-and-ntfy-reporting.md) | Milestone status and ntfy reporting |
| [0008](0008-approval-persistence.md) | Approval persistence and authority |
| [0009](0009-payload-compatibility.md) | Temporal payload compatibility |
| [0010](0010-documentation-deployment.md) | Superseded documentation generation and deployment |
| [0011](0011-runtime-state-authority-and-content-boundary.md) | Runtime state authority and immutable content boundary |
| [0012](0012-private-firecracker-boot-probe-v2.md) | Private Firecracker boot-probe v2 protocol |
| [0013](0013-temporary-documentation-audit-exception.md) | Retired documentation production-dependency audit exception |
| [0014](0014-astro-starlight-documentation-platform.md) | Astro Starlight documentation platform |
| [0015](0015-codec-enabled-orchestration-worker.md) | Codec-enabled orchestration worker capability |
