package sandboxcontrol

import (
	"context"

	"github.com/0x63616c/agent-runtime/sandbox"
)

// ResourceReadModel is the durable, principal-scoped projection required
// before sandbox.control/v1 can serve public resource-inspection endpoints.
//
// DurableStore deliberately contains only the immutable operation ledger and
// its bounded routing metadata. In particular, an operation target is not a
// SandboxInfo or ProcessInfo: it cannot report desired/actual state, admitted
// image and limits, process result, or object retention without inventing
// state. Implementations must persist those projections atomically with their
// control-plane transitions and apply the same not-found-or-denied semantics as
// DurableStore.Get. Output replay is intentionally not included here because
// it additionally needs retained, redacted bytes rather than host-output
// digests and sizes.
//
// The control API must not expose a resource endpoint until its configured
// store implements this interface. Keeping it separate from DurableStore makes
// that storage/migration prerequisite explicit for both the in-memory and
// PostgreSQL control paths.
type ResourceReadModel interface {
	GetSandbox(context.Context, string, sandbox.SandboxID) (sandbox.SandboxInfo, error)
	GetProcess(context.Context, string, sandbox.ProcessID) (sandbox.ProcessInfo, error)
	GetVolume(context.Context, string, sandbox.VolumeID) (sandbox.VolumeInfo, error)
	ListVolumes(context.Context, string, sandbox.Page) (sandbox.VolumePage, error)
	GetSnapshot(context.Context, string, sandbox.SnapshotID) (sandbox.SnapshotInfo, error)
	ListSnapshots(context.Context, string, sandbox.Page) (sandbox.SnapshotPage, error)
}
