package sandboxcontrol

import (
	"context"
	"sort"
	"sync"

	"github.com/0x63616c/agent-runtime/sandbox"
	"github.com/cockroachdb/errors"
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

// OutputReplayStore is the separately authenticated, durable output window
// behind the public replay transport. It returns only retained redacted bytes;
// callers cannot derive output from host metadata headers.
type OutputReplayStore interface {
	ReplayOutput(context.Context, string, sandbox.ProcessID, sandbox.OutputCursor) ([]sandbox.OutputEvent, error)
}

// MemoryResourceReadModel is a hermetic, principal-scoped resource projection
// for control-plane tests. It is deliberately independent from MemoryLedger:
// callers must project complete resource facts as their state transitions are
// committed, rather than deriving resource state from an operation target.
//
// It is not a substitute for the transactional PostgreSQL projection required
// by the production control path. In particular, it has no outbox, retention
// reaper, or host reconciliation responsibility.
type MemoryResourceReadModel struct {
	mu        sync.RWMutex
	sandboxes map[string]map[sandbox.SandboxID]sandbox.SandboxInfo
	processes map[string]map[sandbox.ProcessID]sandbox.ProcessInfo
	volumes   map[string]map[sandbox.VolumeID]sandbox.VolumeInfo
	snapshots map[string]map[sandbox.SnapshotID]sandbox.SnapshotInfo
}

// NewMemoryResourceReadModel constructs an empty test-only resource projection.
func NewMemoryResourceReadModel() *MemoryResourceReadModel {
	return &MemoryResourceReadModel{
		sandboxes: make(map[string]map[sandbox.SandboxID]sandbox.SandboxInfo),
		processes: make(map[string]map[sandbox.ProcessID]sandbox.ProcessInfo),
		volumes:   make(map[string]map[sandbox.VolumeID]sandbox.VolumeInfo),
		snapshots: make(map[string]map[sandbox.SnapshotID]sandbox.SnapshotInfo),
	}
}

// ProjectSandbox records the complete current sandbox metadata for principal.
func (model *MemoryResourceReadModel) ProjectSandbox(ctx context.Context, principal string, value sandbox.SandboxInfo) error {
	if err := validateProjectionInput(ctx, principal, string(value.ID)); err != nil {
		return err
	}
	model.mu.Lock()
	defer model.mu.Unlock()
	if model.sandboxes[principal] == nil {
		model.sandboxes[principal] = make(map[sandbox.SandboxID]sandbox.SandboxInfo)
	}
	model.sandboxes[principal][value.ID] = copySandboxInfo(value)
	return nil
}

// ProjectProcess records the complete current process metadata for principal.
func (model *MemoryResourceReadModel) ProjectProcess(ctx context.Context, principal string, value sandbox.ProcessInfo) error {
	if err := validateProjectionInput(ctx, principal, string(value.ID)); err != nil {
		return err
	}
	model.mu.Lock()
	defer model.mu.Unlock()
	if model.processes[principal] == nil {
		model.processes[principal] = make(map[sandbox.ProcessID]sandbox.ProcessInfo)
	}
	model.processes[principal][value.ID] = copyProcessInfo(value)
	return nil
}

// ProjectVolume records the complete current volume metadata for principal.
func (model *MemoryResourceReadModel) ProjectVolume(ctx context.Context, principal string, value sandbox.VolumeInfo) error {
	if err := validateProjectionInput(ctx, principal, string(value.ID)); err != nil {
		return err
	}
	model.mu.Lock()
	defer model.mu.Unlock()
	if model.volumes[principal] == nil {
		model.volumes[principal] = make(map[sandbox.VolumeID]sandbox.VolumeInfo)
	}
	model.volumes[principal][value.ID] = copyVolumeInfo(value)
	return nil
}

// ProjectSnapshot records the complete current snapshot metadata for principal.
func (model *MemoryResourceReadModel) ProjectSnapshot(ctx context.Context, principal string, value sandbox.SnapshotInfo) error {
	if err := validateProjectionInput(ctx, principal, string(value.ID)); err != nil {
		return err
	}
	model.mu.Lock()
	defer model.mu.Unlock()
	if model.snapshots[principal] == nil {
		model.snapshots[principal] = make(map[sandbox.SnapshotID]sandbox.SnapshotInfo)
	}
	model.snapshots[principal][value.ID] = value
	return nil
}

func (model *MemoryResourceReadModel) GetSandbox(ctx context.Context, principal string, id sandbox.SandboxID) (sandbox.SandboxInfo, error) {
	if err := validateProjectionInput(ctx, principal, string(id)); err != nil {
		return sandbox.SandboxInfo{}, err
	}
	model.mu.RLock()
	defer model.mu.RUnlock()
	value, ok := model.sandboxes[principal][id]
	if !ok {
		return sandbox.SandboxInfo{}, ErrNotFoundOrDenied
	}
	return copySandboxInfo(value), nil
}

func (model *MemoryResourceReadModel) GetProcess(ctx context.Context, principal string, id sandbox.ProcessID) (sandbox.ProcessInfo, error) {
	if err := validateProjectionInput(ctx, principal, string(id)); err != nil {
		return sandbox.ProcessInfo{}, err
	}
	model.mu.RLock()
	defer model.mu.RUnlock()
	value, ok := model.processes[principal][id]
	if !ok {
		return sandbox.ProcessInfo{}, ErrNotFoundOrDenied
	}
	return copyProcessInfo(value), nil
}

func (model *MemoryResourceReadModel) GetVolume(ctx context.Context, principal string, id sandbox.VolumeID) (sandbox.VolumeInfo, error) {
	if err := validateProjectionInput(ctx, principal, string(id)); err != nil {
		return sandbox.VolumeInfo{}, err
	}
	model.mu.RLock()
	defer model.mu.RUnlock()
	value, ok := model.volumes[principal][id]
	if !ok {
		return sandbox.VolumeInfo{}, ErrNotFoundOrDenied
	}
	return copyVolumeInfo(value), nil
}

func (model *MemoryResourceReadModel) ListVolumes(ctx context.Context, principal string, page sandbox.Page) (sandbox.VolumePage, error) {
	if err := validateProjectionPage(ctx, principal, page); err != nil {
		return sandbox.VolumePage{}, err
	}
	model.mu.RLock()
	defer model.mu.RUnlock()
	return pageVolumes(model.volumes[principal], page), nil
}

func (model *MemoryResourceReadModel) GetSnapshot(ctx context.Context, principal string, id sandbox.SnapshotID) (sandbox.SnapshotInfo, error) {
	if err := validateProjectionInput(ctx, principal, string(id)); err != nil {
		return sandbox.SnapshotInfo{}, err
	}
	model.mu.RLock()
	defer model.mu.RUnlock()
	value, ok := model.snapshots[principal][id]
	if !ok {
		return sandbox.SnapshotInfo{}, ErrNotFoundOrDenied
	}
	return value, nil
}

func (model *MemoryResourceReadModel) ListSnapshots(ctx context.Context, principal string, page sandbox.Page) (sandbox.SnapshotPage, error) {
	if err := validateProjectionPage(ctx, principal, page); err != nil {
		return sandbox.SnapshotPage{}, err
	}
	model.mu.RLock()
	defer model.mu.RUnlock()
	return pageSnapshots(model.snapshots[principal], page), nil
}

func validateProjectionInput(ctx context.Context, principal, id string) error {
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, "read sandbox resource projection")
	}
	if !validBounded(principal, maxPrincipalBytes) || !validBounded(id, maxOperationIDBytes) {
		return ErrNotFoundOrDenied
	}
	return nil
}

func validateProjectionPage(ctx context.Context, principal string, page sandbox.Page) error {
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, "list sandbox resource projection")
	}
	if !validBounded(principal, maxPrincipalBytes) {
		return ErrNotFoundOrDenied
	}
	if page.Limit == 0 || page.Limit > 100 {
		return errors.New("list sandbox resource projection: page limit must be between one and one hundred")
	}
	return nil
}

func pageVolumes(values map[sandbox.VolumeID]sandbox.VolumeInfo, page sandbox.Page) sandbox.VolumePage {
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	start := projectionCursorStart(page.Cursor, ids)
	end := start + int(page.Limit)
	if end > len(ids) {
		end = len(ids)
	}
	result := sandbox.VolumePage{Items: make([]sandbox.VolumeInfo, 0, end-start)}
	for _, id := range ids[start:end] {
		result.Items = append(result.Items, copyVolumeInfo(values[sandbox.VolumeID(id)]))
	}
	if end < len(ids) {
		result.Next = sandbox.PageCursor(ids[end-1])
	}
	return result
}

func pageSnapshots(values map[sandbox.SnapshotID]sandbox.SnapshotInfo, page sandbox.Page) sandbox.SnapshotPage {
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	start := projectionCursorStart(page.Cursor, ids)
	end := start + int(page.Limit)
	if end > len(ids) {
		end = len(ids)
	}
	result := sandbox.SnapshotPage{Items: make([]sandbox.SnapshotInfo, 0, end-start)}
	for _, id := range ids[start:end] {
		result.Items = append(result.Items, values[sandbox.SnapshotID(id)])
	}
	if end < len(ids) {
		result.Next = sandbox.PageCursor(ids[end-1])
	}
	return result
}

func projectionCursorStart(cursor sandbox.PageCursor, values []string) int {
	if cursor == "" {
		return 0
	}
	return sort.Search(len(values), func(index int) bool { return values[index] > string(cursor) })
}

func copySandboxInfo(value sandbox.SandboxInfo) sandbox.SandboxInfo {
	copied := value
	copied.Image.Identity.Groups = append([]uint32(nil), value.Image.Identity.Groups...)
	copied.Capabilities = copyCapabilitySnapshot(value.Capabilities)
	if value.Failure != nil {
		failure := *value.Failure
		failure.Details = append([]sandbox.FailureDetail(nil), value.Failure.Details...)
		copied.Failure = &failure
	}
	return copied
}

func copyCapabilitySnapshot(value sandbox.CapabilitySnapshot) sandbox.CapabilitySnapshot {
	copied := value
	copied.Signals = append([]sandbox.Signal(nil), value.Signals...)
	for _, descriptor := range []struct{ destination, source *sandbox.CapabilityDescriptor }{
		{&copied.ControlProtocol, &value.ControlProtocol}, {&copied.Isolation, &value.Isolation},
		{&copied.Guest, &value.Guest}, {&copied.Resources, &value.Resources},
		{&copied.Reconnect, &value.Reconnect}, {&copied.ImageAdmission, &value.ImageAdmission},
		{&copied.Output, &value.Output}, {&copied.Transfer, &value.Transfer},
		{&copied.Mounts, &value.Mounts}, {&copied.Volumes, &value.Volumes},
		{&copied.Snapshots, &value.Snapshots}, {&copied.Egress, &value.Egress},
		{&copied.Secrets, &value.Secrets},
	} {
		descriptor.destination.LimitPrecision = append([]string(nil), descriptor.source.LimitPrecision...)
	}
	return copied
}

func copyProcessInfo(value sandbox.ProcessInfo) sandbox.ProcessInfo {
	copied := value
	if value.Result != nil {
		result := *value.Result
		if value.Result.ExitCode != nil {
			exitCode := *value.Result.ExitCode
			result.ExitCode = &exitCode
		}
		if value.Result.Signal != nil {
			signal := *value.Result.Signal
			result.Signal = &signal
		}
		copied.Result = &result
	}
	return copied
}

func copyVolumeInfo(value sandbox.VolumeInfo) sandbox.VolumeInfo {
	copied := value
	if value.Attachment != nil {
		attachment := *value.Attachment
		copied.Attachment = &attachment
	}
	return copied
}
