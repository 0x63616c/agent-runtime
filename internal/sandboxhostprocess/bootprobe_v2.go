package sandboxhostprocess

import (
	"context"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobejournal"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobev2"
	"github.com/0x63616c/agent-runtime/internal/sandboxbootprobehostprocess"
	"github.com/cockroachdb/errors"
	"net/http"
)

// RunBootProbeV2Once is the private host-process v2 flow. It never invokes the
// v1 pull/receipt protocol: control authorizes a v2 session, the host fsyncs
// its intent, and only then does control record launch-started.
func RunBootProbeV2Once(ctx context.Context, client *http.Client, origin, principal, operationID, instanceID, journalPath string) (firecrackerbootprobev2.Snapshot, error) {
	snapshot, err := sandboxbootprobehostprocess.Prepare(ctx, client, origin, principal, operationID, instanceID)
	if err != nil {
		return firecrackerbootprobev2.Snapshot{}, err
	}
	journal, err := firecrackerbootprobejournal.Open(journalPath)
	if err != nil {
		return firecrackerbootprobev2.Snapshot{}, err
	}
	defer journal.Close()
	if err := journal.StageLaunchSnapshot(snapshot); err != nil {
		return firecrackerbootprobev2.Snapshot{}, err
	}
	return sandboxbootprobehostprocess.LaunchStarted(ctx, client, origin, snapshot)
}

// RecoverBootProbeV2 resumes only the fsynced exact intent and refuses an
// absent or altered host-instance session rather than minting another launch.
func RecoverBootProbeV2(ctx context.Context, client *http.Client, origin, journalPath string) (firecrackerbootprobev2.Snapshot, error) {
	journal, err := firecrackerbootprobejournal.Open(journalPath)
	if err != nil {
		return firecrackerbootprobev2.Snapshot{}, err
	}
	defer journal.Close()
	snapshot, ok := journal.LaunchSnapshot()
	if !ok {
		return firecrackerbootprobev2.Snapshot{}, errors.New("recover sandbox host v2 boot probe: durable intent absent")
	}
	return sandboxbootprobehostprocess.LaunchStarted(ctx, client, origin, snapshot)
}
