// Package sandboxbootprobehostprocess composes the private v2 host recovery
// boundary: durable intent always precedes launch-started authority.
package sandboxbootprobehostprocess

import (
	"context"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobejournal"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobev2"
	"github.com/cockroachdb/errors"
)

// Control records the authoritative launch-started transition for one exact
// persisted session snapshot.
type Control interface {
	LaunchStarted(context.Context, firecrackerbootprobev2.Snapshot) (firecrackerbootprobev2.Snapshot, error)
}

// StageAndRecordLaunchStarted fsyncs intent before asking control to cross the
// irreversible transition. A restart repeats only the exact journaled intent.
func StageAndRecordLaunchStarted(ctx context.Context, journal *firecrackerbootprobejournal.Journal, control Control, snapshot firecrackerbootprobev2.Snapshot) (firecrackerbootprobev2.Snapshot, error) {
	if ctx == nil || journal == nil || control == nil || snapshot.Session.Lifecycle.Phase != firecrackerbootprobev2.LifecycleLaunchAuthorized {
		return firecrackerbootprobev2.Snapshot{}, errors.New("stage v2 boot-probe launch: exact journal, control and authorization required")
	}
	if err := journal.StageLaunchIntent(snapshot.Session); err != nil {
		return firecrackerbootprobev2.Snapshot{}, err
	}
	return control.LaunchStarted(ctx, snapshot)
}

// RecoverLaunchStarted resumes the same durable intent after host restart;
// it never reconstructs a delivery or asks for a replacement session.
func RecoverLaunchStarted(ctx context.Context, journal *firecrackerbootprobejournal.Journal, control Control, snapshot firecrackerbootprobev2.Snapshot) (firecrackerbootprobev2.Snapshot, error) {
	intent, ok := journal.LaunchIntent()
	if !ok {
		return firecrackerbootprobev2.Snapshot{}, errors.New("recover v2 boot-probe launch: durable intent is absent")
	}
	wire, _ := firecrackerbootprobev2.EncodeSession(intent)
	if string(wire) != string(snapshot.Wire) {
		return firecrackerbootprobev2.Snapshot{}, errors.New("recover v2 boot-probe launch: persisted session differs from intent")
	}
	return StageAndRecordLaunchStarted(ctx, journal, control, snapshot)
}
