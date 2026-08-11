package runtimeorchestration

import (
	"context"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/runtimestate"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestPublisherRoutesEveryTerminalApprovalEvent(t *testing.T) {
	t.Parallel()
	published := &approvalLifecyclePublisher{}
	publisher := &Publisher{publisher: published}
	for _, expected := range []struct {
		event   agentruntime.EventKind
		command CommandKind
	}{
		{event: agentruntime.EventApprovalResolved, command: CommandApprovalResolved},
		{event: agentruntime.EventApprovalExpired, command: CommandApprovalExpired},
		{event: agentruntime.EventApprovalCancelled, command: CommandApprovalCancelled},
	} {
		record := runtimestate.OutboxRecord{Tenant: "tenant-a", OutboxID: runtimestate.OutboxID("outbox_1234567890ABCDEF"), SessionID: "sess_1234567890ABCDEF", EventKind: expected.event, EventSequence: 7}
		if err := publisher.route(context.Background(), record); err != nil {
			t.Fatalf("route %q: %v", expected.event, err)
		}
		if got := published.commands[len(published.commands)-1]; got.Kind != expected.command || got.Sequence != record.EventSequence || !matchesCommand(record.EventKind, got.Kind) || !knownCommandKind(got.Kind) {
			t.Fatalf("route %q = %#v, want command %q", expected.event, got, expected.command)
		}
	}
}

type approvalLifecyclePublisher struct{ commands []Command }

func (publisher *approvalLifecyclePublisher) StartSession(context.Context, SessionStart) error {
	return nil
}

func (publisher *approvalLifecyclePublisher) SignalSession(_ context.Context, _ SessionStart, command Command) error {
	publisher.commands = append(publisher.commands, command)
	return nil
}
