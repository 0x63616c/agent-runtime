//go:build integration

package runtimeorchestration_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimeorchestration"
	"github.com/0x63616c/agent-runtime/internal/temporalpayloadruntime"
	"github.com/0x63616c/agent-runtime/temporalpayload"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/log"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
)

func TestSessionWorkflowRunsThroughTheOwnedFactoryAgainstTemporal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	server, err := testsuite.StartDevServer(ctx, testsuite.DevServerOptions{})
	if err != nil {
		t.Fatalf("start Temporal development server: %v", err)
	}
	defer func() { _ = server.Stop() }()
	codec, err := temporalpayload.NewCodec(&retainedReplayBlobStore{values: map[temporalpayload.BlobKey][]byte{}}, temporalpayload.WithBlobPrefix("runtime-orchestration-integration"))
	if err != nil {
		t.Fatal(err)
	}
	factory, err := temporalpayloadruntime.NewFactory(codec)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := factory.NewClient(ctx, client.Options{HostPort: server.FrontendHostPort()})
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Close()
	workerRuntime, err := factory.NewWorker(owned, "runtime-orchestration-integration", worker.Options{})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &integrationDispatcher{}
	activities, err := runtimeorchestration.NewActivities(dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtimeorchestration.Register(workerRuntime, activities); err != nil {
		t.Fatal(err)
	}
	if err := workerRuntime.Start(); err != nil {
		t.Fatal(err)
	}
	defer workerRuntime.Stop()
	run, err := owned.ExecuteWorkflow(ctx, client.StartWorkflowOptions{ID: "session-orchestration-integration", TaskQueue: "runtime-orchestration-integration"}, runtimeorchestration.SessionWorkflow, runtimeorchestration.WorkflowInput{SessionID: "sess_1234567890ABCDEF", ContinueAfter: 100})
	if err != nil {
		t.Fatalf("start Session workflow: %v", err)
	}
	command := runtimeorchestration.Command{Tenant: "tenant-a", OutboxID: "outbox-1", SessionID: "sess_1234567890ABCDEF", Kind: runtimeorchestration.CommandInputAccepted, Sequence: 1}
	if err := owned.SignalWorkflow(ctx, "session-orchestration-integration", run.GetRunID(), runtimeorchestration.SessionCommandSignal, command); err != nil {
		t.Fatalf("signal durable command: %v", err)
	}
	if !dispatcher.wait(ctx, command) {
		t.Fatal("state-backed activity did not receive the durable command")
	}
	history, err := owned.WorkflowHistory(ctx, "session-orchestration-integration", run.GetRunID())
	if err != nil || len(history.Events) == 0 {
		t.Fatalf("retain actual Temporal history = %#v, %v", history, err)
	}
	replayer, err := factory.NewWorkflowReplayer()
	if err != nil {
		t.Fatal(err)
	}
	replayer.RegisterWorkflow(runtimeorchestration.SessionWorkflow)
	if err := replayer.ReplayWorkflowHistory(log.NewStructuredLogger(slog.New(slog.NewTextHandler(io.Discard, nil))), history); err != nil {
		t.Fatalf("replay retained actual Temporal Session history: %v", err)
	}
}

// retainedReplayBlobStore is a test-only compatibility corpus seam. Production
// worker composition always uses the dedicated S3 payload capability; it has
// no MemoryBlobStore fallback.
type retainedReplayBlobStore struct {
	values map[temporalpayload.BlobKey][]byte
}

func (store *retainedReplayBlobStore) Put(_ context.Context, key temporalpayload.BlobKey, value []byte) error {
	if current, found := store.values[key]; found && !bytes.Equal(current, value) {
		return temporalpayload.ErrBlobIntegrity
	}
	store.values[key] = bytes.Clone(value)
	return nil
}

func (store *retainedReplayBlobStore) Get(_ context.Context, key temporalpayload.BlobKey, maximum int) ([]byte, error) {
	value, found := store.values[key]
	if !found {
		return nil, temporalpayload.ErrBlobNotFound
	}
	if len(value) > maximum {
		return nil, temporalpayload.ErrBlobTooLarge
	}
	return bytes.Clone(value), nil
}

type integrationDispatcher struct {
	mu       sync.Mutex
	commands []runtimeorchestration.Command
	notify   chan struct{}
}

func (dispatcher *integrationDispatcher) Dispatch(_ context.Context, command runtimeorchestration.Command) error {
	dispatcher.mu.Lock()
	dispatcher.commands = append(dispatcher.commands, command)
	if dispatcher.notify == nil {
		dispatcher.notify = make(chan struct{})
	}
	close(dispatcher.notify)
	dispatcher.mu.Unlock()
	return nil
}

func (dispatcher *integrationDispatcher) wait(ctx context.Context, want runtimeorchestration.Command) bool {
	for {
		dispatcher.mu.Lock()
		for _, command := range dispatcher.commands {
			if command == want {
				dispatcher.mu.Unlock()
				return true
			}
		}
		notify := dispatcher.notify
		if notify == nil {
			notify = make(chan struct{})
			dispatcher.notify = notify
		}
		dispatcher.mu.Unlock()
		select {
		case <-notify:
		case <-ctx.Done():
			return false
		}
	}
}
