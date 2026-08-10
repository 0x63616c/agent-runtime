//go:build integration

package runtimeorchestration_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimeorchestration"
	"github.com/0x63616c/agent-runtime/internal/temporalpayloadruntime"
	"github.com/0x63616c/agent-runtime/temporalpayload"
	"go.temporal.io/sdk/client"
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
	codec, err := temporalpayload.NewCodec(temporalpayload.NewMemoryBlobStore(), temporalpayload.WithBlobPrefix("runtime-orchestration-integration"))
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
	command := runtimeorchestration.Command{SessionID: "sess_1234567890ABCDEF", Kind: runtimeorchestration.CommandInputAccepted, Sequence: 1}
	if err := owned.SignalWorkflow(ctx, "session-orchestration-integration", run.GetRunID(), runtimeorchestration.SessionCommandSignal, command); err != nil {
		t.Fatalf("signal durable command: %v", err)
	}
	if !dispatcher.wait(ctx, command) {
		t.Fatal("state-backed activity did not receive the durable command")
	}
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
