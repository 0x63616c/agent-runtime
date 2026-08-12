package architecture_test

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("public Agent Runtime Go contract", func() {
	It("lets an external common-session consumer typecheck its cursor and cancellation flow", func() {
		root, err := filepath.Abs(filepath.Join("..", ".."))
		Expect(err).NotTo(HaveOccurred())
		consumer := GinkgoT().TempDir()
		writeConsumerFile(consumer, "go.mod", "module example.com/common-session-consumer\n\ngo 1.26\n\nrequire github.com/0x63616c/agent-runtime v0.0.0\n\nreplace github.com/0x63616c/agent-runtime => "+root+"\n")
		writeConsumerFile(consumer, "main_test.go", commonSessionConsumerSource())
		for _, arguments := range [][]string{{"mod", "tidy"}, {"test", "."}} {
			command := exec.Command("go", arguments...)
			command.Dir = consumer
			output, commandErr := command.CombinedOutput()
			Expect(commandErr).NotTo(HaveOccurred(), string(output))
		}
	})

	It("rejects direct implementation imports from an external example fixture", func() {
		fixture := filepath.Join("testdata", "example_forbidden_import.go")
		imports, err := forbiddenExampleImports(fixture)
		Expect(err).NotTo(HaveOccurred())
		Expect(imports).To(ConsistOf(
			"github.com/0x63616c/agent-runtime/internal/runtimeapi",
			"github.com/0x63616c/agent-runtime/internal/sandboxcontrol",
			"github.com/0x63616c/agent-runtime/temporalpayload",
			"github.com/0x63616c/agent-runtime/tests/testroute",
			"github.com/minio/minio-go/v7",
			"go.temporal.io/sdk/client",
		))
		consumer := GinkgoT().TempDir()
		writeConsumerFile(consumer, "main_test.go", commonSessionConsumerSource())
		imports, err = forbiddenExampleImports(filepath.Join(consumer, "main_test.go"))
		Expect(err).NotTo(HaveOccurred())
		Expect(imports).To(BeEmpty())
	})

	It("lets a release consumer compile the public SDK and OpenAPI-backed additive capabilities without workspace state", func() {
		root, err := filepath.Abs(filepath.Join("..", ".."))
		Expect(err).NotTo(HaveOccurred())
		consumer := GinkgoT().TempDir()
		writeConsumerFile(consumer, "go.mod", "module example.com/runtime-consumer\n\ngo 1.26\n\nrequire github.com/0x63616c/agent-runtime v0.0.0\n\nreplace github.com/0x63616c/agent-runtime => "+root+"\n")
		writeConsumerFile(consumer, "main_test.go", releaseConsumerSource())
		for _, arguments := range [][]string{{"mod", "tidy"}, {"test", "."}} {
			command := exec.Command("go", arguments...)
			command.Dir = consumer
			command.Env = append(os.Environ(), "GOWORK=off")
			output, commandErr := command.CombinedOutput()
			Expect(commandErr).NotTo(HaveOccurred(), string(output))
		}
	})

	It("has no Temporal or implementation SDK in its transitive import graph", func() {
		command := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./sdk/go")
		command.Dir = filepath.Join("..", "..")
		output, err := command.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(output))
		imports := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, imported := range imports {
			for _, forbidden := range []string{
				"go.temporal.io/",
				"github.com/0x63616c/agent-runtime/internal/",
				"github.com/0x63616c/agent-runtime/sandbox",
				"github.com/0x63616c/agent-runtime/temporalpayload",
				"github.com/jackc/pgx/",
				"github.com/minio/",
			} {
				Expect(imported).NotTo(HavePrefix(forbidden), imported)
			}
		}
	})
})

func commonSessionConsumerSource() string {
	return `package consumer

import (
    "context"
    "fmt"
    "testing"

    agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

type sessionClient interface {
    CreateSession(context.Context, agentruntime.CreateSessionRequest) (agentruntime.Session, error)
    SendInput(context.Context, agentruntime.SendInputRequest) (agentruntime.SendInputResult, error)
    Events(context.Context, agentruntime.SessionID, agentruntime.Cursor, int) (agentruntime.EventPage, error)
    InspectTurn(context.Context, agentruntime.SessionID, agentruntime.TurnID) (agentruntime.Turn, error)
    CancelTurn(context.Context, agentruntime.CancelTurnRequest) (agentruntime.Turn, error)
    CloseSession(context.Context, agentruntime.CloseSessionRequest) (agentruntime.Session, error)
}

var _ sessionClient = (agentruntime.RuntimeClient)(nil)

var (
    revisionID = agentruntime.AgentRevisionID("arev_1234567890ABCDEF")
    sessionID = agentruntime.SessionID("sess_1234567890ABCDEF")
    inputID = agentruntime.InputID("inpt_1234567890ABCDEF")
    turnID = agentruntime.TurnID("turn_1234567890ABCDEF")
    firstCursor = agentruntime.Cursor("cur_1234567890ABCDEF")
    secondCursor = agentruntime.Cursor("cur_ABCDEF1234567890")
)

type fakeClient struct {
    sent *agentruntime.SendInputResult
    cancelled bool
}

func (client *fakeClient) CreateSession(_ context.Context, request agentruntime.CreateSessionRequest) (agentruntime.Session, error) {
    if request.IdempotencyKey != "create-session" || request.AgentRevision != revisionID {
        return agentruntime.Session{}, fmt.Errorf("unexpected create request")
    }
    return agentruntime.Session{ID: sessionID, AgentRevision: revisionID, State: agentruntime.SessionOpen}, nil
}

func (client *fakeClient) SendInput(_ context.Context, request agentruntime.SendInputRequest) (agentruntime.SendInputResult, error) {
    if request.SessionID != sessionID || request.IdempotencyKey != "send-input" || len(request.Parts) != 1 || request.Parts[0].Text != "hello" {
        return agentruntime.SendInputResult{}, fmt.Errorf("unexpected input request")
    }
    if client.sent == nil {
        client.sent = &agentruntime.SendInputResult{Input: agentruntime.Input{ID: inputID}, Turn: agentruntime.Turn{ID: turnID, InputID: inputID, Position: 1, State: agentruntime.TurnRunning}}
    }
    return *client.sent, nil
}

func (client *fakeClient) Events(_ context.Context, requestedSession agentruntime.SessionID, after agentruntime.Cursor, limit int) (agentruntime.EventPage, error) {
    if requestedSession != sessionID || limit != 1 {
        return agentruntime.EventPage{}, fmt.Errorf("unexpected event request")
    }
    switch after {
    case "":
        return agentruntime.EventPage{Events: []agentruntime.Event{{Cursor: firstCursor, Sequence: 1, Kind: agentruntime.EventInputAccepted, SessionID: sessionID, InputID: inputID}}, NextCursor: firstCursor}, nil
    case firstCursor:
        return agentruntime.EventPage{Events: []agentruntime.Event{{Cursor: secondCursor, Sequence: 2, Kind: agentruntime.EventTurnStarted, SessionID: sessionID, TurnID: turnID}}, NextCursor: secondCursor}, nil
    default:
        return agentruntime.EventPage{}, fmt.Errorf("unexpected cursor")
    }
}

func (client *fakeClient) InspectTurn(_ context.Context, requestedSession agentruntime.SessionID, requestedTurn agentruntime.TurnID) (agentruntime.Turn, error) {
    if requestedSession != sessionID || requestedTurn != turnID {
        return agentruntime.Turn{}, fmt.Errorf("unexpected turn inspection")
    }
    return agentruntime.Turn{ID: turnID, InputID: inputID, Position: 1, State: agentruntime.TurnRunning}, nil
}

func (client *fakeClient) CancelTurn(_ context.Context, request agentruntime.CancelTurnRequest) (agentruntime.Turn, error) {
    if request.SessionID != sessionID || request.TurnID != turnID || request.IdempotencyKey != "cancel-turn" {
        return agentruntime.Turn{}, fmt.Errorf("unexpected cancellation")
    }
    client.cancelled = true
    return agentruntime.Turn{ID: turnID, InputID: inputID, Position: 1, State: agentruntime.TurnCancelled}, nil
}

func (client *fakeClient) CloseSession(_ context.Context, request agentruntime.CloseSessionRequest) (agentruntime.Session, error) {
    if request.SessionID != sessionID || request.IdempotencyKey != "close-session" || !client.cancelled {
        return agentruntime.Session{}, fmt.Errorf("unexpected close")
    }
    return agentruntime.Session{ID: sessionID, AgentRevision: revisionID, State: agentruntime.SessionCompleted}, nil
}

func runCommonSession(ctx context.Context, client sessionClient) error {
    session, err := client.CreateSession(ctx, agentruntime.CreateSessionRequest{IdempotencyKey: "create-session", AgentRevision: revisionID})
    if err != nil {
        return err
    }
    request := agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "send-input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "hello"}}}
    firstSend, err := client.SendInput(ctx, request)
    if err != nil {
        return err
    }
    replayedSend, err := client.SendInput(ctx, request)
    if err != nil || replayedSend.Input.ID != firstSend.Input.ID || replayedSend.Turn.ID != firstSend.Turn.ID {
        return fmt.Errorf("input idempotency replay failed")
    }
    firstPage, err := client.Events(ctx, session.ID, "", 1)
    if err != nil || firstPage.NextCursor != firstCursor {
        return fmt.Errorf("initial cursor page failed")
    }
    secondPage, err := client.Events(ctx, session.ID, firstPage.NextCursor, 1)
    if err != nil || secondPage.NextCursor != secondCursor {
        return fmt.Errorf("cursor resume failed")
    }
    inspected, err := client.InspectTurn(ctx, session.ID, firstSend.Turn.ID)
    if err != nil || inspected.State != agentruntime.TurnRunning {
        return fmt.Errorf("turn inspection failed")
    }
    cancelled, err := client.CancelTurn(ctx, agentruntime.CancelTurnRequest{SessionID: session.ID, TurnID: inspected.ID, IdempotencyKey: "cancel-turn"})
    if err != nil || cancelled.State != agentruntime.TurnCancelled {
        return fmt.Errorf("turn cancellation failed")
    }
    closed, err := client.CloseSession(ctx, agentruntime.CloseSessionRequest{SessionID: session.ID, IdempotencyKey: "close-session"})
    if err != nil || closed.State != agentruntime.SessionCompleted {
        return fmt.Errorf("session close failed")
    }
    return nil
}

func TestCommonSessionConsumer(t *testing.T) {
    if err := runCommonSession(context.Background(), &fakeClient{}); err != nil {
        t.Fatal(err)
    }
}
`
}

func releaseConsumerSource() string {
	return `package consumer

import (
    "context"
    "io"
    "testing"

    agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

var (
    _ agentruntime.RuntimeClient = (*agentruntime.Client)(nil)
    _ agentruntime.ArtifactStreamer = (*agentruntime.Client)(nil)
    _ agentruntime.SessionCanceller = (*agentruntime.Client)(nil)
    _ agentruntime.ToolCallInspector = (*agentruntime.Client)(nil)
)

func TestPublicRuntimeContract(t *testing.T) {
    sessionID, err := agentruntime.ParseSessionID("sess_1234567890ABCDEF")
    if err != nil {
        t.Fatalf("parse Session ID: %v", err)
    }
    turnID, err := agentruntime.ParseTurnID("turn_1234567890ABCDEF")
    if err != nil {
        t.Fatalf("parse Turn ID: %v", err)
    }
    artifactID, err := agentruntime.ParseArtifactID("art_1234567890ABCDEF")
    if err != nil {
        t.Fatalf("parse Artifact ID: %v", err)
    }
    request := agentruntime.SendInputRequest{
        SessionID: sessionID,
        IdempotencyKey: "consumer-input-1",
        Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "hello"}},
    }
    if request.SessionID != sessionID {
        t.Fatal("public request did not retain typed Session ID")
    }
    inspectAdditiveContract(context.Background(), artifactID, sessionID, turnID)
}

func inspectAdditiveContract(ctx context.Context, artifactID agentruntime.ArtifactID, sessionID agentruntime.SessionID, turnID agentruntime.TurnID) {
    var artifacts agentruntime.ArtifactStreamer
    var sessions agentruntime.SessionCanceller
    var tools agentruntime.ToolCallInspector
    _ = artifacts
    _ = sessions
    _ = tools
    cancel := agentruntime.CancelSessionRequest{SessionID: sessionID, IdempotencyKey: "consumer-cancel-session-1"}
    _ = cancel
    _ = agentruntime.EventSessionCancelled
    _ = agentruntime.EventSessionFailed
    page := agentruntime.ToolCallPage{}
    _ = page.Clone()
    var stream agentruntime.ArtifactStream
    _ = io.Reader(stream.Body)
    _ = ctx
    _ = artifactID
    _ = sessionID
    _ = turnID
}
`
}

func forbiddenExampleImports(path string) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	var imports []string
	for _, imported := range file.Imports {
		value := strings.Trim(imported.Path.Value, `"`)
		if strings.HasPrefix(value, "github.com/0x63616c/agent-runtime/internal/") ||
			strings.HasPrefix(value, "github.com/0x63616c/agent-runtime/temporalpayload") ||
			strings.HasPrefix(value, "github.com/0x63616c/agent-runtime/tests/") ||
			strings.HasPrefix(value, "github.com/minio/") ||
			strings.HasPrefix(value, "go.temporal.io/") {
			imports = append(imports, value)
		}
	}
	sort.Strings(imports)
	return imports, nil
}
