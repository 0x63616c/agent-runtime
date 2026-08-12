//go:build integration

package durablechat_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	durablechat "github.com/0x63616c/agent-runtime/examples/durable-chat"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestDurableChatReconnectsAndCancelsThroughRestartedDurableAPIProcess(t *testing.T) {
	if os.Getenv("AR_RUNTIME_POSTGRES_DSN") == "" || os.Getenv("AR_RUNTIME_MINIO_ENDPOINT") == "" || os.Getenv("AR_RUNTIME_MINIO_ACCESS_KEY") == "" || os.Getenv("AR_RUNTIME_MINIO_SECRET_KEY") == "" || os.Getenv("AR_RUNTIME_MINIO_BUCKET") == "" {
		t.Skip("AR_RUNTIME_POSTGRES_DSN and MinIO integration environment are required")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	binary := filepath.Join(temporary, "agent-runtime-api")
	build := exec.Command("go", "build", "-o", binary, "./cmd/agent-runtime-api")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build API role: %v: %s", err, output)
	}
	configPath := filepath.Join(temporary, "runtime-api.json")
	config := `{"version":1,"listen_address":"127.0.0.1:0","storage":{"mode":"postgres","database_dsn_environment":"AR_RUNTIME_POSTGRES_DSN","content":{"endpoint":"` + os.Getenv("AR_RUNTIME_MINIO_ENDPOINT") + `","access_key_environment":"AR_RUNTIME_MINIO_ACCESS_KEY","secret_key_environment":"AR_RUNTIME_MINIO_SECRET_KEY","bucket":"` + os.Getenv("AR_RUNTIME_MINIO_BUCKET") + `"}},"model_profiles":["balanced"],"max_request_bytes":4194304,"principals":[{"tenant":"durable-chat-e2e","principal":"admin","admin":true,"bearer_token_environment":"DURABLE_CHAT_ADMIN_TOKEN"},{"tenant":"durable-chat-e2e","principal":"user","admin":false,"bearer_token_environment":"DURABLE_CHAT_USER_TOKEN"}]}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	first := startAPI(t, ctx, binary, configPath)
	admin := newIntegrationClient(t, "http://"+first.address, "durable-chat-admin-token-000000", &integrationIDs{})
	user := newIntegrationClient(t, "http://"+first.address, "durable-chat-user-token-000000", &integrationIDs{})
	agent, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "durable-chat-e2e-agent", Name: "durable-chat", ModelProfile: "balanced", Instructions: "durable public-contract probe"})
	if err != nil {
		t.Fatalf("create Agent: %v", err)
	}
	app, err := durablechat.NewApp(user, durablechat.RandomKeys{})
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.NewSession(ctx, agent.RevisionID)
	if err != nil {
		t.Fatalf("create Session through example: %v", err)
	}
	_, err = app.Send(ctx, session.ID, "first durable message")
	if err != nil {
		t.Fatalf("queue first Input: %v", err)
	}
	secondTurn, err := app.Send(ctx, session.ID, "second queued durable message")
	if err != nil {
		t.Fatalf("queue second Input: %v", err)
	}
	if secondTurn.Turn.State != agentruntime.TurnQueued {
		t.Fatalf("second Turn state = %s, want queued", secondTurn.Turn.State)
	}
	events, err := app.Reconnect(ctx, session.ID, "")
	if err != nil || events.NextCursor == "" {
		t.Fatalf("read pre-restart events = %#v, %v", events, err)
	}
	if err := first.stop(); err != nil {
		t.Fatalf("stop first API role: %v", err)
	}
	second := startAPI(t, ctx, binary, configPath)
	defer func() { _ = second.stop() }()
	restartedClient := newIntegrationClient(t, "http://"+second.address, "durable-chat-user-token-000000", &integrationIDs{})
	restartedApp, err := durablechat.NewApp(restartedClient, durablechat.RandomKeys{})
	if err != nil {
		t.Fatal(err)
	}
	view, err := restartedApp.Resume(ctx, session.ID)
	if err != nil || view.Session.ID != session.ID || view.QueuedTurnCount == 0 {
		t.Fatalf("resume after API restart = %#v, %v", view, err)
	}
	resumedEvents, err := restartedApp.Reconnect(ctx, session.ID, events.NextCursor)
	if err != nil {
		t.Fatalf("reconnect after API restart: %v", err)
	}
	if resumedEvents.Gap != nil {
		t.Fatalf("reconnect after API restart reported unexpected gap: %#v", resumedEvents.Gap)
	}
	cancelled, err := restartedApp.Cancel(ctx, session.ID, secondTurn.Turn.ID)
	if err != nil || cancelled.State != agentruntime.TurnCancelled {
		t.Fatalf("cancel queued Turn after restart = %#v, %v", cancelled, err)
	}
}

func TestDurableChatTerminalAndWebBinariesUseOnlyPublicPathAcrossRestart(t *testing.T) {
	if os.Getenv("AR_RUNTIME_POSTGRES_DSN") == "" || os.Getenv("AR_RUNTIME_MINIO_ENDPOINT") == "" || os.Getenv("AR_RUNTIME_MINIO_ACCESS_KEY") == "" || os.Getenv("AR_RUNTIME_MINIO_SECRET_KEY") == "" || os.Getenv("AR_RUNTIME_MINIO_BUCKET") == "" {
		t.Skip("AR_RUNTIME_POSTGRES_DSN and MinIO integration environment are required")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	apiBinary := filepath.Join(temporary, "agent-runtime-api")
	chatBinary := filepath.Join(temporary, "durable-chat")
	for _, target := range []struct{ binary, packagePath string }{{apiBinary, "./cmd/agent-runtime-api"}, {chatBinary, "./examples/durable-chat/cmd/durable-chat"}} {
		command := exec.Command("go", "build", "-o", target.binary, target.packagePath)
		command.Dir = root
		if output, buildErr := command.CombinedOutput(); buildErr != nil {
			t.Fatalf("build %s: %v: %s", target.packagePath, buildErr, output)
		}
	}
	configPath := writeDurableAPIConfig(t, temporary)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	first := startAPI(t, ctx, apiBinary, configPath)
	admin := newIntegrationClient(t, "http://"+first.address, "durable-chat-admin-token-000000", &integrationIDs{})
	agent, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "durable-chat-ui-agent", Name: "durable-chat-ui", ModelProfile: "balanced", Instructions: "public UI probe"})
	if err != nil {
		t.Fatalf("create Agent: %v", err)
	}
	terminalEnv := append(os.Environ(), "AGENT_RUNTIME_DEVELOPER_TOKEN=durable-chat-user-token-000000")
	created := runTerminalBinary(t, ctx, chatBinary, "http://"+first.address, terminalEnv, "new "+agent.RevisionID.String()+"\nquit\n")
	sessionID := findID(t, `session (sess_[A-Za-z0-9]+)`, created)
	queued := runTerminalBinary(t, ctx, chatBinary, "http://"+first.address, terminalEnv, "send "+sessionID+" first browser-safe message\nsend "+sessionID+" queued browser-safe message\nevents "+sessionID+"\nquit\n")
	turnID := findLastID(t, `queued turn (turn_[A-Za-z0-9]+)`, queued)
	if err := first.stop(); err != nil {
		t.Fatalf("stop first API role: %v", err)
	}
	second := startAPI(t, ctx, apiBinary, configPath)
	defer func() { _ = second.stop() }()
	web := startWebBinary(t, ctx, chatBinary, "http://"+second.address, terminalEnv)
	defer func() { _ = web.command.Process.Kill(); _ = web.command.Wait() }()
	page, err := http.Get(web.address + "/?session=" + sessionID)
	if err != nil {
		t.Fatalf("get Durable Chat web page: %v", err)
	}
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(page.Body)
	_ = page.Body.Close()
	if page.StatusCode != http.StatusOK || !bytes.Contains(body.Bytes(), []byte("not a subscription canary")) || !bytes.Contains(body.Bytes(), []byte(sessionID)) {
		t.Fatalf("web page = %d %q", page.StatusCode, body.String())
	}
	csrf := findID(t, `name="csrf" value="([A-Fa-f0-9]+)"`, body.String())
	cancelRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, web.address+"/sessions/"+sessionID+"/cancel", strings.NewReader(url.Values{"csrf": {csrf}, "turn": {turnID}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	cancelRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cancelRequest.Header.Set("Origin", web.address)
	response, err := http.DefaultClient.Do(cancelRequest)
	if err != nil {
		t.Fatalf("cancel through web binary: %v", err)
	}
	_ = response.Body.Close()
	if response.Request.Header.Get("Authorization") != "" {
		t.Fatal("browser request unexpectedly held runtime bearer")
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("cancel through web redirect final status = %d", response.StatusCode)
	}
	resumed := runTerminalBinary(t, ctx, chatBinary, "http://"+second.address, terminalEnv, "resume "+sessionID+"\nquit\n")
	if !strings.Contains(resumed, "state=") {
		t.Fatalf("resume through terminal binary = %q", resumed)
	}
}

func writeDurableAPIConfig(t *testing.T, directory string) string {
	t.Helper()
	path := filepath.Join(directory, "runtime-api.json")
	config := `{"version":1,"listen_address":"127.0.0.1:0","storage":{"mode":"postgres","database_dsn_environment":"AR_RUNTIME_POSTGRES_DSN","content":{"endpoint":"` + os.Getenv("AR_RUNTIME_MINIO_ENDPOINT") + `","access_key_environment":"AR_RUNTIME_MINIO_ACCESS_KEY","secret_key_environment":"AR_RUNTIME_MINIO_SECRET_KEY","bucket":"` + os.Getenv("AR_RUNTIME_MINIO_BUCKET") + `"}},"model_profiles":["balanced"],"max_request_bytes":4194304,"principals":[{"tenant":"durable-chat-e2e","principal":"admin","admin":true,"bearer_token_environment":"DURABLE_CHAT_ADMIN_TOKEN"},{"tenant":"durable-chat-e2e","principal":"user","admin":false,"bearer_token_environment":"DURABLE_CHAT_USER_TOKEN"}]}`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runTerminalBinary(t *testing.T, ctx context.Context, binary, apiURL string, environment []string, script string) string {
	t.Helper()
	command := exec.CommandContext(ctx, binary, "--mode=terminal", "--runtime-url="+apiURL)
	command.Env = environment
	command.Stdin = strings.NewReader(script)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run Durable Chat terminal: %v: %s", err, output)
	}
	return string(output)
}

type webProcess struct {
	command *exec.Cmd
	address string
}

func startWebBinary(t *testing.T, ctx context.Context, binary, apiURL string, environment []string) webProcess {
	t.Helper()
	command := exec.CommandContext(ctx, binary, "--mode=web", "--runtime-url="+apiURL, "--listen=127.0.0.1:0")
	command.Env = environment
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatalf("read web readiness: %v", scanner.Err())
	}
	match := regexp.MustCompile("ready at (http://127\\.0\\.0\\.1:[0-9]+)").FindStringSubmatch(scanner.Text())
	if len(match) != 2 {
		t.Fatalf("web readiness = %q", scanner.Text())
	}
	return webProcess{command: command, address: match[1]}
}

func findID(t *testing.T, expression, output string) string {
	t.Helper()
	match := regexp.MustCompile(expression).FindStringSubmatch(output)
	if len(match) != 2 {
		t.Fatalf("find %q in %q", expression, output)
	}
	return match[1]
}
func findLastID(t *testing.T, expression, output string) string {
	t.Helper()
	matches := regexp.MustCompile(expression).FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		t.Fatalf("find %q in %q", expression, output)
	}
	return matches[len(matches)-1][1]
}

type apiProcess struct {
	command *exec.Cmd
	address string
	stderr  bytes.Buffer
}

func startAPI(t *testing.T, ctx context.Context, binary, configPath string) *apiProcess {
	t.Helper()
	command := exec.CommandContext(ctx, binary, "--config", configPath)
	command.Env = append(os.Environ(), "DURABLE_CHAT_ADMIN_TOKEN=durable-chat-admin-token-000000", "DURABLE_CHAT_USER_TOKEN=durable-chat-user-token-000000")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	process := &apiProcess{command: command}
	command.Stderr = &process.stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start API role: %v", err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatalf("read API readiness: %v: %s", scanner.Err(), process.stderr.String())
	}
	var record struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal(scanner.Bytes(), &record); err != nil || record.Address == "" {
		t.Fatalf("decode API readiness %q: %v", scanner.Text(), err)
	}
	process.address = record.Address
	return process
}

func (process *apiProcess) stop() error {
	if process == nil || process.command == nil || process.command.Process == nil {
		return nil
	}
	if err := process.command.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	return process.command.Wait()
}

type integrationIDs struct {
	mutex sync.Mutex
	next  uint64
}

func (source *integrationIDs) NextRequestID() (agentruntime.RequestID, error) {
	source.mutex.Lock()
	defer source.mutex.Unlock()
	source.next++
	return agentruntime.ParseRequestID(fmt.Sprintf("req_%016d", source.next))
}
func newIntegrationClient(t *testing.T, baseURL, token string, ids agentruntime.RequestIDSource) *agentruntime.Client {
	t.Helper()
	credential, err := agentruntime.NewStaticBearerCredential(token)
	if err != nil {
		t.Fatal(err)
	}
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: baseURL, HTTPClient: http.DefaultClient, Credentials: credential, RequestIDs: ids})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
