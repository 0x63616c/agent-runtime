//go:build integration

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestStandaloneBinaryServesThePublicSDKFromStrictConfiguration(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("repository root: %v", err)
	}
	temporary := t.TempDir()
	binary := filepath.Join(temporary, "agent-runtime-api")
	build := exec.Command("go", "build", "-o", binary, "./cmd/agent-runtime-api")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build standalone role: %v: %s", err, output)
	}
	configPath := filepath.Join(temporary, "runtime-api.json")
	config := `{"version":1,"listen_address":"127.0.0.1:0","storage":{"mode":"memory-unsafe"},"model_profiles":["balanced"],"max_request_bytes":4194304,"principals":[{"tenant":"e2e","principal":"admin","admin":true,"bearer_token_environment":"E2E_ADMIN_TOKEN"},{"tenant":"e2e","principal":"user","admin":false,"bearer_token_environment":"E2E_USER_TOKEN"}]}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "--config", configPath)
	command.Env = append(os.Environ(), "E2E_ADMIN_TOKEN=admin-token-0000", "E2E_USER_TOKEN=user-token-00000")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout: %v", err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start standalone role: %v", err)
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatalf("read readiness: %v: %s", scanner.Err(), stderr.String())
	}
	var ready struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal(scanner.Bytes(), &ready); err != nil || ready.Address == "" {
		t.Fatalf("decode readiness %q: %v", scanner.Text(), err)
	}
	ids := &integrationRequestIDs{}
	admin := integrationClient(t, "http://"+ready.Address, "admin-token-0000", ids)
	user := integrationClient(t, "http://"+ready.Address, "user-token-00000", ids)
	agent, err := admin.CreateAgent(ctx, agentruntime.CreateAgentRequest{IdempotencyKey: "create", Name: "assistant", ModelProfile: "balanced", Instructions: "help"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	session, err := user.CreateSession(ctx, agentruntime.CreateSessionRequest{IdempotencyKey: "session", AgentRevision: agent.RevisionID})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	accepted, err := user.SendInput(ctx, agentruntime.SendInputRequest{SessionID: session.ID, IdempotencyKey: "input", Parts: []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "hello"}}})
	if err != nil {
		t.Fatalf("SendInput: %v", err)
	}
	if _, err := user.InspectTurn(ctx, session.ID, accepted.Turn.ID); err != nil {
		t.Fatalf("InspectTurn: %v", err)
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal shutdown: %v", err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("standalone role shutdown: %v: %s", err, stderr.String())
	}
	stopped = true
}

type integrationRequestIDs struct {
	mu   sync.Mutex
	next uint64
}

func (source *integrationRequestIDs) NextRequestID() (agentruntime.RequestID, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.next++
	return agentruntime.ParseRequestID(fmt.Sprintf("req_%016d", source.next))
}

func integrationClient(t *testing.T, baseURL, token string, ids agentruntime.RequestIDSource) *agentruntime.Client {
	t.Helper()
	credential, err := agentruntime.NewStaticBearerCredential(token)
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	client, err := agentruntime.NewClient(agentruntime.ClientConfig{BaseURL: baseURL, HTTPClient: http.DefaultClient, Credentials: credential, RequestIDs: ids})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return client
}
