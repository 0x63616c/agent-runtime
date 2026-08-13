package observabilityassets

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests are a deterministic provisioning gate for the checked-in
// operator assets. They intentionally do not claim that an external Grafana,
// Prometheus, or Temporal installation has loaded them.
func TestProvisionedDashboardCoversEveryRequiredOperatorSurface(t *testing.T) {
	t.Parallel()
	dashboard := readJSON(t, "../../deploy/observability/grafana/provisioning/dashboards/agent-runtime-overview.json")
	panels, ok := dashboard["panels"].([]any)
	if !ok {
		t.Fatal("dashboard panels is not an array")
	}
	joined := strings.ToLower(marshal(t, panels))
	for _, required := range []string{
		"sessions", "turns", "model", "retries", "tool", "authorization",
		"approval", "sandbox", "event", "blob", "codec", "temporal", "redaction", "oversize",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("dashboard is missing required observability surface %q", required)
		}
	}
	if dashboard["uid"] != "agent-runtime-operator-overview" {
		t.Fatalf("dashboard uid = %#v", dashboard["uid"])
	}
}

func TestProvisionedAlertRulesAreBoundedAndCoverSyntheticFailureSignals(t *testing.T) {
	t.Parallel()
	rules := readJSON(t, "../../deploy/observability/grafana/provisioning/alerting/agent-runtime-rules.json")
	groups, ok := rules["groups"].([]any)
	if !ok || len(groups) != 1 {
		t.Fatalf("alert groups = %#v, want one group", rules["groups"])
	}
	group, ok := groups[0].(map[string]any)
	if !ok {
		t.Fatal("alert group is not an object")
	}
	alerts, ok := group["rules"].([]any)
	if !ok || len(alerts) < 8 {
		t.Fatalf("alert rules = %#v, want at least eight", group["rules"])
	}
	seen := map[string]bool{}
	for _, value := range alerts {
		alert, ok := value.(map[string]any)
		if !ok {
			t.Fatal("alert is not an object")
		}
		uid, _ := alert["uid"].(string)
		if uid == "" || seen[uid] {
			t.Fatalf("alert uid %q is empty or duplicated", uid)
		}
		seen[uid] = true
		data := marshal(t, alert["data"])
		if alert["for"] == "" || !strings.Contains(data, "expr") {
			t.Fatalf("alert %q is not a bounded query alert", uid)
		}
	}
	for _, uid := range []string{"runtime-api-failures", "runtime-approval-expiry", "runtime-sandbox-failures", "runtime-event-gap", "runtime-redaction-oversize"} {
		if !seen[uid] {
			t.Fatalf("synthetic alert signal %q is missing", uid)
		}
	}
}

func TestDisposableOTLPLabWaitsForItsExpectedPublicResponse(t *testing.T) {
	t.Parallel()
	bytes, err := os.ReadFile(filepath.Clean("../../deploy/observability/local/run-otlp-lab.sh"))
	if err != nil {
		t.Fatalf("read disposable OTLP lab: %v", err)
	}
	text := string(bytes)
	if !strings.Contains(text, `if [[ "$response" == 400 ]]; then`) {
		t.Fatal("disposable OTLP lab does not wait for its expected bounded public response")
	}
	if strings.Contains(text, `curl -fsS "http://127.0.0.1:$api_port/v1/unknown"`) {
		t.Fatal("disposable OTLP lab treats its intentional non-2xx public route as curl --fail readiness")
	}
	for _, argument := range []string{"curl_timeout=(--connect-timeout 2 --max-time 5)", `curl "${curl_timeout[@]}" -sS`, `curl "${curl_timeout[@]}" -fsS`} {
		if !strings.Contains(text, argument) {
			t.Fatalf("disposable OTLP lab lacks bounded curl argument %q", argument)
		}
	}
	if !strings.Contains(text, `--validate-redaction-probe-response`) || !strings.Contains(text, `collector_unsafe_attribute_runtime_probe:true`) {
		t.Fatal("disposable OTLP lab does not expose its runtime redaction probe verification")
	}
}

func TestDisposableOTLPLabRedactionProbeRejectsEveryForbiddenAttributeKey(t *testing.T) {
	script := filepath.Clean("../../deploy/observability/local/run-otlp-lab.sh")
	for _, unsafeKey := range []string{
		"http.request.header.authorization", "http.request.body", "http.response.body", "gen_ai.prompt",
		"gen_ai.completion", "runtime.model.reasoning", "runtime.tool.output", "process.command_args",
	} {
		t.Run(unsafeKey, func(t *testing.T) {
			response := filepath.Join(t.TempDir(), "jaeger-response.json")
			fixture := map[string]any{"data": []any{map[string]any{"spans": []any{map[string]any{"tags": []any{
				map[string]any{"key": "safe.probe", "value": "collector-redaction-probe-safe-v1"},
				map[string]any{"key": unsafeKey, "value": "synthetic-unsafe-value"},
			}}}}}}
			bytes, err := json.Marshal(fixture)
			if err != nil {
				t.Fatalf("marshal fixture: %v", err)
			}
			if err := os.WriteFile(response, bytes, 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			command := exec.Command("bash", script, "--validate-redaction-probe-response", response)
			if output, err := command.CombinedOutput(); err == nil {
				t.Fatalf("redaction probe accepted %q: %s", unsafeKey, output)
			}
		})
	}

	t.Run("safe response", func(t *testing.T) {
		response := filepath.Join(t.TempDir(), "jaeger-response.json")
		fixture := []byte(`{"data":[{"spans":[{"tags":[{"key":"safe.probe","value":"collector-redaction-probe-safe-v1"}]}]}]}`)
		if err := os.WriteFile(response, fixture, 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		command := exec.Command("bash", script, "--validate-redaction-probe-response", response)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("redaction probe rejected safe response: %v: %s", err, output)
		}
	})
}

func TestDisposableOTLPLabRefusesEvidenceOutsideCleanMainCheckout(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		prepare func(t *testing.T, repository string)
		message string
	}{
		{
			name: "dirty",
			prepare: func(t *testing.T, repository string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(repository, "deploy", "production", "stack.json"), []byte("{}\n"), 0o600); err != nil {
					t.Fatalf("make checkout dirty: %v", err)
				}
			},
			message: "OTLP evidence requires a clean checkout",
		},
		{
			name: "untracked",
			prepare: func(t *testing.T, repository string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(repository, "untracked-evidence-input"), []byte("untracked\n"), 0o600); err != nil {
					t.Fatalf("make untracked input: %v", err)
				}
			},
			message: "OTLP evidence requires a clean checkout",
		},
		{
			name: "non-main branch",
			prepare: func(t *testing.T, repository string) {
				t.Helper()
				runGit(t, repository, "checkout", "-qb", "evidence-branch")
			},
			message: "OTLP evidence requires a checkout attached to main",
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			repository := disposableOTLPLabRepository(t)
			scenario.prepare(t, repository)
			script := filepath.Join(repository, "deploy", "observability", "local", "run-otlp-lab.sh")
			report := filepath.Join(repository, "evidence.json")
			output, err := exec.Command("bash", script, "--report", report, "--execute-authorized-disposable-lab").CombinedOutput()
			if err == nil || !strings.Contains(string(output), scenario.message) {
				t.Fatalf("evidence checkout refusal = %v, %s; want %q", err, output, scenario.message)
			}
		})
	}
}

func disposableOTLPLabRepository(t *testing.T) string {
	t.Helper()
	repository := t.TempDir()
	for _, path := range []string{
		"deploy/observability/local/run-otlp-lab.sh",
		"deploy/observability/otelcol/collector.yaml",
		"deploy/production/stack.json",
	} {
		bytes, err := os.ReadFile(filepath.Clean("../../" + path))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		target := filepath.Join(repository, path)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("make parent for %s: %v", path, err)
		}
		if err := os.WriteFile(target, bytes, 0o700); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	runGit(t, repository, "init", "-q", "-b", "main")
	runGit(t, repository, "config", "user.email", "observability-test@example.invalid")
	runGit(t, repository, "config", "user.name", "Observability Test")
	runGit(t, repository, "add", ".")
	runGit(t, repository, "commit", "-qm", "OTLP lab fixture")
	return repository
}

func runGit(t *testing.T, repository string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", repository}, arguments...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	bytes, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return decoded
}

func marshal(t *testing.T, value any) string {
	t.Helper()
	bytes, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(bytes)
}
