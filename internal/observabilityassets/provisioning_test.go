package observabilityassets

import (
	"encoding/json"
	"os"
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
