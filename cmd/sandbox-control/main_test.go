package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/0x63616c/agent-runtime/internal/sandboxcontrolprocess"
)

func TestLogReadyEmitsOnlyBoundRoleAddresses(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	logReady(logger, sandboxcontrolprocess.BoundAddresses{Public: "127.0.0.1:41001", HostControl: "0.0.0.0:41002"})
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode readiness record: %v", err)
	}
	if record["msg"] != "sandbox control ready" || record["role"] != "sandbox-control" || record["public_address"] != "127.0.0.1:41001" || record["host_control_address"] != "0.0.0.0:41002" {
		t.Fatalf("readiness record = %#v", record)
	}
	for _, forbidden := range []string{"config", "secret", "database", "authorization", "assertion", "key", "certificate"} {
		if _, found := record[forbidden]; found {
			t.Fatalf("readiness record includes unsafe field %q: %#v", forbidden, record)
		}
	}
}
