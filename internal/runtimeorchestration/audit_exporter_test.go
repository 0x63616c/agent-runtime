package runtimeorchestration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	"github.com/0x63616c/agent-runtime/internal/runtimeorchestration"
	"github.com/0x63616c/agent-runtime/internal/runtimestate"
)

func TestHTTPAuditExporterPostsOneBoundedAuditFactAndRejectsAnOutage(t *testing.T) {
	fact := runtimestate.AuditFactRecord{Tenant: runtimecontent.TenantID("tenant-a"), AuditFactID: "audit_0000000000000001", OperationID: "operation-1", Actor: runtimecontent.PrincipalID("principal-a"), Kind: "input.accepted", OccurredAt: time.Date(2026, 8, 11, 2, 0, 0, 0, time.UTC), RetentionUntil: time.Date(2026, 8, 12, 2, 0, 0, 0, time.UTC)}
	var received runtimestate.AuditFactRecord
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	exporter, err := runtimeorchestration.NewHTTPAuditExporter(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Export(context.Background(), fact); err != nil {
		t.Fatalf("export audit fact: %v", err)
	}
	if received != fact {
		t.Fatalf("received audit fact = %#v, want %#v", received, fact)
	}

	outage := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusServiceUnavailable) }))
	defer outage.Close()
	exporter, err = runtimeorchestration.NewHTTPAuditExporter(outage.URL, outage.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Export(context.Background(), fact); err == nil {
		t.Fatal("export during audit-sink outage = nil, want retryable failure")
	}
}
