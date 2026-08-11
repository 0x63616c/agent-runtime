package runtimeorchestration

import (
	"testing"
	"time"
)

func TestConfiguredAuditExporterRequiresOptionalBoundedHTTPSConfiguration(t *testing.T) {
	valid := ProcessConfig{AuditSinkEndpoint: "https://audit.example.invalid/v1/facts", AuditSinkTimeout: 5 * time.Second}
	exporter, err := configuredAuditExporter(valid)
	if err != nil || exporter == nil {
		t.Fatalf("configured audit exporter = %#v, %v", exporter, err)
	}
	if exporter, err := configuredAuditExporter(ProcessConfig{}); err != nil || exporter != nil {
		t.Fatalf("absent optional audit exporter = %#v, %v", exporter, err)
	}
	for _, invalid := range []ProcessConfig{
		{AuditSinkEndpoint: "http://audit.example.invalid/v1/facts", AuditSinkTimeout: time.Second},
		{AuditSinkEndpoint: "https://audit.example.invalid/v1/facts", AuditSinkTimeout: 0},
		{AuditSinkEndpoint: "https://audit.example.invalid/v1/facts?token=forbidden", AuditSinkTimeout: time.Second},
		{AuditSinkTimeout: time.Second},
	} {
		if _, err := configuredAuditExporter(invalid); err == nil {
			t.Fatalf("configured audit exporter accepted %#v", invalid)
		}
	}
}
