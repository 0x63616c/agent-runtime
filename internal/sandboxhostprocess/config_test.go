package sandboxhostprocess

import (
	"strings"
	"testing"
)

func TestParseStrictReferenceHostConfiguration(t *testing.T) {
	t.Parallel()

	config, err := Parse(strings.NewReader(validHostDocument))
	if err != nil || config.hostID != "host_01" || config.hostGeneration != 2 || config.maximumReceipts != 100 || config.controlTrust.version != 3 || config.controlTrust.next == nil {
		t.Fatalf("Parse() = %#v, %v", config, err)
	}
}

func TestParseReferenceHostResultRecoveryFaultProfile(t *testing.T) {
	t.Parallel()

	input := strings.Replace(validHostDocument, `"test_fault_after_receipt":false`, `"test_fault_after_receipt":true`, 1)
	config, err := Parse(strings.NewReader(input))
	if err != nil || !config.testFaultAfterReceipt {
		t.Fatalf("Parse() = %#v, %v", config, err)
	}
}

func TestParseReferenceHostResultAcknowledgementFaultProfile(t *testing.T) {
	t.Parallel()

	input := strings.Replace(validHostDocument, `"test_fault_after_result_send":false`, `"test_fault_after_result_send":true`, 1)
	config, err := Parse(strings.NewReader(input))
	if err != nil || !config.testFaultAfterResultSend {
		t.Fatalf("Parse() = %#v, %v", config, err)
	}
}

func TestParseReferenceHostRejectsAmbientOrUnknownConfiguration(t *testing.T) {
	t.Parallel()

	for name, input := range map[string]string{
		"HTTP":             strings.Replace(validHostDocument, "https://", "http://", 1),
		"relative journal": strings.Replace(validHostDocument, "/var/lib/sandbox-host/receipts.json", "receipts.json", 1),
		"unknown":          strings.Replace(validHostDocument, `"version":1`, `"version":1,"unknown":true`, 1),
		"ambient secret":   strings.Replace(validHostDocument, "HOST_SIGNING_KEY", "host-signing-key", 1),
	} {
		name, input := name, input
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse(strings.NewReader(input)); err == nil {
				t.Fatal("Parse() error = nil")
			}
		})
	}
}

const validHostDocument = `{"version":1,"control_url":"https://sandbox-control.internal:9443","server_name":"sandbox-control.internal","trust_bundle_file":"/run/sandbox-host/control-ca.crt","client_certificate_file":"/run/sandbox-host/tls.crt","client_private_key_file":"/run/sandbox-host/tls.key","host_id":"host_01","host_generation":2,"journal_file":"/var/lib/sandbox-host/receipts.json","maximum_receipts":100,"control_trust":{"version":3,"revocation_epoch":9,"current":{"id":"control_01","version":4,"public_key_environment":"CONTROL_PUBLIC_KEY","not_before":"2026-08-08T00:00:00Z","not_after":"2026-08-09T00:00:00Z"},"next":{"id":"control_02","version":5,"public_key_environment":"CONTROL_NEXT_PUBLIC_KEY","not_before":"2026-08-08T00:00:00Z","not_after":"2026-08-09T00:00:00Z"}},"host_signing_key_environment":"HOST_SIGNING_KEY","request_timeout_seconds":5,"test_fault_after_journal":false,"test_fault_after_receipt":false,"test_fault_after_result_send":false}`
