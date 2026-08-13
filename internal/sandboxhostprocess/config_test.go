package sandboxhostprocess

import (
	"strings"
	"testing"
)

func TestParseStrictReferenceHostConfiguration(t *testing.T) {
	t.Parallel()

	config, err := Parse(strings.NewReader(validHostDocument))
	if err != nil || config.hostID != "host_01" || config.hostGeneration != 2 || config.maximumReceipts != 100 || config.controlTrustFile != "/run/sandbox-host/control-trust.json" {
		t.Fatalf("Parse() = %#v, %v", config, err)
	}
}

func TestParseVersionOneHostConfigurationRequiresExplicitMigration(t *testing.T) {
	t.Parallel()

	compatibility := strings.Replace(validHostDocument, `"version":2`, `"version":1`, 1)
	if _, err := Parse(strings.NewReader(compatibility)); err == nil || !strings.Contains(err.Error(), "migrate to version 2") {
		t.Fatalf("Parse(version 1 versioned trust) error = %v, want explicit version 2 migration", err)
	}
	legacy := strings.Replace(compatibility, `"control_trust_file":`, `"control_key_id":"control_01","control_public_key_environment":"CONTROL_PUBLIC_KEY","control_trust_file":`, 1)
	if _, err := Parse(strings.NewReader(legacy)); err == nil || !strings.Contains(err.Error(), "migrate to version 2") {
		t.Fatalf("Parse(version 1 legacy trust) error = %v, want explicit version 2 migration", err)
	}
}

func TestParseVersionTwoHostConfigurationRefusesLegacySingleKeyFields(t *testing.T) {
	t.Parallel()

	legacy := strings.Replace(validHostDocument, `"control_trust_file":`, `"control_key_id":"control_01","control_public_key_environment":"CONTROL_PUBLIC_KEY","control_trust_file":`, 1)
	if _, err := Parse(strings.NewReader(legacy)); err == nil || !strings.Contains(err.Error(), "legacy") {
		t.Fatalf("Parse(version 2 legacy trust) error = %v, want versioned control_trust refusal", err)
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
		"unknown":          strings.Replace(validHostDocument, `"version":2`, `"version":2,"unknown":true`, 1),
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

func TestParseReferenceHostConfigurationBoundsItsInputBeforeAcceptingTrailingWhitespace(t *testing.T) {
	t.Parallel()

	const maximum = 64 << 10
	input := &countingReader{Reader: strings.NewReader(validHostDocument + strings.Repeat(" ", maximum+128))}
	if _, err := Parse(input); err == nil || input.read > maximum+1 {
		t.Fatalf("Parse(oversized) error=%v bytes-read=%d", err, input.read)
	}
}

const validHostDocument = `{"version":2,"control_url":"https://sandbox-control.internal:9443","server_name":"sandbox-control.internal","trust_bundle_file":"/run/sandbox-host/control-ca.crt","client_certificate_file":"/run/sandbox-host/tls.crt","client_private_key_file":"/run/sandbox-host/tls.key","control_trust_file":"/run/sandbox-host/control-trust.json","host_id":"host_01","host_generation":2,"journal_file":"/var/lib/sandbox-host/receipts.json","maximum_receipts":100,"host_signing_key_environment":"HOST_SIGNING_KEY","request_timeout_seconds":5,"test_fault_after_journal":false,"test_fault_after_receipt":false,"test_fault_after_result_send":false}`

type countingReader struct {
	*strings.Reader
	read int
}

func (reader *countingReader) Read(target []byte) (int, error) {
	count, err := reader.Reader.Read(target)
	reader.read += count
	return count, err
}
