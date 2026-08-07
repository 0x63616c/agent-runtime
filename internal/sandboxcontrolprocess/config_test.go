package sandboxcontrolprocess

import (
	"strings"
	"testing"
	"time"
)

func TestParseStrictDeclarativeConfiguration(t *testing.T) {
	t.Parallel()

	config, err := Parse(strings.NewReader(validDocument))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if config.listenAddress != "127.0.0.1:8443" || config.identity.Principal != "principal_01" || config.reconciliationInterval != time.Second || config.reconciliationPageSize != 100 {
		t.Fatalf("Parse() config = %#v", config)
	}
	if config.admission.Defaults.MilliCPU != 100 || config.admission.Defaults.Lifetime != 60*time.Second {
		t.Fatalf("Parse() defaults = %#v", config.admission.Defaults)
	}
}

func TestParseRejectsImplicitOrAmbiguousConfiguration(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"unknown field":            strings.Replace(validDocument, `"version": 1`, `"version": 1, "surprise": true`, 1),
		"relative TLS path":        strings.Replace(validDocument, `"/run/tls/tls.crt"`, `"tls.crt"`, 1),
		"invalid secret reference": strings.Replace(validDocument, `"SANDBOX_DATABASE_DSN"`, `"database-dsn"`, 1),
		"unbounded binding":        strings.Replace(validDocument, `"binding_lifetime_seconds": 300`, `"binding_lifetime_seconds": 0`, 1),
		"trailing document":        validDocument + `{}`,
	}
	for name, input := range tests {
		name, input := name, input
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse(strings.NewReader(input)); err == nil {
				t.Fatal("Parse() error = nil")
			}
		})
	}
}

func TestRequiredSecretDoesNotDiscloseValues(t *testing.T) {
	t.Parallel()

	const secret = "do-not-print-this-secret"
	_, err := requiredSecret(func(string) (string, bool) { return secret, true }, "SANDBOX_AUTHORIZATION")
	if err != nil {
		t.Fatalf("requiredSecret() error = %v", err)
	}
	_, err = requiredSecret(func(string) (string, bool) { return "", false }, "SANDBOX_AUTHORIZATION")
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("requiredSecret() error = %v", err)
	}
}

func TestParseHostControlRequiresDistinctExplicitAuthority(t *testing.T) {
	t.Parallel()

	withHost := strings.TrimSuffix(validDocument, "\n}") + `,
  "host_control": {
    "listen_address": "127.0.0.1:9443",
    "tls_certificate_file": "/run/host-control/tls.crt",
    "tls_private_key_file": "/run/host-control/tls.key",
    "client_ca_file": "/run/host-control/client-ca.crt",
    "control_key_id": "control_01",
    "control_signing_key_environment": "SANDBOX_CONTROL_SIGNING_KEY",
    "lease_seconds": 60
  }
}`
	config, err := Parse(strings.NewReader(withHost))
	if err != nil || config.hostControl == nil || config.hostControl.lease != time.Minute {
		t.Fatalf("Parse(host control) = %#v, %v", config.hostControl, err)
	}
	invalid := strings.Replace(withHost, `"127.0.0.1:9443"`, `"127.0.0.1:8443"`, 1)
	if _, err := Parse(strings.NewReader(invalid)); err == nil {
		t.Fatal("Parse() accepted shared public/host listener")
	}
}

const validDocument = `{
  "version": 1,
  "listen_address": "127.0.0.1:8443",
  "tls_certificate_file": "/run/tls/tls.crt",
  "tls_private_key_file": "/run/tls/tls.key",
  "database_dsn_environment": "SANDBOX_DATABASE_DSN",
  "authorization_environment": "SANDBOX_AUTHORIZATION",
  "assertion_key_environment": "SANDBOX_ASSERTION_KEY",
  "identity": {
    "authority": "development",
    "tenant": "tenant_01",
    "subject": "runtime_01",
    "principal": "principal_01"
  },
  "binding_lifetime_seconds": 300,
  "retention_seconds": 86400,
  "wait_interval_millis": 25,
  "reconciliation_interval_millis": 1000,
  "reconciliation_page_size": 100,
  "admission": {
    "version": "policy-v1",
    "canonicalizer_version": "sandbox.control/v1",
    "capability_version": "capabilities-v1",
    "image_admission_version": "images-v1",
    "defaults": {"milli_cpu": 100, "lifetime_seconds": 60},
    "maximum": {"milli_cpu": 1000, "lifetime_seconds": 3600},
    "capabilities": {},
    "admitted_images": {}
  }
}`
