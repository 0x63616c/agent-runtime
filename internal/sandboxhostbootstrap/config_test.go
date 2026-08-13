package sandboxhostbootstrap

import (
	"strings"
	"testing"
)

func TestParseAcceptsOneStrictLocalBootstrapDocument(t *testing.T) {
	config, err := Parse(strings.NewReader(`{"version":1,"database_dsn_environment":"SANDBOX_STATE_DSN","host_id":"sandbox-host-01","tenant":"public","pool":"local","generation":1,"certificate_file":"/run/host/tls.crt","signing_key_file":"/run/host/signing.key","capability_digest":"sha256:abcdef0123456789","expires_at":"2030-01-01T00:00:00Z"}`))
	if err != nil || config.hostID != "sandbox-host-01" || config.generation != 1 {
		t.Fatalf("Parse() = %#v, %v", config, err)
	}
}

func TestParseRefusesProductionShapedOrAmbiguousInput(t *testing.T) {
	for _, document := range []string{
		`{"version":2,"database_dsn_environment":"SANDBOX_STATE_DSN","host_id":"sandbox-host-01","tenant":"public","pool":"local","generation":1,"certificate_file":"/run/host/tls.crt","signing_key_file":"/run/host/signing.key","capability_digest":"sha256:abcdef0123456789","expires_at":"2030-01-01T00:00:00Z"}`,
		`{"version":1,"database_dsn_environment":"SANDBOX_STATE_DSN","host_id":"sandbox-host-01","tenant":"public","pool":"local","generation":1,"certificate_file":"relative","signing_key_file":"/run/host/signing.key","capability_digest":"sha256:abcdef0123456789","expires_at":"2030-01-01T00:00:00Z"}`,
		`{"version":1,"database_dsn_environment":"SANDBOX_STATE_DSN","host_id":"sandbox-host-01","tenant":"public","pool":"local","generation":1,"certificate_file":"/run/host/tls.crt","signing_key_file":"/run/host/signing.key","capability_digest":"not-a-digest","expires_at":"2030-01-01T00:00:00Z"}`,
	} {
		if _, err := Parse(strings.NewReader(document)); err == nil {
			t.Fatalf("Parse(%s) error = nil", document)
		}
	}
}
