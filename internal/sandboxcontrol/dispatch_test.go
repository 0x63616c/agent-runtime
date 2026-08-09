package sandboxcontrol

import (
	"context"
	"testing"
	"time"
)

func TestMemoryLedgerRejectsSecretMaterialFromDurableDispatchBody(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	for name, body := range map[string]string{
		"known environment key": `{"environment":{"API_TOKEN":"synthetic-secret"}}`,
		"bearer value":          `{"environment":{"MODE":"Bearer synthetic-secret"}}`,
		"private key":           `{"command":{"environment":{"MODE":"-----BEGIN PRIVATE KEY-----"}}}`,
	} {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			operation := Operation{Principal: "tenant_01:subject_01", ID: "op_secret", InputDigest: "sha256:input", CanonicalDigest: "sha256:canonical", EffectiveSpecDigest: "sha256:effective", DispatchBody: body, AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour)}
			if _, _, err := NewMemoryLedger().Accept(context.Background(), operation); err == nil {
				t.Fatal("Accept() accepted direct secret material")
			}
		})
	}
}

func TestMemoryLedgerPersistsOrdinaryEnvironmentAndIndirectSecretReference(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	operation := Operation{Principal: "tenant_01:subject_01", ID: "op_ordinary", InputDigest: "sha256:input", CanonicalDigest: "sha256:canonical", EffectiveSpecDigest: "sha256:effective", DispatchBody: `{"environment":{"MODE":"test"},"secret_bindings":[{"name":"model","purpose":"command"}]}`, AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour)}
	if _, _, err := NewMemoryLedger().Accept(context.Background(), operation); err != nil {
		t.Fatalf("Accept() rejected ordinary environment and indirect binding: %v", err)
	}
}
