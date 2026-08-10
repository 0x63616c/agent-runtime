package sandboxcontrol

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestMemoryLedgerRejectsDirectSecretTransportFromTypedDispatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	for name, request := range map[string]sandbox.OperationRequest{
		"non-public environment name": {ID: "op_secret", Kind: sandbox.OperationCreateSandbox, CreateSandbox: &sandbox.CreateSandboxRequest{Spec: sandbox.SandboxSpec{Environment: map[string]string{"API_TOKEN": "synthetic-secret"}}}},
		"mixed-case bearer command":   {ID: "op_secret", Kind: sandbox.OperationExecProcess, ExecProcess: &sandbox.ExecProcessRequest{SandboxID: "sbx_01", Command: sandbox.Command{Executable: "/bin/echo", Argv: []string{"bEaReR synthetic-secret"}, WorkDir: "/work"}}},
		"private key environment":     {ID: "op_secret", Kind: sandbox.OperationExecProcess, ExecProcess: &sandbox.ExecProcessRequest{SandboxID: "sbx_01", Command: sandbox.Command{Executable: "/bin/echo", WorkDir: "/work", Environment: map[string]string{"MODE": "-----BEGIN PRIVATE KEY-----"}}}},
	} {
		name, request := name, request
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			operation := dispatchOperation(t, now, request)
			if _, _, err := NewMemoryLedger().Accept(context.Background(), operation); err == nil {
				t.Fatal("Accept() accepted direct secret transport")
			}
		})
	}
}

func TestMemoryLedgerPersistsTypedOrdinaryEnvironmentAndIndirectSecretReference(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	request := sandbox.OperationRequest{ID: "op_ordinary", Kind: sandbox.OperationCreateSandbox, CreateSandbox: &sandbox.CreateSandboxRequest{Spec: sandbox.SandboxSpec{Environment: map[string]string{"MODE": "test", "PUBLIC_FEATURE_FLAG": "tokenizer-sketch"}, SecretBindings: []sandbox.SecretBinding{{Name: "model", Purpose: "command"}}, Labels: map[string]string{"secret-history": "Bearer is documentation, not authority"}}}}
	operation := dispatchOperation(t, now, request)
	if _, _, err := NewMemoryLedger().Accept(context.Background(), operation); err != nil {
		t.Fatalf("Accept() rejected typed ordinary environment and indirect binding: %v", err)
	}
}

func TestMemoryLedgerRejectsUntypedDispatchShape(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	operation := Operation{Principal: "tenant_01:subject_01", ID: "op_untyped", InputDigest: "sha256:input", CanonicalDigest: "sha256:canonical", EffectiveSpecDigest: "sha256:effective", DispatchBody: `{"environment":{"MODE":"test"}}`, AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour)}
	if _, _, err := NewMemoryLedger().Accept(context.Background(), operation); err == nil {
		t.Fatal("Accept() accepted an untyped arbitrary JSON dispatch")
	}
}

func dispatchOperation(t *testing.T, now time.Time, request sandbox.OperationRequest) Operation {
	t.Helper()
	body, err := json.Marshal(dispatchEnvelope{Version: "sandbox.control/v1", Kind: "operation-request", Request: request})
	if err != nil {
		t.Fatal(err)
	}
	return Operation{Principal: "tenant_01:subject_01", ID: string(request.ID), InputDigest: "sha256:input", CanonicalDigest: "sha256:canonical", EffectiveSpecDigest: "sha256:effective", DispatchBody: string(body), AcceptedAt: now, RetentionExpiresAt: now.Add(time.Hour)}
}
