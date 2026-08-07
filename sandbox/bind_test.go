package sandbox

import (
	"context"
	"testing"
	"time"
)

func TestBindCodecRejectsUnknownFields(t *testing.T) {
	_, err := decodeBindResponse([]byte(`{"version":"sandbox.control/v1","kind":"bind-response","assertion":"opaque","expires_at":"2026-08-07T00:00:00Z","unknown":true}`))
	if err == nil {
		t.Fatal("decodeBindResponse() error = nil, want rejection")
	}
}

func TestBindCodecRejectsDuplicateAndTrailingFields(t *testing.T) {
	for _, payload := range []string{
		`{"version":"sandbox.control/v1","version":"sandbox.control/v1","kind":"bind-response","assertion":"opaque","expires_at":"2026-08-07T00:00:00Z"}`,
		`{"version":"sandbox.control/v1","kind":"bind-response","assertion":"opaque","expires_at":"2026-08-07T00:00:00Z"} null`,
	} {
		if _, err := decodeBindResponse([]byte(payload)); err == nil {
			t.Fatalf("decodeBindResponse(%s) error = nil, want strict rejection", payload)
		}
	}
}

func TestClientBindsBeforePublication(t *testing.T) {
	source := &recordingCredentialSource{}
	client, err := newClientWithBindTransportAt(context.Background(), validClientConfig(source), bindTransportFunc(func(context.Context, string) (bindResponse, error) {
		return bindResponse{Version: controlV1, Kind: bindResponseKind, Assertion: "opaque", ExpiresAt: time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)}, nil
	}), time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("newClientWithBindTransport() error = %v", err)
	}
	if source.calls != 1 || client.assertion != "opaque" {
		t.Fatalf("bind state = calls:%d assertion:%q", source.calls, client.assertion)
	}
}

func validClientConfig(source CredentialSource) ClientConfig {
	return ClientConfig{Endpoint: Endpoint{URL: "https://sandbox.example.test"}, TLS: TLSConfig{ServerName: "sandbox.example.test", TrustBundleRef: "trust"}, Credentials: source, RequestTimeout: time.Second}
}
