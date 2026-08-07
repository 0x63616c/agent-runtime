package sandbox

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBindCodecRejectsUnknownFields(t *testing.T) {
	_, err := decodeBindResponse([]byte(`{"version":"sandbox.control/v1","kind":"bind-response","assertion":"opaque","expires_at":"2026-08-07T00:00:00Z","unknown":true}`))
	if err == nil {
		t.Fatal("decodeBindResponse() error = nil, want rejection")
	}
}

func TestClientRejectsCredentialSourceThatDoesNotSetExactlyOneAuthorization(t *testing.T) {
	validResponse := bindResponse{Version: controlV1, Kind: bindResponseKind, Assertion: "opaque", ExpiresAt: time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)}
	for _, test := range []struct {
		name   string
		source CredentialSource
	}{
		{name: "missing", source: credentialSourceFunc(func(context.Context, CredentialSink) error { return nil })},
		{name: "duplicate", source: credentialSourceFunc(func(_ context.Context, sink CredentialSink) error {
			_ = sink.SetAuthorization("Bearer", "first")
			_ = sink.SetAuthorization("Bearer", "second")
			return nil
		})},
		{name: "invalid scheme", source: credentialSourceFunc(func(_ context.Context, sink CredentialSink) error {
			_ = sink.SetAuthorization("Bearer injected", "value")
			return nil
		})},
	} {
		t.Run(test.name, func(t *testing.T) {
			bindCalls := 0
			_, err := newClientWithBindTransportAt(context.Background(), validClientConfig(test.source), bindTransportFunc(func(context.Context, string) (bindResponse, error) {
				bindCalls++
				return validResponse, nil
			}), time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC))
			failure, ok := AsFailure(err)
			if !ok || failure.Code != FailureUnavailable {
				t.Fatalf("credential failure = %#v, %v; want unavailable", failure, err)
			}
			if bindCalls != 0 {
				t.Fatalf("bind calls = %d, want none before valid request authorization", bindCalls)
			}
		})
	}
}

func TestCredentialSinkIsRevokedBeforeBindResponseWait(t *testing.T) {
	var retained CredentialSink
	source := credentialSourceFunc(func(_ context.Context, sink CredentialSink) error {
		retained = sink
		return sink.SetAuthorization("Bearer", "credential")
	})
	_, err := newClientWithBindTransportAt(context.Background(), validClientConfig(source), bindTransportFunc(func(_ context.Context, authorization string) (bindResponse, error) {
		if authorization != "Bearer credential" {
			t.Fatalf("authorization = %q", authorization)
		}
		if setErr := retained.SetAuthorization("Bearer", "late"); setErr == nil {
			t.Fatal("credential sink remained writable while awaiting bind response")
		}
		return bindResponse{Version: controlV1, Kind: bindResponseKind, Assertion: "opaque", ExpiresAt: time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)}, nil
	}), time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if setErr := retained.SetAuthorization("Bearer", "after-return"); setErr == nil {
		t.Fatal("credential sink became writable after constructor returned")
	}
}

func TestBindMapsContextCancellationWithoutTransportCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sourceError := errors.New("credential backend detail")
	_, err := newClientWithBindTransportAt(ctx, validClientConfig(credentialSourceFunc(func(context.Context, CredentialSink) error {
		return sourceError
	})), bindTransportFunc(func(context.Context, string) (bindResponse, error) {
		t.Fatal("bind transport called after cancellation")
		return bindResponse{}, nil
	}), time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC))
	failure, ok := AsFailure(err)
	if !ok || failure.Code != FailureCancelled || !errors.Is(err, context.Canceled) || errors.Is(err, sourceError) {
		t.Fatalf("cancelled bind error = %#v, %v", failure, err)
	}
}

type credentialSourceFunc func(context.Context, CredentialSink) error

func (source credentialSourceFunc) Apply(ctx context.Context, sink CredentialSink) error {
	return source(ctx, sink)
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
	return ClientConfig{Endpoint: Endpoint{URL: "https://sandbox.example.test"}, TLS: TLSConfig{ServerName: "sandbox.example.test", TrustBundleRef: "trust"}, Credentials: source, TrustBundles: trustBundleSourceFunc(func(context.Context, TrustBundleRef) (TrustBundle, error) {
		return TrustBundle{Version: "test/v1", PEMRoots: []byte("test")}, nil
	}), RequestTimeout: time.Second}
}

type trustBundleSourceFunc func(context.Context, TrustBundleRef) (TrustBundle, error)

func (source trustBundleSourceFunc) ResolveTrustBundle(ctx context.Context, reference TrustBundleRef) (TrustBundle, error) {
	return source(ctx, reference)
}
