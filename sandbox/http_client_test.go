package sandbox

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClientBindsThroughPinnedHTTPSWithoutAmbientTrust(t *testing.T) {
	bindCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		bindCalls++
		if request.URL.Path != bindRouteV1 || request.Method != http.MethodPost {
			t.Fatalf("bind request = %s %s", request.Method, request.URL.Path)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer test-credential" {
			t.Fatalf("authorization = %q", got)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(body), `{"version":"sandbox.control/v1","kind":"bind-request"}`; got != want {
			t.Fatalf("bind body = %q, want %q", got, want)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"version":"sandbox.control/v1","kind":"bind-response","assertion":"opaque-binding","expires_at":"2030-01-01T00:00:00Z"}`))
	}))
	t.Cleanup(server.Close)

	certificate := server.Certificate()
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	source, err := NewStaticTrustBundleSource(map[TrustBundleRef]TrustBundle{
		"trust/test": {Version: "test/v1", PEMRoots: roots},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(context.Background(), ClientConfig{
		Endpoint: Endpoint{URL: server.URL},
		TLS:      TLSConfig{ServerName: certificate.DNSNames[0], TrustBundleRef: "trust/test"},
		Credentials: credentialSourceFunc(func(_ context.Context, sink CredentialSink) error {
			return sink.SetAuthorization("Bearer", "test-credential")
		}),
		TrustBundles:   source,
		RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if bindCalls != 1 {
		t.Fatalf("bind calls = %d, want one", bindCalls)
	}
	if err := client.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestStaticTrustBundleSourceFreezesAndDefensivelyReturnsPEM(t *testing.T) {
	pemRoots := []byte("original")
	source, err := NewStaticTrustBundleSource(map[TrustBundleRef]TrustBundle{
		"trust/test": {Version: "test/v1", PEMRoots: pemRoots},
	})
	if err != nil {
		t.Fatal(err)
	}
	pemRoots[0] = 'X'
	first, err := source.ResolveTrustBundle(context.Background(), "trust/test")
	if err != nil {
		t.Fatal(err)
	}
	first.PEMRoots[0] = 'Y'
	second, err := source.ResolveTrustBundle(context.Background(), "trust/test")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(second.PEMRoots), "original"; got != want {
		t.Fatalf("resolved PEM = %q, want frozen %q", got, want)
	}
}

func TestNewClientRejectsTrustBundleWithoutCertificate(t *testing.T) {
	source, err := NewStaticTrustBundleSource(map[TrustBundleRef]TrustBundle{
		"trust/invalid": {Version: "test/v1", PEMRoots: []byte("not a certificate")},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewClient(context.Background(), ClientConfig{
		Endpoint:       Endpoint{URL: "https://sandbox.example.test"},
		TLS:            TLSConfig{ServerName: "sandbox.example.test", TrustBundleRef: "trust/invalid"},
		Credentials:    credentialSourceFunc(func(_ context.Context, sink CredentialSink) error { return sink.SetAuthorization("Bearer", "test") }),
		TrustBundles:   source,
		RequestTimeout: time.Second,
	})
	failure, ok := AsFailure(err)
	if !ok || failure.Code != FailureInvalidArgument {
		t.Fatalf("trust failure = %#v, %v", failure, err)
	}
}
