package tooldispatch_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/tooldispatch"
)

func TestDispatchTriggerAuthenticatesAnEmptyRequestWithoutExposingExecutionAuthority(t *testing.T) {
	calls := 0
	service, err := tooldispatch.NewServer("broker-token", func(context.Context) error { calls++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(service)
	defer server.Close()
	for _, test := range []struct {
		token, body    string
		audience, role string
		want           int
	}{{"", "", tooldispatch.Audience, tooldispatch.Role, http.StatusNotFound}, {"Bearer wrong", "", tooldispatch.Audience, tooldispatch.Role, http.StatusNotFound}, {"Bearer broker-token", "{}", tooldispatch.Audience, tooldispatch.Role, http.StatusNotFound}, {"Bearer broker-token", "", "wrong", tooldispatch.Role, http.StatusNotFound}, {"Bearer broker-token", "", tooldispatch.Audience, tooldispatch.Role, http.StatusOK}} {
		request, err := http.NewRequest(http.MethodPost, server.URL+"/private/v1/tool-dispatch/scan", strings.NewReader(test.body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", test.token)
		request.Header.Set("X-Tool-Dispatch-Audience", test.audience)
		request.Header.Set("X-Tool-Dispatch-Role", test.role)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if response.StatusCode != test.want {
			t.Fatalf("status = %d, want %d", response.StatusCode, test.want)
		}
	}
	if calls != 1 {
		t.Fatalf("scan calls = %d, want 1", calls)
	}
}

func TestClientSendsOnlyTheFixedTriggerIdentity(t *testing.T) {
	service, err := tooldispatch.NewServer("broker-token", func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(service)
	defer server.Close()
	client, err := tooldispatch.NewClient(server.URL, "broker-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := client.DispatchOnce(context.Background())
	if err != nil || !receipt.Attempted {
		t.Fatalf("DispatchOnce() = %#v, %v", receipt, err)
	}
}

func TestClientRefusesInsecureTriggerEndpoint(t *testing.T) {
	client, err := tooldispatch.NewClient("http://tool-dispatch.invalid", "broker-token", nil)
	if client != nil || err == nil {
		t.Fatalf("NewClient insecure endpoint = %#v, %v", client, err)
	}
}

func TestTrustedClientRequiresReadablePinnedCAAndServerName(t *testing.T) {
	service, err := tooldispatch.NewServer("broker-token", func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(service)
	defer server.Close()
	certificate := server.Certificate()
	path := t.TempDir() + "/dispatch-ca.pem"
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if client, err := tooldispatch.NewTrustedClient(server.URL, "broker-token", certificate.DNSNames[0], path); err != nil || client == nil {
		t.Fatalf("NewTrustedClient() = %#v, %v", client, err)
	}
	if client, err := tooldispatch.NewTrustedClient(server.URL, "broker-token", certificate.DNSNames[0], path+".missing"); err == nil || client != nil {
		t.Fatalf("NewTrustedClient unreadable trust = %#v, %v", client, err)
	}
	otherTrustPath := t.TempDir() + "/unrelated-ca.pem"
	if err := os.WriteFile(otherTrustPath, unrelatedCertificatePEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := tooldispatch.NewTrustedClient(server.URL, "broker-token", certificate.DNSNames[0], otherTrustPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.DispatchOnce(context.Background()); err == nil {
		t.Fatal("DispatchOnce accepted a certificate outside the mounted trust bundle")
	}
	client, err = tooldispatch.NewTrustedClient(server.URL, "broker-token", "wrong.dispatch.invalid", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.DispatchOnce(context.Background()); err == nil {
		t.Fatal("DispatchOnce with mismatched server name succeeded")
	}
}

func unrelatedCertificatePEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "unrelated.tool-dispatch.invalid"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute), IsCA: true, BasicConstraintsValid: true}
	raw, err := x509.CreateCertificate(rand.Reader, &certificate, &certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
}

func TestBrokerServerRefusesMissingWorker(t *testing.T) {
	if service, err := tooldispatch.NewBrokerServer("broker-token", nil); err == nil || service != nil {
		t.Fatalf("NewBrokerServer(nil) = %#v, %v", service, err)
	}
}

func TestDispatchTriggerRejectsChunkedPayload(t *testing.T) {
	calls := 0
	service, err := tooldispatch.NewServer("broker-token", func(context.Context) error { calls++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service)
	defer server.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/private/v1/tool-dispatch/scan", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = -1
	request.Header.Set("Authorization", "Bearer broker-token")
	request.Header.Set("X-Tool-Dispatch-Audience", tooldispatch.Audience)
	request.Header.Set("X-Tool-Dispatch-Role", tooldispatch.Role)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNotFound || calls != 0 {
		t.Fatalf("chunked trigger = status %d calls %d, want 404 and zero calls", response.StatusCode, calls)
	}
}

func TestTriggerLoopMakesOneBoundedEmptyScanAndStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	client := triggerClientFunc(func(context.Context) (tooldispatch.Receipt, error) {
		calls++
		cancel()
		return tooldispatch.Receipt{Attempted: true}, nil
	})
	if err := tooldispatch.RunTriggerLoop(ctx, client, triggerScheduler{ticks: make(chan time.Time)}, time.Second); err != nil {
		t.Fatalf("RunTriggerLoop() = %v", err)
	}
	if calls != 1 {
		t.Fatalf("scan calls = %d, want 1", calls)
	}
}

type triggerScheduler struct{ ticks chan time.Time }

func (scheduler triggerScheduler) After(time.Duration) <-chan time.Time { return scheduler.ticks }

type triggerClientFunc func(context.Context) (tooldispatch.Receipt, error)

func (function triggerClientFunc) DispatchOnce(ctx context.Context) (tooldispatch.Receipt, error) {
	return function(ctx)
}
