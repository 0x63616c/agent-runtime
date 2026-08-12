package agentspecbackfillkube

import (
	"net/http"
	"testing"
	"time"
)

func TestRESTConfigPinsTheDeclaredServiceAccountConnectionWithoutAmbientProxy(t *testing.T) {
	t.Parallel()
	configured, err := restConfig(Config{APIServerURL: "https://kubernetes.example.test:6443", Namespace: "agent-spec-backfill", CAFile: "/var/run/certs/ca.crt", TokenFile: "/var/run/tokens/controller", TLSServerName: "kubernetes.example.test", RequestTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if configured.Host != "https://kubernetes.example.test:6443" || configured.CAFile != "/var/run/certs/ca.crt" || configured.ServerName != "kubernetes.example.test" || configured.BearerTokenFile != "/var/run/tokens/controller" || configured.Timeout != 3*time.Second || configured.Proxy == nil || configured.UserAgent != "agent-runtime-agent-spec-backfill-controller" {
		t.Fatalf("unexpected explicit REST configuration: %#v", configured)
	}
	proxy, err := configured.Proxy(&http.Request{})
	if err != nil || proxy != nil {
		t.Fatalf("expected ambient proxy to be disabled, got proxy=%v err=%v", proxy, err)
	}
}
