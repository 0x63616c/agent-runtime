package egressproxy_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0x63616c/agent-runtime/internal/egressproxy"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Allowlisted egress proxy", func() {
	It("forwards only an absolute HTTP request to an exact allowlisted host and port", func() {
		client, upstream := net.Pipe()
		responded := respondToHTTP(upstream, http.StatusAccepted, "X-Upstream: allowed\r\n", "accepted")
		proxy, err := egressproxy.New(egressproxy.Config{
			AllowedTargets: []egressproxy.Target{{Host: "models.example.invalid", Port: 8080}},
			Resolve: func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
			},
			DialContext: func(_ context.Context, _ string, address string) (net.Conn, error) {
				Expect(address).To(Equal("8.8.8.8:8080"))
				return client, nil
			},
		})
		Expect(err).NotTo(HaveOccurred())

		request := httptest.NewRequest(http.MethodPost, "http://models.example.invalid:8080/v1/messages", strings.NewReader("request"))
		request.Header.Set("Proxy-Authorization", "never-forward-this")
		response := httptest.NewRecorder()
		proxy.ServeHTTP(response, request)

		Expect(response.Code).To(Equal(http.StatusAccepted))
		Expect(response.Header().Get("X-Upstream")).To(Equal("allowed"))
		Expect(response.Body.String()).To(Equal("accepted"))
		<-responded
	})

	It("refuses undeclared hosts, ports, proxy credentials, and origin-form requests before dialing", func() {
		called := false
		proxy, err := egressproxy.New(egressproxy.Config{
			AllowedTargets: []egressproxy.Target{{Host: "models.example.invalid", Port: 443}},
			DialContext:    func(context.Context, string, string) (net.Conn, error) { called = true; return nil, nil },
		})
		Expect(err).NotTo(HaveOccurred())
		for _, request := range []*http.Request{
			httptest.NewRequest(http.MethodGet, "http://other.example.invalid:443/v1", nil),
			httptest.NewRequest(http.MethodGet, "http://models.example.invalid:444/v1", nil),
			httptest.NewRequest(http.MethodGet, "/relative", nil),
		} {
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, request)
			Expect(response.Code).To(Equal(http.StatusForbidden))
		}
		Expect(called).To(BeFalse())
	})

	It("does not let a resolver or dial test seam reach a special address through HTTP", func() {
		for _, address := range []string{"10.0.0.1", "127.0.0.1", "169.254.169.254", "::1", "fc00::1"} {
			address := address
			By("refusing IANA special-use address " + address)
			dialed := false
			proxy, err := egressproxy.New(egressproxy.Config{
				AllowedTargets: []egressproxy.Target{{Host: "models.example.invalid", Port: 443}},
				Resolve: func(context.Context, string) ([]net.IPAddr, error) {
					return []net.IPAddr{{IP: net.ParseIP(address)}}, nil
				},
				DialContext: func(context.Context, string, string) (net.Conn, error) { dialed = true; return nil, nil },
			})
			Expect(err).NotTo(HaveOccurred())
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://models.example.invalid:443/v1/messages", nil))
			Expect(response.Code).To(Equal(http.StatusBadGateway), address)
			Expect(dialed).To(BeFalse(), address)
		}
	})

	It("checks the resolved address again when an HTTP redirect is requested", func() {
		firstClient, firstUpstream := net.Pipe()
		responded := respondToHTTP(firstUpstream, http.StatusFound, "Location: http://redirect.example.invalid:8080/token\r\n", "")
		var dials atomic.Int32
		proxy, err := egressproxy.New(egressproxy.Config{
			AllowedTargets: []egressproxy.Target{
				{Host: "models.example.invalid", Port: 8080},
				{Host: "redirect.example.invalid", Port: 8080},
			},
			Resolve: func(_ context.Context, host string) ([]net.IPAddr, error) {
				if host == "models.example.invalid" {
					return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
				}
				Expect(host).To(Equal("redirect.example.invalid"))
				return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
			},
			DialContext: func(_ context.Context, _ string, address string) (net.Conn, error) {
				Expect(address).To(Equal("8.8.8.8:8080"))
				dials.Add(1)
				return firstClient, nil
			},
		})
		Expect(err).NotTo(HaveOccurred())

		initial := httptest.NewRecorder()
		proxy.ServeHTTP(initial, httptest.NewRequest(http.MethodGet, "http://models.example.invalid:8080/v1/messages", nil))
		Expect(initial.Code).To(Equal(http.StatusFound))
		Expect(initial.Header().Get("Location")).To(Equal("http://redirect.example.invalid:8080/token"))
		<-responded

		redirect := httptest.NewRecorder()
		proxy.ServeHTTP(redirect, httptest.NewRequest(http.MethodGet, "http://redirect.example.invalid:8080/token", nil))
		Expect(redirect.Code).To(Equal(http.StatusBadGateway))
		Expect(dials.Load()).To(Equal(int32(1)))
	})

	It("checks a fresh HTTP resolution before each new upstream connection", func() {
		firstClient, firstUpstream := net.Pipe()
		responded := respondToHTTP(firstUpstream, http.StatusOK, "", "first")
		var resolutions atomic.Int32
		var dials atomic.Int32
		proxy, err := egressproxy.New(egressproxy.Config{
			AllowedTargets: []egressproxy.Target{{Host: "models.example.invalid", Port: 8080}},
			Resolve: func(context.Context, string) ([]net.IPAddr, error) {
				if resolutions.Add(1) == 1 {
					return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
				}
				return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
			},
			DialContext: func(_ context.Context, _ string, address string) (net.Conn, error) {
				Expect(address).To(Equal("8.8.8.8:8080"))
				dials.Add(1)
				return firstClient, nil
			},
		})
		Expect(err).NotTo(HaveOccurred())

		first := httptest.NewRecorder()
		proxy.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "http://models.example.invalid:8080/v1/messages", nil))
		Expect(first.Code).To(Equal(http.StatusOK))
		<-responded
		second := httptest.NewRecorder()
		proxy.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "http://models.example.invalid:8080/v1/messages", nil))
		Expect(second.Code).To(Equal(http.StatusBadGateway))
		Expect(resolutions.Load()).To(Equal(int32(2)))
		Expect(dials.Load()).To(Equal(int32(1)))
	})

	It("requires a finite exact target inventory", func() {
		for _, config := range []egressproxy.Config{
			{},
			{AllowedTargets: []egressproxy.Target{{Host: "*.example.invalid", Port: 443}}},
			{AllowedTargets: []egressproxy.Target{{Host: "models.example.invalid", Port: 0}}},
			{AllowedTargets: []egressproxy.Target{{Host: "models.example.invalid", Port: 443}, {Host: "MODELS.EXAMPLE.INVALID", Port: 443}}},
		} {
			_, err := egressproxy.New(config)
			Expect(err).To(HaveOccurred())
		}
	})

	It("opens an HTTPS CONNECT tunnel only to an exact declared target", func() {
		upstreamClient, upstreamServer := net.Pipe()
		proxy, err := egressproxy.New(egressproxy.Config{
			AllowedTargets: []egressproxy.Target{{Host: "models.example.invalid", Port: 443}},
			Resolve: func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
			},
			DialContext: func(_ context.Context, _ string, address string) (net.Conn, error) {
				Expect(address).To(Equal("8.8.8.8:443"))
				return upstreamServer, nil
			},
		})
		Expect(err).NotTo(HaveOccurred())
		client, server := net.Pipe()
		response := &hijackResponseWriter{header: make(http.Header), connection: server}
		request := httptest.NewRequestWithContext(context.Background(), http.MethodConnect, "http://models.example.invalid:443", nil)
		request.Host = "models.example.invalid:443"
		finished := make(chan struct{})
		go func() { proxy.ServeHTTP(response, request); close(finished) }()

		reader := bufio.NewReader(client)
		status, readErr := reader.ReadString('\n')
		Expect(readErr).NotTo(HaveOccurred())
		Expect(status).To(ContainSubstring("200"))
		_, writeErr := client.Write([]byte("encrypted-request"))
		Expect(writeErr).NotTo(HaveOccurred())
		buffer := make([]byte, len("encrypted-request"))
		_, readErr = io.ReadFull(upstreamClient, buffer)
		Expect(readErr).NotTo(HaveOccurred())
		Expect(string(buffer)).To(Equal("encrypted-request"))
		Expect(client.Close()).To(Succeed())
		Expect(upstreamClient.Close()).To(Succeed())
		<-finished
	})

	It("force-closes and accounts for held CONNECT tunnels during shutdown", func() {
		upstreamClient, upstreamServer := net.Pipe()
		proxy, err := egressproxy.New(egressproxy.Config{
			AllowedTargets: []egressproxy.Target{{Host: "models.example.invalid", Port: 443}},
			Resolve: func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
			},
			DialContext: func(context.Context, string, string) (net.Conn, error) { return upstreamServer, nil },
		})
		Expect(err).NotTo(HaveOccurred())
		client, server := net.Pipe()
		response := &hijackResponseWriter{header: make(http.Header), connection: server}
		request := httptest.NewRequestWithContext(context.Background(), http.MethodConnect, "http://models.example.invalid:443", nil)
		request.Host = "models.example.invalid:443"
		finished := make(chan struct{})
		go func() { proxy.ServeHTTP(response, request); close(finished) }()

		_, readErr := bufio.NewReader(client).ReadString('\n')
		Expect(readErr).NotTo(HaveOccurred())
		Eventually(proxy.ActiveTunnelCount).WithTimeout(time.Second).Should(Equal(1))
		Expect(proxy.CloseActiveTunnels()).To(Equal(1))
		shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		Expect(proxy.WaitForTunnels(shutdownContext)).To(Succeed())
		Expect(proxy.ActiveTunnelCount()).To(Equal(0))
		select {
		case <-finished:
		case <-shutdownContext.Done():
			Fail("held CONNECT tunnel did not return after force close")
		}
		Expect(client.Close()).To(Succeed())
		Expect(upstreamClient.Close()).To(Succeed())
	})

	It("refuses a target resolution with no public address before dialing", func() {
		for _, address := range []string{
			"0.0.0.1", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254",
			"172.16.0.1", "192.0.0.9", "192.0.2.1", "192.31.196.1", "192.52.193.1",
			"192.88.99.1", "192.168.0.1", "192.175.48.1", "198.18.0.1", "198.51.100.1",
			"203.0.113.9", "224.0.0.1", "240.0.0.1", "255.255.255.255",
			"::", "::1", "64:ff9b::1", "64:ff9b:1::1", "100::1", "100:0:0:1::1",
			"2001::1", "2001:db8::1", "2002::1", "2620:4f:8000::1", "3fff::1",
			"5f00::1", "fc00::1", "fe80::1", "ff00::1",
		} {
			address := address
			By("rejecting IANA special-use address " + address)
			dialed := false
			proxy, err := egressproxy.New(egressproxy.Config{
				AllowedTargets: []egressproxy.Target{{Host: "models.example.invalid", Port: 443}},
				Resolve: func(context.Context, string) ([]net.IPAddr, error) {
					return []net.IPAddr{{IP: net.ParseIP(address)}}, nil
				},
				DialContext: func(context.Context, string, string) (net.Conn, error) { dialed = true; return nil, nil },
			})
			Expect(err).NotTo(HaveOccurred())
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodConnect, "http://models.example.invalid:443", nil)
			request.Host = "models.example.invalid:443"
			proxy.ServeHTTP(response, request)
			Expect(response.Code).To(Equal(http.StatusBadGateway), address)
			Expect(dialed).To(BeFalse(), address)
		}
	})
})

func respondToHTTP(connection net.Conn, status int, headers, body string) <-chan struct{} {
	responded := make(chan struct{})
	go func() {
		defer GinkgoRecover()
		defer close(responded)
		defer func() { _ = connection.Close() }()
		request, err := http.ReadRequest(bufio.NewReader(connection))
		Expect(err).NotTo(HaveOccurred())
		Expect(request.URL.Path).To(Equal("/v1/messages"))
		Expect(request.Header.Get("Proxy-Authorization")).To(BeEmpty())
		_, err = io.WriteString(connection, fmt.Sprintf("HTTP/1.1 %d %s\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), headers, len(body), body))
		Expect(err).NotTo(HaveOccurred())
	}()
	return responded
}

type hijackResponseWriter struct {
	header     http.Header
	connection net.Conn
}

func (writer *hijackResponseWriter) Header() http.Header { return writer.header }

func (*hijackResponseWriter) Write(bytes []byte) (int, error) { return len(bytes), nil }

func (*hijackResponseWriter) WriteHeader(int) {}

func (writer *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return writer.connection, bufio.NewReadWriter(bufio.NewReader(writer.connection), bufio.NewWriter(writer.connection)), nil
}
