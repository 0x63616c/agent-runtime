// Package egressproxy provides an exact-target forward proxy for trust-scoped workloads.
package egressproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
)

var hostPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// specialUsePrefixes is the reviewed union of the IANA IPv4 and IPv6
// special-purpose registries as of 2025-10-09. The broad registry prefixes
// intentionally include their globally reachable exceptions: model egress
// has no reason to reach protocol anycast, transition, or AS112 addresses.
var specialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// Target is one exact DNS host and TCP port allowed through the proxy.
type Target struct {
	// Host is an exact public DNS name without wildcards.
	Host string
	// Port is the exact permitted TCP port.
	Port int
}

// Config declares the complete egress authority for one proxy process.
type Config struct {
	// AllowedTargets is the finite exact host/port allowlist.
	AllowedTargets []Target
	// Transport forwards non-CONNECT HTTP requests. Nil selects the standard transport.
	Transport http.RoundTripper
	// DialContext establishes one already-authorized target connection. Nil uses a standard dialer.
	DialContext func(context.Context, string, string) (net.Conn, error)
	// Resolve resolves a declared DNS host before dialing. Nil uses the system resolver.
	Resolve func(context.Context, string) ([]net.IPAddr, error)
}

// Proxy is a validated HTTP proxy with no ambient target authority.
type Proxy struct {
	allowed   map[string]struct{}
	transport http.RoundTripper
	dial      func(context.Context, string, string) (net.Conn, error)
	resolve   func(context.Context, string) ([]net.IPAddr, error)
}

// New validates the complete finite target allowlist.
func New(config Config) (Proxy, error) {
	targets, err := ParseTargets(config.AllowedTargets)
	if err != nil {
		return Proxy{}, err
	}
	config.AllowedTargets = targets
	if len(config.AllowedTargets) == 0 {
		return Proxy{}, errors.New("create egress proxy: at least one exact target is required")
	}
	allowed := make(map[string]struct{}, len(config.AllowedTargets))
	for _, target := range config.AllowedTargets {
		host := strings.ToLower(target.Host)
		if !hostPattern.MatchString(host) || target.Port < 1 || target.Port > 65535 {
			return Proxy{}, errors.New("create egress proxy: targets require an exact DNS host and TCP port")
		}
		key := targetKey(host, target.Port)
		if _, exists := allowed[key]; exists {
			return Proxy{}, errors.Newf("create egress proxy: target %s is declared more than once", key)
		}
		allowed[key] = struct{}{}
	}
	dial := config.DialContext
	if dial == nil {
		var dialer net.Dialer
		dial = dialer.DialContext
	}
	resolve := config.Resolve
	if resolve == nil {
		resolve = net.DefaultResolver.LookupIPAddr
	}
	proxy := Proxy{allowed: allowed, dial: dial, resolve: resolve}
	if config.Transport == nil {
		proxy.transport = &http.Transport{DialContext: proxy.dialResolved}
	} else {
		proxy.transport = config.Transport
	}
	return proxy, nil
}

// ParseTargets validates a finite exact-target inventory for composition roots.
func ParseTargets(input []Target) ([]Target, error) {
	if len(input) == 0 {
		return nil, errors.New("create egress proxy: at least one exact target is required")
	}
	allowed := make(map[string]struct{}, len(input))
	targets := make([]Target, 0, len(input))
	for _, target := range input {
		host := strings.ToLower(target.Host)
		if !hostPattern.MatchString(host) || target.Port < 1 || target.Port > 65535 {
			return nil, errors.New("create egress proxy: targets require an exact DNS host and TCP port")
		}
		key := targetKey(host, target.Port)
		if _, exists := allowed[key]; exists {
			return nil, errors.Newf("create egress proxy: target %s is declared more than once", key)
		}
		allowed[key] = struct{}{}
		targets = append(targets, Target{Host: host, Port: target.Port})
	}
	sort.Slice(targets, func(left, right int) bool {
		return targetKey(targets[left].Host, targets[left].Port) < targetKey(targets[right].Host, targets[right].Port)
	})
	return targets, nil
}

// ServeHTTP handles absolute-form HTTP and HTTPS CONNECT proxy requests only to allowlisted targets.
func (proxy Proxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodConnect {
		proxy.connect(writer, request)
		return
	}
	if !request.URL.IsAbs() || request.URL.User != nil || request.URL.Scheme != "http" || !proxy.allowedTarget(request.URL.Hostname(), request.URL.Port(), 80) {
		http.Error(writer, "egress target is not declared", http.StatusForbidden)
		return
	}
	forward := request.Clone(request.Context())
	forward.RequestURI = ""
	forward.Header = request.Header.Clone()
	forward.Header.Del("Proxy-Authorization")
	forward.Header.Del("Proxy-Connection")
	response, err := proxy.transport.RoundTrip(forward)
	if err != nil {
		http.Error(writer, "declared egress target is unavailable", http.StatusBadGateway)
		return
	}
	for name, values := range response.Header {
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	writer.WriteHeader(response.StatusCode)
	_, copyErr := io.Copy(writer, response.Body)
	closeErr := response.Body.Close()
	if copyErr != nil || closeErr != nil {
		return
	}
}

func (proxy Proxy) connect(writer http.ResponseWriter, request *http.Request) {
	host, port, err := net.SplitHostPort(request.Host)
	if err != nil || !proxy.allowedTarget(host, port, -1) {
		http.Error(writer, "egress target is not declared", http.StatusForbidden)
		return
	}
	upstream, err := proxy.dialResolved(request.Context(), "tcp", request.Host)
	if err != nil {
		http.Error(writer, "declared egress target is unavailable", http.StatusBadGateway)
		return
	}
	hijacker, supported := writer.(http.Hijacker)
	if !supported {
		closeConnection(upstream)
		http.Error(writer, "CONNECT is not supported by this server", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		closeConnection(upstream)
		return
	}
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		closeConnection(client)
		closeConnection(upstream)
		return
	}
	if err := buffered.Flush(); err != nil {
		closeConnection(client)
		closeConnection(upstream)
		return
	}
	toUpstream := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, client)
		closeConnection(upstream)
		close(toUpstream)
	}()
	_, _ = io.Copy(client, upstream)
	closeConnection(client)
	<-toUpstream
}

func (proxy Proxy) dialResolved(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || !proxy.allowedTarget(host, port, -1) {
		return nil, errors.New("dial egress proxy: target is not declared")
	}
	addresses, err := proxy.resolve(ctx, host)
	if err != nil {
		return nil, errors.Wrap(err, "resolve egress proxy target")
	}
	for _, candidate := range addresses {
		if !publicAddress(candidate.IP) {
			continue
		}
		connection, dialErr := proxy.dial(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
		if dialErr == nil {
			return connection, nil
		}
	}
	return nil, errors.New("dial egress proxy: declared target has no reachable public address")
}

func publicAddress(address net.IP) bool {
	parsed, valid := netip.AddrFromSlice(address)
	if !valid {
		return false
	}
	parsed = parsed.Unmap()
	for _, prefix := range specialUsePrefixes {
		if prefix.Contains(parsed) {
			return false
		}
	}
	return parsed.IsGlobalUnicast()
}

func closeConnection(connection io.Closer) {
	if err := connection.Close(); err != nil {
		return
	}
}

func (proxy Proxy) allowedTarget(host, port string, defaultPort int) bool {
	if port == "" {
		port = strconv.Itoa(defaultPort)
	}
	_, allowed := proxy.allowed[targetKey(strings.ToLower(host), parsePort(port))]
	return allowed
}

func parsePort(value string) int {
	port, err := net.LookupPort("tcp", value)
	if err != nil {
		return -1
	}
	return port
}

func targetKey(host string, port int) string { return host + ":" + strconv.Itoa(port) }

// Targets returns a sorted copy of the configured target inventory for authorized diagnostics.
func (proxy Proxy) Targets() []string {
	targets := make([]string, 0, len(proxy.allowed))
	for target := range proxy.allowed {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	return targets
}
