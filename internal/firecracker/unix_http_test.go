package firecracker

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUnixFirecrackerHTTPWaitReadyUsesTheBoundSocket(t *testing.T) {
	directory, err := os.MkdirTemp(os.TempDir(), "fc-http-")
	if err != nil {
		t.Fatalf("make short socket directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(directory) }()
	socketPath := filepath.Join(directory, "firecracker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on Firecracker socket: %v", err)
	}
	defer func() { _ = listener.Close() }()
	port, err := newUnixFirecrackerHTTP(socketPath, &net.Dialer{})
	if err != nil {
		t.Fatalf("newUnixFirecrackerHTTP() error = %v", err)
	}
	if err := port.Bind(context.Background(), socketPath); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := port.WaitReady(ctx); err != nil {
		t.Fatalf("WaitReady() error = %v", err)
	}
}

func TestUnixFirecrackerHTTPWaitReadyHonorsItsContext(t *testing.T) {
	port, err := newUnixFirecrackerHTTP(filepath.Join(t.TempDir(), "missing.sock"), &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := port.Bind(context.Background(), port.socketPath); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := port.WaitReady(ctx); err == nil || !strings.Contains(err.Error(), "await private Firecracker API socket") {
		t.Fatalf("WaitReady() error = %v, want bounded socket readiness failure", err)
	}
}

func TestUnixFirecrackerHTTPWritesTheFixedLaunchSequenceToItsBoundSocket(t *testing.T) {
	directory, err := os.MkdirTemp(os.TempDir(), "fc-http-")
	if err != nil {
		t.Fatalf("make short socket directory: %v", err)
	}
	defer func() {
		if closeErr := os.RemoveAll(directory); closeErr != nil {
			t.Errorf("remove socket directory: %v", closeErr)
		}
	}()
	socketPath := filepath.Join(directory, "firecracker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on Firecracker socket: %v", err)
	}
	defer func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close socket listener: %v", closeErr)
		}
	}()

	type receivedRequest struct {
		method string
		path   string
		body   string
	}
	var (
		mu       sync.Mutex
		received []receivedRequest
	)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Errorf("read request body: %v", readErr)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		mu.Lock()
		received = append(received, receivedRequest{method: request.Method, path: request.URL.Path, body: string(body)})
		mu.Unlock()
		writer.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = server.Serve(listener) }()
	defer func() {
		if closeErr := server.Close(); closeErr != nil {
			t.Errorf("close HTTP server: %v", closeErr)
		}
	}()

	port, err := newUnixFirecrackerHTTP(socketPath, &net.Dialer{})
	if err != nil {
		t.Fatalf("newUnixFirecrackerHTTP() error = %v", err)
	}
	if err := port.Bind(context.Background(), socketPath); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	for _, call := range []struct {
		path string
		body any
	}{
		{path: "/machine-config", body: firecrackerMachineConfig{VCPUCount: 1, MemoryMiB: 256}},
		{path: "/boot-source", body: firecrackerBootSource{KernelImagePath: "/kernel/vmlinux", BootArgs: "console=ttyS0 reboot=k panic=1 init=/sbin/init -- sandbox-001 fixture-v1"}},
		{path: "/drives/rootfs", body: firecrackerRootDrive{DriveID: "rootfs", PathOnHost: "/drives/rootfs.ext4", RootDevice: true, ReadOnly: false}},
		{path: "/vsock", body: firecrackerVSock{GuestCID: defaultGuestCID, UDSPath: "/run/firecracker.vsock"}},
		{path: "/actions", body: firecrackerAction{ActionType: "InstanceStart"}},
	} {
		if err := port.Put(context.Background(), call.path, call.body); err != nil {
			t.Fatalf("Put(%s) error = %v", call.path, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	want := []receivedRequest{
		{method: http.MethodPut, path: "/machine-config", body: `{"vcpu_count":1,"mem_size_mib":256,"smt":false}`},
		{method: http.MethodPut, path: "/boot-source", body: `{"kernel_image_path":"/kernel/vmlinux","boot_args":"console=ttyS0 reboot=k panic=1 init=/sbin/init -- sandbox-001 fixture-v1"}`},
		{method: http.MethodPut, path: "/drives/rootfs", body: `{"drive_id":"rootfs","path_on_host":"/drives/rootfs.ext4","is_root_device":true,"is_read_only":false}`},
		{method: http.MethodPut, path: "/vsock", body: `{"guest_cid":3,"uds_path":"/run/firecracker.vsock"}`},
		{method: http.MethodPut, path: "/actions", body: `{"action_type":"InstanceStart"}`},
	}
	if len(received) != len(want) {
		t.Fatalf("received %d requests, want %d: %#v", len(received), len(want), received)
	}
	for index := range want {
		if received[index] != want[index] {
			t.Errorf("request %d = %#v, want %#v", index, received[index], want[index])
		}
	}
}

func TestUnixFirecrackerHTTPRefusesAnotherSocketBeforeDialing(t *testing.T) {
	dialer := &recordingUnixDialer{}
	port, err := newUnixFirecrackerHTTP("/run/firecracker.socket", dialer)
	if err != nil {
		t.Fatalf("newUnixFirecrackerHTTP() error = %v", err)
	}
	if err := port.Bind(context.Background(), "/run/other.socket"); !errors.Is(err, ErrSmokeUnavailable) {
		t.Fatalf("Bind() error = %v, want canonical socket refusal", err)
	}
	if got := dialer.CallCount(); got != 0 {
		t.Fatalf("dial count = %d, want no dial", got)
	}
}

func TestUnixFirecrackerHTTPRequiresOneCanonicalSocketAndDialer(t *testing.T) {
	for _, test := range []struct {
		name       string
		socketPath string
		dialer     unixSocketDialer
	}{
		{name: "relative socket", socketPath: "firecracker.sock", dialer: &net.Dialer{}},
		{name: "root socket", socketPath: "/", dialer: &net.Dialer{}},
		{name: "nil dialer", socketPath: "/run/firecracker.socket"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newUnixFirecrackerHTTP(test.socketPath, test.dialer); !errors.Is(err, ErrSmokeUnavailable) {
				t.Fatalf("newUnixFirecrackerHTTP() error = %v, want fail-closed refusal", err)
			}
		})
	}
}

func TestUnixFirecrackerHTTPRefusesUnknownRouteAndInvalidFixedBodiesBeforeDialing(t *testing.T) {
	dialer := &recordingUnixDialer{}
	port, err := newUnixFirecrackerHTTP("/run/firecracker.socket", dialer)
	if err != nil {
		t.Fatalf("newUnixFirecrackerHTTP() error = %v", err)
	}
	if err := port.Bind(context.Background(), "/run/firecracker.socket"); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	for _, call := range []struct {
		name string
		path string
		body any
	}{
		{name: "unknown route", path: "/network-interfaces/eth0", body: firecrackerAction{ActionType: "InstanceStart"}},
		{name: "machine SMT", path: "/machine-config", body: firecrackerMachineConfig{VCPUCount: 1, MemoryMiB: 256, SMT: true}},
		{name: "boot injection", path: "/boot-source", body: firecrackerBootSource{KernelImagePath: "/kernel/vmlinux", BootArgs: "console=ttyS0 reboot=k panic=1 init=/sbin/init -- sandbox-001 fixture-v1 extra"}},
		{name: "read-only root", path: "/drives/rootfs", body: firecrackerRootDrive{DriveID: "rootfs", PathOnHost: "/drives/rootfs.ext4", RootDevice: true, ReadOnly: true}},
		{name: "different CID", path: "/vsock", body: firecrackerVSock{GuestCID: defaultGuestCID + 1, UDSPath: "/run/firecracker.vsock"}},
		{name: "other action", path: "/actions", body: firecrackerAction{ActionType: "SendCtrlAltDel"}},
	} {
		t.Run(call.name, func(t *testing.T) {
			if err := port.Put(context.Background(), call.path, call.body); !errors.Is(err, ErrSmokeUnavailable) {
				t.Fatalf("Put(%s) error = %v, want fail-closed refusal", call.path, err)
			}
		})
	}
	if got := dialer.CallCount(); got != 0 {
		t.Fatalf("dial count = %d, want no dial", got)
	}
}

func TestUnixFirecrackerHTTPSolelyDialsTheBoundUnixSocket(t *testing.T) {
	directory, err := os.MkdirTemp(os.TempDir(), "fc-http-")
	if err != nil {
		t.Fatalf("make short socket directory: %v", err)
	}
	defer func() {
		if closeErr := os.RemoveAll(directory); closeErr != nil {
			t.Errorf("remove socket directory: %v", closeErr)
		}
	}()
	socketPath := filepath.Join(directory, "firecracker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on Firecracker socket: %v", err)
	}
	defer func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close socket listener: %v", closeErr)
		}
	}()
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })}
	go func() { _ = server.Serve(listener) }()
	defer func() {
		if closeErr := server.Close(); closeErr != nil {
			t.Errorf("close HTTP server: %v", closeErr)
		}
	}()
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:8080")
	dialer := &recordingUnixDialer{}
	port, err := newUnixFirecrackerHTTP(socketPath, dialer)
	if err != nil {
		t.Fatalf("newUnixFirecrackerHTTP() error = %v", err)
	}
	if err := port.Bind(context.Background(), socketPath); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := port.Put(context.Background(), "/actions", firecrackerAction{ActionType: "InstanceStart"}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if got, want := dialer.Calls(), []dialCall{{network: "unix", address: socketPath}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("dials = %#v, want %#v", got, want)
	}
}

func TestUnixFirecrackerHTTPRefusesOversizedErrorResponsesWithoutReturningTheirContents(t *testing.T) {
	directory, err := os.MkdirTemp(os.TempDir(), "fc-http-")
	if err != nil {
		t.Fatalf("make short socket directory: %v", err)
	}
	defer func() {
		if closeErr := os.RemoveAll(directory); closeErr != nil {
			t.Errorf("remove socket directory: %v", closeErr)
		}
	}()
	socketPath := filepath.Join(directory, "firecracker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on Firecracker socket: %v", err)
	}
	defer func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close socket listener: %v", closeErr)
		}
	}()
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(writer, strings.Repeat("server-secret", maximumFirecrackerAPIResponseBytes))
	})}
	go func() { _ = server.Serve(listener) }()
	defer func() {
		if closeErr := server.Close(); closeErr != nil {
			t.Errorf("close HTTP server: %v", closeErr)
		}
	}()
	port, err := newUnixFirecrackerHTTP(socketPath, &net.Dialer{})
	if err != nil {
		t.Fatalf("newUnixFirecrackerHTTP() error = %v", err)
	}
	if err := port.Bind(context.Background(), socketPath); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	err = port.Put(context.Background(), "/actions", firecrackerAction{ActionType: "InstanceStart"})
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("Put() error = %v, want bounded response refusal", err)
	}
	if strings.Contains(err.Error(), "server-secret") {
		t.Fatalf("Put() error disclosed server response: %v", err)
	}
}

func TestUnixFirecrackerHTTPFailsClosedOnANonSuccessfulStatusWithoutReturningItsBody(t *testing.T) {
	directory, err := os.MkdirTemp(os.TempDir(), "fc-http-")
	if err != nil {
		t.Fatalf("make short socket directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(directory) }()
	socketPath := filepath.Join(directory, "firecracker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on Firecracker socket: %v", err)
	}
	defer func() { _ = listener.Close() }()
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(writer, "private-server-detail")
	})}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()
	port, err := newUnixFirecrackerHTTP(socketPath, &net.Dialer{})
	if err != nil {
		t.Fatalf("newUnixFirecrackerHTTP() error = %v", err)
	}
	if err := port.Bind(context.Background(), socketPath); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	err = port.Put(context.Background(), "/actions", firecrackerAction{ActionType: "InstanceStart"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 409") {
		t.Fatalf("Put() error = %v, want safe non-success status", err)
	}
	if strings.Contains(err.Error(), "private-server-detail") {
		t.Fatalf("Put() error disclosed server response: %v", err)
	}
}

func TestUnixFirecrackerHTTPPropagatesCancellationDuringAnInFlightRequest(t *testing.T) {
	directory, err := os.MkdirTemp(os.TempDir(), "fc-http-")
	if err != nil {
		t.Fatalf("make short socket directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(directory) }()
	socketPath := filepath.Join(directory, "firecracker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on Firecracker socket: %v", err)
	}
	defer func() { _ = listener.Close() }()
	started := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
	})}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()
	port, err := newUnixFirecrackerHTTP(socketPath, &net.Dialer{})
	if err != nil {
		t.Fatalf("newUnixFirecrackerHTTP() error = %v", err)
	}
	if err := port.Bind(context.Background(), socketPath); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- port.Put(ctx, "/actions", firecrackerAction{ActionType: "InstanceStart"}) }()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Put() error = %v, want context cancellation", err)
	}
}

type dialCall struct {
	network string
	address string
}

type recordingUnixDialer struct {
	mu    sync.Mutex
	dial  net.Dialer
	calls []dialCall
}

func (dialer *recordingUnixDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer.mu.Lock()
	dialer.calls = append(dialer.calls, dialCall{network: network, address: address})
	dialer.mu.Unlock()
	return dialer.dial.DialContext(ctx, network, address)
}

func (dialer *recordingUnixDialer) CallCount() int {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	return len(dialer.calls)
}

func (dialer *recordingUnixDialer) Calls() []dialCall {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	return append([]dialCall(nil), dialer.calls...)
}
