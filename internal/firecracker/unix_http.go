package firecracker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
)

const maximumFirecrackerAPIResponseBytes = 64 << 10

type unixSocketDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// unixFirecrackerHTTP is the private, one-socket Firecracker REST adapter.
// It deliberately has no URL, proxy, redirect, or TCP configuration surface.
type unixFirecrackerHTTP struct {
	socketPath string
	dialer     unixSocketDialer

	mu    sync.Mutex
	bound bool
}

func newUnixFirecrackerHTTP(socketPath string, dialer unixSocketDialer) (*unixFirecrackerHTTP, error) {
	if !safeAbsolutePath(socketPath) || dialer == nil {
		return nil, fmt.Errorf("%w: canonical private API socket and Unix dialer are required", ErrSmokeUnavailable)
	}
	return &unixFirecrackerHTTP{socketPath: socketPath, dialer: dialer}, nil
}

func (port *unixFirecrackerHTTP) Bind(ctx context.Context, socketPath string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if port == nil || !safeAbsolutePath(socketPath) || socketPath != port.socketPath {
		return fmt.Errorf("%w: exact private Firecracker API socket is required", ErrSmokeUnavailable)
	}
	port.mu.Lock()
	defer port.mu.Unlock()
	if port.bound {
		return fmt.Errorf("%w: private Firecracker API socket is already bound", ErrSmokeUnavailable)
	}
	port.bound = true
	return nil
}

// WaitReady waits only for the exact bound private Unix socket to accept a
// connection. Jailer.Start returning does not imply Firecracker has created
// that socket yet. It uses the caller's bounded context and never sends an API
// request, so the immutable launch sequence still begins at machine-config.
func (port *unixFirecrackerHTTP) WaitReady(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if port == nil {
		return fmt.Errorf("%w: private Firecracker API socket is required", ErrSmokeUnavailable)
	}
	port.mu.Lock()
	bound, socketPath, dialer := port.bound, port.socketPath, port.dialer
	port.mu.Unlock()
	if !bound || !safeAbsolutePath(socketPath) || dialer == nil {
		return fmt.Errorf("%w: bound private Firecracker API socket is required", ErrSmokeUnavailable)
	}
	for {
		connection, err := dialer.DialContext(ctx, "unix", socketPath)
		if err == nil {
			closeErr := connection.Close()
			if closeErr != nil {
				return fmt.Errorf("close Firecracker API readiness connection: %w", closeErr)
			}
			return nil
		}
		if contextErr := contextError(ctx); contextErr != nil {
			return fmt.Errorf("%w: await private Firecracker API socket: %w", ErrSmokeUnavailable, contextErr)
		}
		// Socket creation is an event driven by the just-started Jailer. Yield
		// rather than introducing a wall-clock polling timer; the caller's
		// bounded context remains the sole deadline authority.
		runtime.Gosched()
	}
}

func (port *unixFirecrackerHTTP) Put(ctx context.Context, endpoint string, body any) (err error) {
	if err := contextError(ctx); err != nil {
		return err
	}
	if port == nil || !validFirecrackerAPIRequest(endpoint, body) {
		return fmt.Errorf("%w: fixed Firecracker API endpoint and body are required", ErrSmokeUnavailable)
	}
	port.mu.Lock()
	bound, socketPath, dialer := port.bound, port.socketPath, port.dialer
	port.mu.Unlock()
	if !bound {
		return fmt.Errorf("%w: private Firecracker API socket must be bound before requests", ErrSmokeUnavailable)
	}
	encoded, err := json.Marshal(body)
	if err != nil || len(encoded) > maximumFirecrackerAPIResponseBytes {
		return fmt.Errorf("%w: encode bounded Firecracker API request", ErrSmokeUnavailable)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://firecracker"+endpoint, strings.NewReader(string(encoded)))
	if err != nil {
		return fmt.Errorf("construct Firecracker API request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{
		Proxy:              nil,
		DisableCompression: true,
		DisableKeepAlives:  true,
		ForceAttemptHTTP2:  false,
		DialContext: func(callCtx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "firecracker:80" {
				return nil, fmt.Errorf("%w: Firecracker transport target is not fixed", ErrSmokeUnavailable)
			}
			return dialer.DialContext(callCtx, "unix", socketPath)
		},
	}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(request)
	if err != nil {
		return fmt.Errorf("call Firecracker API %s: %w", endpoint, err)
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close Firecracker API response %s: %w", endpoint, closeErr)
		}
	}()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maximumFirecrackerAPIResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read bounded Firecracker API response %s: %w", endpoint, err)
	}
	if len(responseBody) > maximumFirecrackerAPIResponseBytes {
		return fmt.Errorf("Firecracker API response exceeds %d bytes", maximumFirecrackerAPIResponseBytes)
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("Firecracker API %s returned HTTP %d", endpoint, response.StatusCode)
	}
	return nil
}

func validFirecrackerAPIRequest(endpoint string, body any) bool {
	switch endpoint {
	case "/machine-config":
		value, ok := body.(firecrackerMachineConfig)
		return ok && value.VCPUCount > 0 && value.MemoryMiB > 0 && !value.SMT
	case "/boot-source":
		value, ok := body.(firecrackerBootSource)
		return ok && safeAbsolutePath(value.KernelImagePath) && validFirecrackerBootArguments(value.BootArgs)
	case "/drives/rootfs":
		value, ok := body.(firecrackerRootDrive)
		return ok && value.DriveID == "rootfs" && safeAbsolutePath(value.PathOnHost) && value.RootDevice && !value.ReadOnly
	case "/vsock":
		value, ok := body.(firecrackerVSock)
		return ok && value.GuestCID == defaultGuestCID && safeAbsolutePath(value.UDSPath)
	case "/actions":
		value, ok := body.(firecrackerAction)
		return ok && value.ActionType == "InstanceStart"
	default:
		return false
	}
}

func validFirecrackerBootArguments(value string) bool {
	fields := strings.Fields(value)
	return len(fields) == 7 && fields[0] == "console=ttyS0" && fields[1] == "reboot=k" && fields[2] == "panic=1" && fields[3] == "init=/sbin/init" && fields[4] == "--" && validVMID(fields[5]) && validFixtureVersion(fields[6]) && strings.Join(fields, " ") == value
}
