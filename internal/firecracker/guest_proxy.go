package firecracker

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/0x63616c/agent-runtime/internal/sandboxauthority"
)

const (
	// GuestProxyOperationKind identifies the private, bounded AF_VSOCK proxy operation.
	GuestProxyOperationKind = "agent-runtime.guest-proxy/v1"
	maximumGuestProxyBytes  = 32 << 10
)

// GuestProxyPayload is the only bounded guest egress shape permitted inside a
// control-signed operation. It contains one lease-bound domain request and at
// most one finite byte sequence, not a guest-selected socket or tunnel.
type GuestProxyPayload struct {
	Version string                               `json:"version"`
	Request sandboxauthority.ProxySessionRequest `json:"request"`
	Input   []byte                               `json:"input"`
}

// DecodeGuestProxyPayload accepts only one canonical bounded proxy payload.
func DecodeGuestProxyPayload(payload []byte) (GuestProxyPayload, error) {
	if len(payload) == 0 || len(payload) > maximumGuestDispatchBytes {
		return GuestProxyPayload{}, fmt.Errorf("decode guest proxy payload: %w", ErrCapabilityUnavailable)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var proxy GuestProxyPayload
	if err := decoder.Decode(&proxy); err != nil {
		return GuestProxyPayload{}, fmt.Errorf("decode guest proxy payload: %w", ErrCapabilityUnavailable)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return GuestProxyPayload{}, fmt.Errorf("decode guest proxy payload: %w", ErrCapabilityUnavailable)
	}
	canonical, err := json.Marshal(proxy)
	if err != nil || !bytes.Equal(canonical, payload) || proxy.Version != GuestProxyOperationKind || len(proxy.Input) > maximumGuestProxyBytes || proxy.Request.SandboxID == "" || proxy.Request.ProcessID == "" || proxy.Request.OperationID == "" || proxy.Request.VMID == "" || proxy.Request.FencingToken == 0 {
		return GuestProxyPayload{}, fmt.Errorf("decode guest proxy payload: %w", ErrCapabilityUnavailable)
	}
	return proxy, nil
}

// EncodeGuestProxyOpen binds the guest's AF_VSOCK open frame to exactly the
// request that was already signed in its host-control operation.
func EncodeGuestProxyOpen(request sandboxauthority.ProxySessionRequest) ([]byte, error) {
	if request.SandboxID == "" || request.ProcessID == "" || request.OperationID == "" || request.VMID == "" || request.FencingToken == 0 {
		return nil, fmt.Errorf("encode guest proxy open: %w", ErrCapabilityUnavailable)
	}
	frame, err := json.Marshal(request)
	if err != nil || len(frame) > maximumGuestControlResponseBytes {
		return nil, fmt.Errorf("encode guest proxy open: %w", ErrCapabilityUnavailable)
	}
	return frame, nil
}

// DecodeGuestProxyOpen accepts only the canonical bounded request returned by
// the guest after it has decoded the authenticated host-control operation.
func DecodeGuestProxyOpen(frame []byte) (sandboxauthority.ProxySessionRequest, error) {
	if len(frame) == 0 || len(frame) > maximumGuestControlResponseBytes {
		return sandboxauthority.ProxySessionRequest{}, fmt.Errorf("decode guest proxy open: %w", ErrCapabilityUnavailable)
	}
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	var request sandboxauthority.ProxySessionRequest
	if err := decoder.Decode(&request); err != nil {
		return sandboxauthority.ProxySessionRequest{}, fmt.Errorf("decode guest proxy open: %w", ErrCapabilityUnavailable)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return sandboxauthority.ProxySessionRequest{}, fmt.Errorf("decode guest proxy open: %w", ErrCapabilityUnavailable)
	}
	canonical, err := json.Marshal(request)
	if err != nil || !bytes.Equal(canonical, frame) || request.SandboxID == "" || request.ProcessID == "" || request.OperationID == "" || request.VMID == "" || request.FencingToken == 0 {
		return sandboxauthority.ProxySessionRequest{}, fmt.Errorf("decode guest proxy open: %w", ErrCapabilityUnavailable)
	}
	return request, nil
}

func sameGuestProxyRequest(left, right sandboxauthority.ProxySessionRequest) bool {
	leftCanonical, leftErr := json.Marshal(left)
	rightCanonical, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftCanonical, rightCanonical)
}
