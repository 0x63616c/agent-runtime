package sandboxbootprobehostprocess

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobev2"
	"github.com/cockroachdb/errors"
	"io"
	"net/http"
)

const protocolVersion = "sandbox.host-control/v2/firecracker-boot-probe"
const preparePath = "/sandbox.host-control/v2/firecracker-boot-probe/prepare"
const startedPath = "/sandbox.host-control/v2/firecracker-boot-probe/launch-started"

type prepareRequest struct {
	ProtocolVersion       string `json:"protocol_version"`
	Principal             string `json:"principal"`
	OperationID           string `json:"operation_id"`
	HostInstanceSessionID string `json:"host_instance_session_id"`
}
type startedRequest struct {
	ProtocolVersion       string `json:"protocol_version"`
	HostInstanceSessionID string `json:"host_instance_session_id"`
	Version               uint64 `json:"version"`
}

// Prepare requests one distinct persisted v2 launch authorization over the
// already-mutually-authenticated control transport.
func Prepare(ctx context.Context, client *http.Client, origin, principal, operationID, instanceID string) (firecrackerbootprobev2.Snapshot, error) {
	return request(ctx, client, origin+preparePath, prepareRequest{protocolVersion, principal, operationID, instanceID})
}

// LaunchStarted submits only the exact durable host-instance snapshot version.
func LaunchStarted(ctx context.Context, client *http.Client, origin string, s firecrackerbootprobev2.Snapshot) (firecrackerbootprobev2.Snapshot, error) {
	return request(ctx, client, origin+startedPath, startedRequest{protocolVersion, s.Session.Delivery.HostInstanceSessionID, s.Version})
}
func request(ctx context.Context, client *http.Client, target string, body any) (firecrackerbootprobev2.Snapshot, error) {
	if ctx == nil || client == nil {
		return firecrackerbootprobev2.Snapshot{}, errors.New("v2 boot-probe host request: context and client required")
	}
	wire, err := json.Marshal(body)
	if err != nil {
		return firecrackerbootprobev2.Snapshot{}, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(wire))
	if err != nil {
		return firecrackerbootprobev2.Snapshot{}, err
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if err != nil {
		return firecrackerbootprobev2.Snapshot{}, err
	}
	defer response.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil {
		return firecrackerbootprobev2.Snapshot{}, errors.New("v2 boot-probe host request: control response unreadable")
	}
	if response.StatusCode != http.StatusOK {
		return firecrackerbootprobev2.Snapshot{}, errors.New("v2 boot-probe host request: control refused with status " + response.Status)
	}
	var s firecrackerbootprobev2.Snapshot
	if json.Unmarshal(reply, &s) != nil || s.Session.Validate() != nil {
		return firecrackerbootprobev2.Snapshot{}, errors.New("v2 boot-probe host request: invalid control snapshot")
	}
	canonical, _ := json.Marshal(s)
	if !bytes.Equal(reply, canonical) {
		return firecrackerbootprobev2.Snapshot{}, errors.New("v2 boot-probe host request: non-canonical control snapshot")
	}
	return s, nil
}
