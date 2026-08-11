package sandboxbootprobehostprocess

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobeprotocol"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobev2"
	"github.com/cockroachdb/errors"
)

const protocolVersion = "sandbox.host-control/v2/firecracker-boot-probe"
const preparePath = "/sandbox.host-control/v2/firecracker-boot-probe/prepare"
const stageReadyPath = "/sandbox.host-control/v2/firecracker-boot-probe/stage-ready"

type prepareRequest struct {
	ProtocolVersion       string `json:"protocol_version"`
	Principal             string `json:"principal"`
	OperationID           string `json:"operation_id"`
	HostInstanceSessionID string `json:"host_instance_session_id"`
}

// Prepare requests one distinct persisted v2 prepared-session snapshot over
// the already-mutually-authenticated control transport. M4 owns post-stage
// authorization, journal, launch-started, and terminal-ACK recovery.
func Prepare(ctx context.Context, client *http.Client, origin, principal, operationID, instanceID string) (firecrackerbootprobev2.Snapshot, error) {
	return request(ctx, client, origin+preparePath, prepareRequest{protocolVersion, principal, operationID, instanceID})
}

// SubmitStageReady signs the locally compiled M4 stage with the distinct
// observation key, submits it to the private M3 route, and accepts a response
// only after its command signature and compiled identity have been verified.
// It does not journal, start, or report a Jailer launch.
func SubmitStageReady(ctx context.Context, client *http.Client, origin string, snapshot firecrackerbootprobev2.Snapshot, identity firecracker.TrustedM4Identity, guestNonce string, observationPrivateKey ed25519.PrivateKey, now time.Time, resolver firecrackerbootprobeprotocol.HostTrustResolver) (firecrackerbootprobeprotocol.VerifiedCommand, error) {
	verifier, err := firecracker.NewCompiledM4IdentityVerifier(identity)
	if err != nil {
		return firecrackerbootprobeprotocol.VerifiedCommand{}, errors.Wrap(err, "submit M4 stage-ready: seal compiled identity verifier")
	}
	stageReady, err := firecrackerbootprobeprotocol.SignStageReady(snapshot, identity, guestNonce, observationPrivateKey)
	if err != nil {
		return firecrackerbootprobeprotocol.VerifiedCommand{}, errors.Wrap(err, "submit M4 stage-ready: sign exact staged identity")
	}
	if ctx == nil || client == nil || resolver == nil || now.IsZero() || now.Location() != time.UTC {
		return firecrackerbootprobeprotocol.VerifiedCommand{}, errors.New("submit M4 stage-ready: context, client, resolver, and UTC time are required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+stageReadyPath, bytes.NewReader(stageReady))
	if err != nil {
		return firecrackerbootprobeprotocol.VerifiedCommand{}, errors.Wrap(err, "submit M4 stage-ready: construct control request")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return firecrackerbootprobeprotocol.VerifiedCommand{}, errors.Wrap(err, "submit M4 stage-ready: call control")
	}
	defer response.Body.Close()
	command, err := io.ReadAll(io.LimitReader(response.Body, 32<<10+1))
	if err != nil || len(command) > 32<<10 {
		return firecrackerbootprobeprotocol.VerifiedCommand{}, errors.New("submit M4 stage-ready: control command is unreadable or exceeds its bound")
	}
	if response.StatusCode != http.StatusOK {
		return firecrackerbootprobeprotocol.VerifiedCommand{}, errors.New("submit M4 stage-ready: control refused with status " + response.Status)
	}
	verified, err := firecrackerbootprobeprotocol.VerifyCommand(ctx, command, now, resolver, verifier)
	if err != nil {
		return firecrackerbootprobeprotocol.VerifiedCommand{}, errors.Wrap(err, "submit M4 stage-ready: verify returned command")
	}
	return verified, nil
}

func request(ctx context.Context, client *http.Client, target string, body any) (snapshot firecrackerbootprobev2.Snapshot, err error) {
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
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil && err == nil {
			err = errors.Wrap(closeErr, "close v2 boot-probe host response")
		}
	}()
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
