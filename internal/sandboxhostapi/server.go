// Package sandboxhostapi exposes the private mutually authenticated host
// control surface. It is not part of the public sandbox Go API.
package sandboxhostapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobev2"
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrol"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/cockroachdb/errors"
)

const (
	pullPath             = "/sandbox.host-control/v1/pull"
	receiptPath          = "/sandbox.host-control/v1/receipt"
	heartbeatPath        = "/sandbox.host-control/v1/heartbeat"
	outputPath           = "/sandbox.host-control/v1/output"
	resultPath           = "/sandbox.host-control/v1/result"
	bootProbePreparePath = "/sandbox.host-control/v2/firecracker-boot-probe/prepare"
	bootProbeStartedPath = "/sandbox.host-control/v2/firecracker-boot-probe/launch-started"
	maxBodyBytes         = 1 << 20
)

// Config contains explicit durable authority and signing material supplied by
// the control-process composition root.
type Config struct {
	Store             sandboxcontrol.HostControlStore
	ControlTrust      sandboxhostprotocol.TrustBundle
	ControlSigningKey ed25519.PrivateKey
	Entropy           io.Reader
	Clock             clock.Clock
	LeaseDuration     time.Duration
	BootProbeStore    *sandboxcontrol.PostgresLedger
}

type server struct{ config Config }

type heartbeatRequest struct {
	ProtocolVersion string `json:"protocol_version"`
	Kind            string `json:"kind"`
	AssignmentID    string `json:"assignment_id"`
	FencingToken    uint64 `json:"fencing_token"`
}

type acknowledgement struct {
	ProtocolVersion string `json:"protocol_version"`
	Kind            string `json:"kind"`
	Duplicate       bool   `json:"duplicate"`
}
type bootProbePrepareRequest struct {
	ProtocolVersion       string `json:"protocol_version"`
	Principal             string `json:"principal"`
	OperationID           string `json:"operation_id"`
	HostInstanceSessionID string `json:"host_instance_session_id"`
}
type bootProbeStartedRequest struct {
	ProtocolVersion       string `json:"protocol_version"`
	HostInstanceSessionID string `json:"host_instance_session_id"`
	Version               uint64 `json:"version"`
}

// NewHandler constructs the bounded host API without opening listeners or
// provisioning enrollment, database, certificates or signing keys.
func NewHandler(config Config) (http.Handler, error) {
	_, trustErr := sandboxhostprotocol.NewAtomicTrust(config.ControlTrust)
	if config.Store == nil || config.Entropy == nil || config.Clock == nil || trustErr != nil || len(config.ControlSigningKey) != ed25519.PrivateKeySize || !bytes.Equal(config.ControlSigningKey.Public().(ed25519.PublicKey), config.ControlTrust.Current.PublicKey) || config.LeaseDuration <= 0 || config.LeaseDuration > time.Hour {
		return nil, errors.New("construct sandbox host handler: explicit finite authority is required")
	}
	server := &server{config: config}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+pullPath, server.pull)
	mux.HandleFunc("POST "+receiptPath, server.receipt)
	mux.HandleFunc("POST "+heartbeatPath, server.heartbeat)
	mux.HandleFunc("POST "+outputPath, server.output)
	mux.HandleFunc("POST "+resultPath, server.result)
	if config.BootProbeStore != nil {
		mux.HandleFunc("POST "+bootProbePreparePath, server.bootProbePrepare)
		mux.HandleFunc("POST "+bootProbeStartedPath, server.bootProbeStarted)
	}
	return secureHeaders(mux), nil
}

func (server *server) bootProbePrepare(writer http.ResponseWriter, request *http.Request) {
	identity, _, ok := server.authenticatePeer(writer, request)
	if !ok {
		return
	}
	var body bootProbePrepareRequest
	if !decodeCanonical(request, &body) || body.ProtocolVersion != "sandbox.host-control/v2/firecracker-boot-probe" || !bounded(body.Principal, 512) || !bounded(body.OperationID, 128) || !bounded(body.HostInstanceSessionID, 128) {
		writeDenied(writer)
		return
	}
	now := server.config.Clock.Now().UTC()
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(server.config.Entropy, nonce); err != nil {
		writeUnavailable(writer)
		return
	}
	nonceText := base64.RawURLEncoding.EncodeToString(nonce)
	delivery := firecrackerbootprobev2.Delivery{EnvelopeID: "v2-" + hex.EncodeToString(nonce[:8]), DeliveryID: "v2-" + hex.EncodeToString(nonce[8:]), Nonce: nonceText, IssuedAt: now, ExpiresAt: now.Add(server.config.LeaseDuration)}
	// The ledger fills the lease and fence only from the locked operation; this
	// initial request cannot choose either authority value.
	op, err := server.config.BootProbeStore.Get(request.Context(), body.Principal, body.OperationID)
	if err != nil {
		writeDenied(writer)
		return
	}
	delivery.LeaseEpoch = op.Assignment.LeaseEpoch
	delivery.FencingToken = op.Assignment.FencingToken
	snapshot, _, err := server.config.BootProbeStore.CreateBootProbeSession(request.Context(), identity, body.Principal, body.OperationID, body.HostInstanceSessionID, delivery, now)
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	snapshot, err = server.config.BootProbeStore.AuthorizeBootProbeLaunch(request.Context(), identity, snapshot, now)
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, snapshot)
}

func (server *server) bootProbeStarted(writer http.ResponseWriter, request *http.Request) {
	identity, _, ok := server.authenticatePeer(writer, request)
	if !ok {
		return
	}
	var body bootProbeStartedRequest
	if !decodeCanonical(request, &body) || body.ProtocolVersion != "sandbox.host-control/v2/firecracker-boot-probe" || !bounded(body.HostInstanceSessionID, 128) || body.Version == 0 {
		writeDenied(writer)
		return
	}
	now := server.config.Clock.Now().UTC()
	snapshot, err := server.config.BootProbeStore.LoadBootProbeSession(request.Context(), body.HostInstanceSessionID)
	if err != nil {
		writeDenied(writer)
		return
	}
	if snapshot.Version != body.Version {
		snapshot, err = server.config.BootProbeStore.RecoverBootProbeLaunchStarted(request.Context(), identity, body.HostInstanceSessionID, body.Version, now)
	} else {
		snapshot, err = server.config.BootProbeStore.RecordBootProbeLaunchStarted(request.Context(), identity, snapshot, now)
	}
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, snapshot)
}

func (server *server) pull(writer http.ResponseWriter, request *http.Request) {
	identity, _, ok := server.authenticatePeer(writer, request)
	if !ok {
		return
	}
	var body sandboxhostprotocol.PullRequest
	if !decodeCanonical(request, &body) || body.ProtocolVersion != sandboxhostprotocol.Version || body.Kind != "pull" || body.HostID != identity.HostID || body.HostGeneration != identity.Generation {
		writeDenied(writer)
		return
	}
	now := server.config.Clock.Now().UTC()
	seed, err := server.deliverySeed(true)
	if err != nil {
		writeUnavailable(writer)
		return
	}
	dispatch, err := server.config.Store.PullHostAssignment(request.Context(), identity, now, now.Add(server.config.LeaseDuration), seed, server.sign)
	if errors.Is(err, sandboxcontrol.ErrNoHostAssignment) {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeStoreError(writer, err)
		return
	}
	writeWire(writer, dispatch.Envelope)
}

func (server *server) receipt(writer http.ResponseWriter, request *http.Request) {
	identity, _, ok := server.authenticatePeer(writer, request)
	if !ok {
		return
	}
	var body sandboxhostprotocol.ReceiptRequest
	if !decodeCanonical(request, &body) || body.ProtocolVersion != sandboxhostprotocol.Version || body.Kind != "receipt" {
		server.denyWithQuarantine(writer, request.Context(), identity, "invalid-receipt-envelope")
		return
	}
	duplicate, err := server.config.Store.AcknowledgeHostAssignment(request.Context(), identity, body.AssignmentID, body.FencingToken, body.ReceiptDigest, server.config.Clock.Now().UTC())
	if err != nil {
		server.protocolStoreError(writer, request.Context(), identity, err, "invalid-receipt-binding")
		return
	}
	writeJSON(writer, http.StatusOK, acknowledgement{ProtocolVersion: sandboxhostprotocol.Version, Kind: "receipt-ack", Duplicate: duplicate})
}

func (server *server) heartbeat(writer http.ResponseWriter, request *http.Request) {
	identity, _, ok := server.authenticatePeer(writer, request)
	if !ok {
		return
	}
	var body heartbeatRequest
	if !decodeCanonical(request, &body) || body.ProtocolVersion != sandboxhostprotocol.Version || body.Kind != "heartbeat" {
		server.denyWithQuarantine(writer, request.Context(), identity, "invalid-heartbeat-envelope")
		return
	}
	now := server.config.Clock.Now().UTC()
	seed, err := server.deliverySeed(false)
	if err != nil {
		writeUnavailable(writer)
		return
	}
	dispatch, err := server.config.Store.RenewHostAssignment(request.Context(), identity, body.AssignmentID, body.FencingToken, now, now.Add(server.config.LeaseDuration), seed, server.sign)
	if err != nil {
		server.protocolStoreError(writer, request.Context(), identity, err, "invalid-heartbeat-binding")
		return
	}
	writeWire(writer, dispatch.Envelope)
}

func (server *server) result(writer http.ResponseWriter, request *http.Request) {
	identity, enrollment, ok := server.authenticatePeer(writer, request)
	if !ok {
		return
	}
	wire, ok := readBody(request)
	if !ok {
		server.denyWithQuarantine(writer, request.Context(), identity, "invalid-result-envelope")
		return
	}
	now := server.config.Clock.Now().UTC()
	result, err := sandboxhostprotocol.VerifyResult(wire, now, enrollment.SigningPublicKey)
	if err != nil || result.HostID != identity.HostID || result.HostGeneration != identity.Generation {
		server.denyWithQuarantine(writer, request.Context(), identity, "invalid-result-signature")
		return
	}
	if _, err := server.config.Store.RecordAuthenticatedHostResult(request.Context(), identity, result, now); err != nil {
		server.protocolStoreError(writer, request.Context(), identity, err, "invalid-result-binding")
		return
	}
	writeJSON(writer, http.StatusOK, acknowledgement{ProtocolVersion: sandboxhostprotocol.Version, Kind: "result-ack"})
}

func (server *server) output(writer http.ResponseWriter, request *http.Request) {
	identity, enrollment, ok := server.authenticatePeer(writer, request)
	if !ok {
		return
	}
	wire, ok := readBody(request)
	if !ok {
		server.denyWithQuarantine(writer, request.Context(), identity, "invalid-output-envelope")
		return
	}
	now := server.config.Clock.Now().UTC()
	output, err := sandboxhostprotocol.VerifyOutput(wire, now, enrollment.SigningPublicKey)
	if err != nil || output.HostID != identity.HostID || output.HostGeneration != identity.Generation {
		server.denyWithQuarantine(writer, request.Context(), identity, "invalid-output-signature")
		return
	}
	duplicate, err := server.config.Store.RecordAuthenticatedHostOutput(request.Context(), identity, output, now)
	if err != nil {
		server.protocolStoreError(writer, request.Context(), identity, err, "invalid-output-sequence")
		return
	}
	writeJSON(writer, http.StatusOK, acknowledgement{ProtocolVersion: sandboxhostprotocol.Version, Kind: "output-ack", Duplicate: duplicate})
}

func (server *server) authenticatePeer(writer http.ResponseWriter, request *http.Request) (sandboxcontrol.HostIdentity, sandboxcontrol.HostEnrollment, bool) {
	identity, err := peerIdentity(request)
	if err != nil {
		writeDenied(writer)
		return sandboxcontrol.HostIdentity{}, sandboxcontrol.HostEnrollment{}, false
	}
	host, err := server.config.Store.AuthenticateHost(request.Context(), identity, server.config.Clock.Now().UTC())
	if err != nil {
		writeDenied(writer)
		return sandboxcontrol.HostIdentity{}, sandboxcontrol.HostEnrollment{}, false
	}
	return identity, host, true
}

func peerIdentity(request *http.Request) (sandboxcontrol.HostIdentity, error) {
	if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return sandboxcontrol.HostIdentity{}, errors.New("sandbox host peer is not mutually authenticated")
	}
	certificate := request.TLS.VerifiedChains[0][0]
	if len(certificate.URIs) != 1 || certificate.URIs[0].Scheme != "spiffe" || certificate.URIs[0].Host != "agent-runtime" {
		return sandboxcontrol.HostIdentity{}, errors.New("sandbox host peer identity is invalid")
	}
	parts := strings.Split(strings.Trim(certificate.URIs[0].Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "sandbox-host" || parts[2] != "generation" || !bounded(parts[1], 128) {
		return sandboxcontrol.HostIdentity{}, errors.New("sandbox host peer identity is invalid")
	}
	generation, err := strconv.ParseUint(parts[3], 10, 64)
	if err != nil || generation == 0 {
		return sandboxcontrol.HostIdentity{}, errors.New("sandbox host peer generation is invalid")
	}
	digest := sha256.Sum256(certificate.Raw)
	return sandboxcontrol.HostIdentity{HostID: parts[1], Generation: generation, CertificateDigest: "sha256:" + hex.EncodeToString(digest[:])}, nil
}

func (server *server) deliverySeed(includeAssignment bool) (sandboxcontrol.DeliverySeed, error) {
	identities := make([]string, 4)
	for index := range identities {
		buffer := make([]byte, 18)
		if _, err := io.ReadFull(server.config.Entropy, buffer); err != nil {
			return sandboxcontrol.DeliverySeed{}, errors.Wrap(err, "generate host delivery identity")
		}
		identities[index] = base64.RawURLEncoding.EncodeToString(buffer)
	}
	seed := sandboxcontrol.DeliverySeed{EnvelopeID: "envelope_" + identities[1], DeliveryID: "delivery_" + identities[2], Nonce: "nonce_" + identities[3]}
	if includeAssignment {
		seed.AssignmentID = "assignment_" + identities[0]
	}
	return seed, nil
}

func (server *server) sign(envelope sandboxhostprotocol.Envelope) ([]byte, error) {
	return sandboxhostprotocol.SignEnvelopeWithTrust(envelope, server.config.ControlTrust, server.config.ControlSigningKey)
}

func (server *server) protocolStoreError(writer http.ResponseWriter, ctx context.Context, identity sandboxcontrol.HostIdentity, err error, reason string) {
	if errors.Is(err, sandboxcontrol.ErrStaleFence) || errors.Is(err, sandboxcontrol.ErrHostProtocolViolation) || errors.Is(err, sandboxcontrol.ErrInvalidTransition) {
		if err := server.quarantine(ctx, identity, reason); err != nil {
			writeStoreError(writer, err)
			return
		}
		writeDenied(writer)
		return
	}
	writeStoreError(writer, err)
}

func (server *server) denyWithQuarantine(writer http.ResponseWriter, ctx context.Context, identity sandboxcontrol.HostIdentity, reason string) {
	if err := server.quarantine(ctx, identity, reason); err != nil {
		writeStoreError(writer, err)
		return
	}
	writeDenied(writer)
}

func (server *server) quarantine(ctx context.Context, identity sandboxcontrol.HostIdentity, reason string) error {
	_, err := server.config.Store.QuarantineHost(ctx, identity, reason, server.config.Clock.Now().UTC())
	return err
}

func decodeCanonical(request *http.Request, destination any) bool {
	wire, ok := readBody(request)
	if !ok {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return false
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, wire) {
		return false
	}
	return true
}

func readBody(request *http.Request) ([]byte, bool) {
	if request.Header.Get("Content-Type") != "application/json" {
		return nil, false
	}
	wire, err := io.ReadAll(io.LimitReader(request.Body, maxBodyBytes+1))
	if err != nil || len(wire) == 0 || len(wire) > maxBodyBytes {
		return nil, false
	}
	return wire, true
}

func writeWire(writer http.ResponseWriter, wire []byte) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(wire)
}

func writeJSON(writer http.ResponseWriter, status int, body any) {
	wire, err := json.Marshal(body)
	if err != nil {
		writeUnavailable(writer)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(wire)
}

func writeStoreError(writer http.ResponseWriter, err error) {
	if errors.Is(err, sandboxcontrol.ErrHostDenied) || errors.Is(err, sandboxcontrol.ErrStaleFence) || errors.Is(err, sandboxcontrol.ErrHostProtocolViolation) {
		writeDenied(writer)
		return
	}
	writeUnavailable(writer)
}

func writeDenied(writer http.ResponseWriter)      { writer.WriteHeader(http.StatusForbidden) }
func writeUnavailable(writer http.ResponseWriter) { writer.WriteHeader(http.StatusServiceUnavailable) }

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(writer, request)
	})
}

func bounded(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsRune(value, '\x00')
}
