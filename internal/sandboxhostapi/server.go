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
	"github.com/0x63616c/agent-runtime/internal/sandboxcontrol"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/cockroachdb/errors"
)

const (
	pullPath      = "/sandbox.host-control/v1/pull"
	receiptPath   = "/sandbox.host-control/v1/receipt"
	heartbeatPath = "/sandbox.host-control/v1/heartbeat"
	outputPath    = "/sandbox.host-control/v1/output"
	resultPath    = "/sandbox.host-control/v1/result"
	maxBodyBytes  = 1 << 20
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
}

type server struct{ config Config }

type pullRequest struct {
	ProtocolVersion string `json:"protocol_version"`
	Kind            string `json:"kind"`
	HostID          string `json:"host_id"`
	HostGeneration  uint64 `json:"host_generation"`
}

type receiptRequest struct {
	ProtocolVersion string `json:"protocol_version"`
	Kind            string `json:"kind"`
	AssignmentID    string `json:"assignment_id"`
	FencingToken    uint64 `json:"fencing_token"`
	ReceiptDigest   string `json:"receipt_digest"`
}

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
	return secureHeaders(mux), nil
}

func (server *server) pull(writer http.ResponseWriter, request *http.Request) {
	identity, _, ok := server.authenticatePeer(writer, request)
	if !ok {
		return
	}
	var body pullRequest
	if !decodeCanonical(writer, request, &body) || body.ProtocolVersion != sandboxhostprotocol.Version || body.Kind != "pull" || body.HostID != identity.HostID || body.HostGeneration != identity.Generation {
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
	var body receiptRequest
	if !decodeCanonical(writer, request, &body) || body.ProtocolVersion != sandboxhostprotocol.Version || body.Kind != "receipt" {
		server.quarantine(request.Context(), identity, "invalid-receipt-envelope")
		writeDenied(writer)
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
	if !decodeCanonical(writer, request, &body) || body.ProtocolVersion != sandboxhostprotocol.Version || body.Kind != "heartbeat" {
		server.quarantine(request.Context(), identity, "invalid-heartbeat-envelope")
		writeDenied(writer)
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
	wire, ok := readBody(writer, request)
	if !ok {
		server.quarantine(request.Context(), identity, "invalid-result-envelope")
		return
	}
	now := server.config.Clock.Now().UTC()
	result, err := sandboxhostprotocol.VerifyResult(wire, now, enrollment.SigningPublicKey)
	if err != nil || result.HostID != identity.HostID || result.HostGeneration != identity.Generation {
		server.quarantine(request.Context(), identity, "invalid-result-signature")
		writeDenied(writer)
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
	wire, ok := readBody(writer, request)
	if !ok {
		server.quarantine(request.Context(), identity, "invalid-output-envelope")
		return
	}
	now := server.config.Clock.Now().UTC()
	output, err := sandboxhostprotocol.VerifyOutput(wire, now, enrollment.SigningPublicKey)
	if err != nil || output.HostID != identity.HostID || output.HostGeneration != identity.Generation {
		server.quarantine(request.Context(), identity, "invalid-output-signature")
		writeDenied(writer)
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
		server.quarantine(ctx, identity, reason)
		writeDenied(writer)
		return
	}
	writeStoreError(writer, err)
}

func (server *server) quarantine(ctx context.Context, identity sandboxcontrol.HostIdentity, reason string) {
	_, _ = server.config.Store.QuarantineHost(ctx, identity, reason, server.config.Clock.Now().UTC())
}

func decodeCanonical(writer http.ResponseWriter, request *http.Request, destination any) bool {
	wire, ok := readBody(writer, request)
	if !ok {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeDenied(writer)
		return false
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, wire) {
		writeDenied(writer)
		return false
	}
	return true
}

func readBody(writer http.ResponseWriter, request *http.Request) ([]byte, bool) {
	if request.Header.Get("Content-Type") != "application/json" {
		writeDenied(writer)
		return nil, false
	}
	wire, err := io.ReadAll(io.LimitReader(request.Body, maxBodyBytes+1))
	if err != nil || len(wire) == 0 || len(wire) > maxBodyBytes {
		writeDenied(writer)
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
