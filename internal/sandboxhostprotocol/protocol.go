// Package sandboxhostprotocol owns the private, bounded host-control wire
// contract. Public sandbox consumers never see host identities or envelopes.
package sandboxhostprotocol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
)

const (
	// Version is the only currently accepted host-control protocol.
	Version       = "sandbox.host-control/v1"
	maxWireBytes  = 1 << 20
	maxPayloadLen = 768 << 10
)

// PullRequest is the canonical private host poll request accepted by control.
type PullRequest struct {
	ProtocolVersion string `json:"protocol_version"`
	Kind            string `json:"kind"`
	HostID          string `json:"host_id"`
	HostGeneration  uint64 `json:"host_generation"`
}

// ReceiptRequest is the canonical private host receipt acknowledgement.
type ReceiptRequest struct {
	ProtocolVersion string `json:"protocol_version"`
	Kind            string `json:"kind"`
	AssignmentID    string `json:"assignment_id"`
	FencingToken    uint64 `json:"fencing_token"`
	ReceiptDigest   string `json:"receipt_digest"`
}

// Envelope is one immutable, control-signed assignment delivery.
type Envelope struct {
	ProtocolVersion        string    `json:"protocol_version"`
	EnvelopeID             string    `json:"envelope_id"`
	DeliveryID             string    `json:"delivery_id"`
	Nonce                  string    `json:"nonce"`
	IssuedAt               time.Time `json:"issued_at"`
	ExpiresAt              time.Time `json:"expires_at"`
	ControlKeyID           string    `json:"control_key_id"`
	ControlKeyVersion      uint64    `json:"control_key_version"`
	ControlRevocationEpoch uint64    `json:"control_revocation_epoch"`
	HostID                 string    `json:"host_id"`
	HostGeneration         uint64    `json:"host_generation"`
	AssignmentID           string    `json:"assignment_id"`
	LeaseEpoch             uint64    `json:"lease_epoch"`
	FencingToken           uint64    `json:"fencing_token"`
	Tenant                 string    `json:"tenant"`
	Principal              string    `json:"principal"`
	SandboxID              string    `json:"sandbox_id"`
	ProcessID              string    `json:"process_id"`
	OperationID            string    `json:"operation_id"`
	OperationKind          string    `json:"operation_kind"`
	EffectiveSpecDigest    string    `json:"effective_spec_digest"`
	CapabilityDigest       string    `json:"capability_digest"`
	CanonicalRequestDigest string    `json:"canonical_request_digest"`
	SequenceContract       string    `json:"sequence_contract"`
	PayloadDigest          string    `json:"payload_digest"`
	Payload                []byte    `json:"payload"`
	Signature              string    `json:"signature"`
}

// Result is one host-signed terminal or progress observation.
type Result struct {
	ProtocolVersion     string    `json:"protocol_version"`
	ResultID            string    `json:"result_id"`
	HostID              string    `json:"host_id"`
	HostGeneration      uint64    `json:"host_generation"`
	AssignmentID        string    `json:"assignment_id"`
	LeaseEpoch          uint64    `json:"lease_epoch"`
	FencingToken        uint64    `json:"fencing_token"`
	Principal           string    `json:"principal"`
	OperationID         string    `json:"operation_id"`
	EffectiveSpecDigest string    `json:"effective_spec_digest"`
	CapabilityDigest    string    `json:"capability_digest"`
	State               string    `json:"state"`
	ObservedAt          time.Time `json:"observed_at"`
	Signature           string    `json:"signature"`
}

// Output is one host-signed bounded output sequence header. Chunk content is
// stored by the output owner; this protocol binds only its integrity metadata.
type Output struct {
	ProtocolVersion string    `json:"protocol_version"`
	OutputID        string    `json:"output_id"`
	HostID          string    `json:"host_id"`
	HostGeneration  uint64    `json:"host_generation"`
	AssignmentID    string    `json:"assignment_id"`
	LeaseEpoch      uint64    `json:"lease_epoch"`
	FencingToken    uint64    `json:"fencing_token"`
	Principal       string    `json:"principal"`
	OperationID     string    `json:"operation_id"`
	Stream          string    `json:"stream"`
	Sequence        uint64    `json:"sequence"`
	ChunkDigest     string    `json:"chunk_digest"`
	SizeBytes       uint32    `json:"size_bytes"`
	ObservedAt      time.Time `json:"observed_at"`
	Signature       string    `json:"signature"`
}

// DataPlaneReceipt is one host-signed, reference-only terminal observation
// owned by private control. It carries only the digest of the private canonical
// metadata; the metadata stays in the host journal and never crosses control.
type DataPlaneReceipt struct {
	ProtocolVersion string `json:"protocol_version"`
	ReceiptID       string `json:"receipt_id"`
	HostID          string `json:"host_id"`
	HostGeneration  uint64 `json:"host_generation"`
	AssignmentID    string `json:"assignment_id"`
	LeaseEpoch      uint64 `json:"lease_epoch"`
	FencingToken    uint64 `json:"fencing_token"`
	OperationID     string `json:"operation_id"`
	Kind            string `json:"kind"`
	ReceiptDigest   string `json:"receipt_digest"`
	Signature       string `json:"signature"`
}

// GuestOutput is one bounded guest chunk before the host signs and durably
// acknowledges its public-control metadata.
type GuestOutput struct {
	Stream   string
	Sequence uint64
	Data     []byte
}

// GuestOutputEmitter accepts one guest chunk at the host-control durability boundary.
type GuestOutputEmitter func(context.Context, GuestOutput) error

// SignEnvelope returns exact canonical bytes with an Ed25519 signature over
// the same object with Signature omitted.
func SignEnvelope(envelope Envelope, keyID string, privateKey ed25519.PrivateKey) ([]byte, error) {
	envelope.ControlKeyID = keyID
	envelope.Signature = ""
	if !validEnvelope(envelope) || len(privateKey) != ed25519.PrivateKeySize || !boundedID(keyID, 128) {
		return nil, errors.New("sign host envelope: invalid bounded envelope or key")
	}
	unsigned, err := json.Marshal(envelope)
	if err != nil {
		return nil, errors.Wrap(err, "sign host envelope")
	}
	envelope.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, unsigned))
	return encodeSignedEnvelope(envelope)
}

// VerifyEnvelope strictly decodes canonical bytes and verifies key, host,
// generation, validity interval, payload digest and Ed25519 signature.
func VerifyEnvelope(wire []byte, hostID string, generation uint64, now time.Time, keys map[string]ed25519.PublicKey) (Envelope, error) {
	if len(wire) == 0 || len(wire) > maxWireBytes || now.IsZero() {
		return Envelope{}, errors.New("verify host envelope: invalid bounded input")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var envelope Envelope
	if err := decoder.Decode(&envelope); err != nil {
		return Envelope{}, errors.New("verify host envelope: invalid wire")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Envelope{}, errors.New("verify host envelope: invalid trailing wire")
	}
	canonical, err := encodeSignedEnvelope(envelope)
	if err != nil || !bytes.Equal(canonical, wire) || !validEnvelope(envelope) || envelope.HostID != hostID || envelope.HostGeneration != generation || now.Before(envelope.IssuedAt) || !now.Before(envelope.ExpiresAt) {
		return Envelope{}, errors.New("verify host envelope: refused")
	}
	publicKey := keys[envelope.ControlKeyID]
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return Envelope{}, errors.New("verify host envelope: refused")
	}
	unsigned := envelope
	unsigned.Signature = ""
	unsignedBytes, err := json.Marshal(unsigned)
	if err != nil || !ed25519.Verify(publicKey, unsignedBytes, signature) {
		return Envelope{}, errors.New("verify host envelope: refused")
	}
	return envelope, nil
}

// ValidateAuthenticatedEnvelopeWire proves that a downstream private hop was
// given the same canonical signed envelope which its caller already verified.
// It deliberately does not re-verify the signature (the caller owns trust
// keys); it prevents a verified envelope object from being rebound to another
// wire before a host-specific data plane consumes it.
func ValidateAuthenticatedEnvelopeWire(wire []byte, expected Envelope) error {
	if len(wire) == 0 || len(wire) > maxWireBytes || !validEnvelope(expected) {
		return errors.New("validate authenticated host envelope: refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var observed Envelope
	if err := decoder.Decode(&observed); err != nil {
		return errors.New("validate authenticated host envelope: refused")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("validate authenticated host envelope: refused")
	}
	canonical, err := encodeSignedEnvelope(observed)
	expectedWire, expectedErr := encodeSignedEnvelope(expected)
	if err != nil || expectedErr != nil || !bytes.Equal(canonical, wire) || !bytes.Equal(expectedWire, wire) {
		return errors.New("validate authenticated host envelope: refused")
	}
	return nil
}

// SignResult returns exact canonical host-signed result bytes.
func SignResult(result Result, privateKey ed25519.PrivateKey) ([]byte, error) {
	result.Signature = ""
	if !validResult(result) || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("sign host result: invalid bounded result or key")
	}
	unsigned, err := json.Marshal(result)
	if err != nil {
		return nil, errors.Wrap(err, "sign host result")
	}
	result.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, unsigned))
	return encodeSignedResult(result)
}

// VerifyResult strictly verifies canonical result bytes and the enrolled host
// signing key. Durable assignment checks remain control-store authority.
func VerifyResult(wire []byte, now time.Time, publicKey ed25519.PublicKey) (Result, error) {
	if len(wire) == 0 || len(wire) > maxWireBytes || now.IsZero() {
		return Result{}, errors.New("verify host result: invalid bounded input")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var result Result
	if err := decoder.Decode(&result); err != nil {
		return Result{}, errors.New("verify host result: invalid wire")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Result{}, errors.New("verify host result: invalid trailing wire")
	}
	canonical, err := encodeSignedResult(result)
	if err != nil || !bytes.Equal(canonical, wire) || !validResult(result) || result.ObservedAt.After(now) {
		return Result{}, errors.New("verify host result: refused")
	}
	signature, err := base64.RawURLEncoding.DecodeString(result.Signature)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return Result{}, errors.New("verify host result: refused")
	}
	unsigned := result
	unsigned.Signature = ""
	unsignedBytes, err := json.Marshal(unsigned)
	if err != nil || !ed25519.Verify(publicKey, unsignedBytes, signature) {
		return Result{}, errors.New("verify host result: refused")
	}
	return result, nil
}

// SignOutput returns exact canonical host-signed output-header bytes.
func SignOutput(output Output, privateKey ed25519.PrivateKey) ([]byte, error) {
	output.Signature = ""
	if !validOutput(output) || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("sign host output: invalid bounded output or key")
	}
	unsigned, err := json.Marshal(output)
	if err != nil {
		return nil, errors.Wrap(err, "sign host output")
	}
	output.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, unsigned))
	return encodeSignedOutput(output)
}

// VerifyOutput strictly verifies canonical output metadata and its enrolled
// host signature. Durable sequence ownership remains in the control store.
func VerifyOutput(wire []byte, now time.Time, publicKey ed25519.PublicKey) (Output, error) {
	if len(wire) == 0 || len(wire) > maxWireBytes || now.IsZero() {
		return Output{}, errors.New("verify host output: invalid bounded input")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var output Output
	if err := decoder.Decode(&output); err != nil {
		return Output{}, errors.New("verify host output: invalid wire")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Output{}, errors.New("verify host output: invalid trailing wire")
	}
	canonical, err := encodeSignedOutput(output)
	if err != nil || !bytes.Equal(canonical, wire) || !validOutput(output) || output.ObservedAt.After(now) {
		return Output{}, errors.New("verify host output: refused")
	}
	signature, err := base64.RawURLEncoding.DecodeString(output.Signature)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return Output{}, errors.New("verify host output: refused")
	}
	unsigned := output
	unsigned.Signature = ""
	unsignedBytes, err := json.Marshal(unsigned)
	if err != nil || !ed25519.Verify(publicKey, unsignedBytes, signature) {
		return Output{}, errors.New("verify host output: refused")
	}
	return output, nil
}

// Digest returns the canonical SHA-256 identity for bounded bytes.
func Digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SignDataPlaneReceipt signs one exact canonical reference-only receipt.
func SignDataPlaneReceipt(receipt DataPlaneReceipt, privateKey ed25519.PrivateKey) ([]byte, error) {
	receipt.Signature = ""
	if !validDataPlaneReceipt(receipt) || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("sign host data-plane receipt: invalid bounded receipt or key")
	}
	unsigned, err := json.Marshal(receipt)
	if err != nil {
		return nil, errors.Wrap(err, "sign host data-plane receipt")
	}
	receipt.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, unsigned))
	return encodeSignedDataPlaneReceipt(receipt)
}

// VerifyDataPlaneReceipt strictly verifies one canonical host-signed terminal
// receipt. Callers must additionally bind it to their enrolled host identity.
func VerifyDataPlaneReceipt(wire []byte, publicKey ed25519.PublicKey) (DataPlaneReceipt, error) {
	if len(wire) == 0 || len(wire) > maxWireBytes {
		return DataPlaneReceipt{}, errors.New("verify host data-plane receipt: invalid bounded input")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var receipt DataPlaneReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return DataPlaneReceipt{}, errors.New("verify host data-plane receipt: invalid wire")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return DataPlaneReceipt{}, errors.New("verify host data-plane receipt: invalid trailing wire")
	}
	canonical, err := encodeSignedDataPlaneReceipt(receipt)
	if err != nil || !bytes.Equal(canonical, wire) || !validDataPlaneReceipt(receipt) {
		return DataPlaneReceipt{}, errors.New("verify host data-plane receipt: refused")
	}
	signature, err := base64.RawURLEncoding.DecodeString(receipt.Signature)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return DataPlaneReceipt{}, errors.New("verify host data-plane receipt: refused")
	}
	unsigned := receipt
	unsigned.Signature = ""
	unsignedWire, err := json.Marshal(unsigned)
	if err != nil || !ed25519.Verify(publicKey, unsignedWire, signature) {
		return DataPlaneReceipt{}, errors.New("verify host data-plane receipt: refused")
	}
	return receipt, nil
}

func encodeSignedEnvelope(envelope Envelope) ([]byte, error) {
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) > maxWireBytes {
		return nil, errors.New("encode host envelope: exceeds bounded canonical wire")
	}
	return encoded, nil
}

func encodeSignedResult(result Result) ([]byte, error) {
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > maxWireBytes {
		return nil, errors.New("encode host result: exceeds bounded canonical wire")
	}
	return encoded, nil
}

func encodeSignedOutput(output Output) ([]byte, error) {
	encoded, err := json.Marshal(output)
	if err != nil || len(encoded) > maxWireBytes {
		return nil, errors.New("encode host output: exceeds bounded canonical wire")
	}
	return encoded, nil
}

func encodeSignedDataPlaneReceipt(receipt DataPlaneReceipt) ([]byte, error) {
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded) > maxWireBytes {
		return nil, errors.New("encode host data-plane receipt: exceeds bounded canonical wire")
	}
	return encoded, nil
}

func validEnvelope(envelope Envelope) bool {
	return envelope.ProtocolVersion == Version && boundedID(envelope.EnvelopeID, 128) && boundedID(envelope.DeliveryID, 128) && boundedID(envelope.Nonce, 128) && !envelope.IssuedAt.IsZero() && envelope.IssuedAt.Location() == time.UTC && envelope.ExpiresAt.Location() == time.UTC && envelope.ExpiresAt.After(envelope.IssuedAt) && envelope.ExpiresAt.Sub(envelope.IssuedAt) <= time.Hour && validControlKeyBinding(envelope) && boundedID(envelope.HostID, 128) && envelope.HostGeneration > 0 && boundedID(envelope.AssignmentID, 128) && envelope.LeaseEpoch > 0 && envelope.FencingToken > 0 && boundedID(envelope.Tenant, 256) && boundedID(envelope.Principal, 512) && strings.HasPrefix(envelope.Principal, envelope.Tenant+":") && boundedID(envelope.OperationID, 128) && boundedID(envelope.OperationKind, 64) && validDigest(envelope.EffectiveSpecDigest) && validDigest(envelope.CapabilityDigest) && validDigest(envelope.CanonicalRequestDigest) && envelope.SequenceContract == "host-proposed/control-owned-v1" && validDigest(envelope.PayloadDigest) && len(envelope.Payload) > 0 && len(envelope.Payload) <= maxPayloadLen && Digest(envelope.Payload) == envelope.PayloadDigest && (envelope.Signature == "" || len(envelope.Signature) <= 128)
}

func validControlKeyBinding(envelope Envelope) bool {
	if !boundedID(envelope.ControlKeyID, 128) {
		return false
	}
	return (envelope.ControlKeyVersion == 0 && envelope.ControlRevocationEpoch == 0) || (envelope.ControlKeyVersion > 0 && envelope.ControlRevocationEpoch > 0)
}

func validResult(result Result) bool {
	switch result.State {
	case "started", "succeeded", "failed", "uncertain":
	default:
		return false
	}
	return result.ProtocolVersion == Version && boundedID(result.ResultID, 128) && boundedID(result.HostID, 128) && result.HostGeneration > 0 && boundedID(result.AssignmentID, 128) && result.LeaseEpoch > 0 && result.FencingToken > 0 && boundedID(result.Principal, 512) && boundedID(result.OperationID, 128) && validDigest(result.EffectiveSpecDigest) && validDigest(result.CapabilityDigest) && !result.ObservedAt.IsZero() && result.ObservedAt.Location() == time.UTC && (result.Signature == "" || len(result.Signature) <= 128)
}

func validOutput(output Output) bool {
	return output.ProtocolVersion == Version && boundedID(output.OutputID, 128) && boundedID(output.HostID, 128) && output.HostGeneration > 0 && boundedID(output.AssignmentID, 128) && output.LeaseEpoch > 0 && output.FencingToken > 0 && boundedID(output.Principal, 512) && boundedID(output.OperationID, 128) && (output.Stream == "stdout" || output.Stream == "stderr") && output.Sequence > 0 && validDigest(output.ChunkDigest) && output.SizeBytes > 0 && output.SizeBytes <= 256<<10 && !output.ObservedAt.IsZero() && output.ObservedAt.Location() == time.UTC && (output.Signature == "" || len(output.Signature) <= 128)
}

func validDataPlaneReceipt(receipt DataPlaneReceipt) bool {
	return receipt.ProtocolVersion == Version && boundedID(receipt.ReceiptID, 128) && boundedID(receipt.HostID, 128) && receipt.HostGeneration > 0 && boundedID(receipt.AssignmentID, 128) && receipt.LeaseEpoch > 0 && receipt.FencingToken > 0 && boundedID(receipt.OperationID, 128) && (receipt.Kind == "transfer" || receipt.Kind == "snapshot-restore" || receipt.Kind == "mount") && validDigest(receipt.ReceiptDigest) && (receipt.Signature == "" || len(receipt.Signature) <= 128)
}

func boundedID(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsRune(value, '\x00')
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[7:] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
