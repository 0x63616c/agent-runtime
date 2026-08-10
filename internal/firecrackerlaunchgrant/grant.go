// Package firecrackerlaunchgrant owns the private, operator-only M3/M4 boot-probe binding.
package firecrackerlaunchgrant

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/0x63616c/agent-runtime/sandbox"
	"github.com/cockroachdb/errors"
	"golang.org/x/text/unicode/norm"
)

var (
	// ErrInvalidGrant identifies a malformed, widened, or non-canonical private boot-probe grant.
	ErrInvalidGrant = errors.New("invalid Firecracker launch grant")
)

const (
	// Version is the only accepted private Firecracker launch-grant wire version.
	Version = "firecracker-launch-grant/v1"
	// OperatorBootProbeOperation is the sole internal operation kind that this grant can authorize.
	OperatorBootProbeOperation = "firecracker-boot-probe"
	// GuestProtocolV1 is the pinned guest protocol expected by this limited boot probe.
	GuestProtocolV1 = "agent-runtime-firecracker-guest/v1"

	maximumWireBytes = 16 << 10
)

// EnvelopeTuple is the non-secret, already-authenticated M3 assignment identity bound to one grant.
// It intentionally excludes the signed envelope payload, its delivery nonce, and its signature.
type EnvelopeTuple struct {
	EnvelopeID             string         `json:"envelope_id"`
	DeliveryID             string         `json:"delivery_id"`
	Nonce                  string         `json:"nonce"`
	IssuedAt               time.Time      `json:"issued_at"`
	ExpiresAt              time.Time      `json:"expires_at"`
	HostID                 string         `json:"host_id"`
	HostGeneration         uint64         `json:"host_generation"`
	AssignmentID           string         `json:"assignment_id"`
	LeaseEpoch             uint64         `json:"lease_epoch"`
	FencingToken           uint64         `json:"fencing_token"`
	Tenant                 string         `json:"tenant"`
	Principal              string         `json:"principal"`
	SandboxID              string         `json:"sandbox_id"`
	OperationID            string         `json:"operation_id"`
	OperationKind          string         `json:"operation_kind"`
	EffectiveSpecDigest    sandbox.Digest `json:"effective_spec_digest"`
	CapabilityDigest       sandbox.Digest `json:"capability_digest"`
	CanonicalRequestDigest sandbox.Digest `json:"canonical_request_digest"`
}

// TrustedM4Identity is the non-secret identity digest tuple constructed from the exact M4 plan, fixture set, stage, and Jailer authority.
// Its producer is responsible for deriving each digest from validated M4 values; this codec only accepts the resulting immutable tuple.
type TrustedM4Identity struct {
	VMID            string         `json:"vm_id"`
	FixtureVersion  string         `json:"fixture_version"`
	PlanDigest      sandbox.Digest `json:"plan_digest"`
	FixtureDigest   sandbox.Digest `json:"fixture_digest"`
	StageDigest     sandbox.Digest `json:"stage_digest"`
	AuthorityDigest sandbox.Digest `json:"authority_digest"`
}

// Grant is a private, short-lived operator boot probe authorization, not a public sandbox lifecycle capability.
// It contains no raw request body, control signature, credential, or host path.
type Grant struct {
	Version       string            `json:"version"`
	Envelope      EnvelopeTuple     `json:"envelope"`
	M4            TrustedM4Identity `json:"m4"`
	GuestProtocol string            `json:"guest_protocol"`
	SerialMarker  string            `json:"serial_marker"`
}

// New creates the sole fixed-purpose grant from an already-authenticated M3 tuple and trusted M4 identity tuple.
// It does not interpret DispatchBody or launch a Jailer, VMM, guest, or vsock connection.
func New(envelope EnvelopeTuple, identity TrustedM4Identity) (Grant, error) {
	grant := Grant{Version: Version, Envelope: envelope, M4: identity, GuestProtocol: GuestProtocolV1, SerialMarker: serialMarker(identity.VMID, identity.FixtureVersion)}
	if err := grant.Validate(); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

// Encode writes the private grant bytes.
func Encode(grant Grant) ([]byte, error) {
	if err := grant.Validate(); err != nil {
		return nil, err
	}
	wire, err := json.Marshal(grant)
	if err != nil || len(wire) > maximumWireBytes {
		return nil, errors.Wrap(ErrInvalidGrant, "encode bounded canonical grant")
	}
	return wire, nil
}

// Decode reads one private grant.
func Decode(wire []byte) (Grant, error) {
	if len(wire) == 0 || len(wire) > maximumWireBytes {
		return Grant{}, errors.Wrap(ErrInvalidGrant, "decode bounded grant")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var grant Grant
	if err := decoder.Decode(&grant); err != nil {
		return Grant{}, errors.Wrap(ErrInvalidGrant, "decode grant")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Grant{}, errors.Wrap(ErrInvalidGrant, "decode trailing grant data")
	}
	if err := grant.Validate(); err != nil {
		return Grant{}, err
	}
	canonical, err := Encode(grant)
	if err != nil || !bytes.Equal(canonical, wire) {
		return Grant{}, errors.Wrap(ErrInvalidGrant, "decode non-canonical grant")
	}
	return grant, nil
}

// Validate confirms that Grant is one bounded, fixed-purpose M3/M4 binding.
func (grant Grant) Validate() error {
	if grant.Version != Version || !validEnvelopeTuple(grant.Envelope) || !validM4Identity(grant.M4) || grant.GuestProtocol != GuestProtocolV1 || grant.SerialMarker != serialMarker(grant.M4.VMID, grant.M4.FixtureVersion) {
		return errors.Wrap(ErrInvalidGrant, "validate exact boot-probe binding")
	}
	return nil
}

// ValidateBinding confirms that a decoded grant remains bound to the exact authenticated M3 tuple and trusted M4 identity supplied by its caller.
// The caller owns envelope authentication and M4 identity derivation; this function performs no request-body interpretation or host effect.
func ValidateBinding(grant Grant, envelope EnvelopeTuple, identity TrustedM4Identity, now time.Time) error {
	if err := grant.Validate(); err != nil {
		return err
	}
	if !validEnvelopeTuple(envelope) || !validM4Identity(identity) || now.IsZero() || now.Location() != time.UTC || now.Before(grant.Envelope.IssuedAt) || !now.Before(grant.Envelope.ExpiresAt) || grant.Envelope != envelope || grant.M4 != identity {
		return errors.Wrap(ErrInvalidGrant, "validate authenticated M3 and trusted M4 binding")
	}
	return nil
}

func serialMarker(vmID, fixtureVersion string) string {
	return "AGENT_RUNTIME_FC_SMOKE " + vmID + " " + fixtureVersion + " " + GuestProtocolV1
}

func validEnvelopeTuple(tuple EnvelopeTuple) bool {
	return validID(tuple.EnvelopeID, 128) && validID(tuple.DeliveryID, 128) && validNonce(tuple.Nonce) && validDeadline(tuple.IssuedAt, tuple.ExpiresAt) && validID(tuple.HostID, 128) && tuple.HostGeneration > 0 && validID(tuple.AssignmentID, 128) && tuple.LeaseEpoch > 0 && tuple.FencingToken > 0 && validID(tuple.Tenant, 256) && validID(tuple.Principal, 512) && strings.HasPrefix(tuple.Principal, tuple.Tenant+":") && validID(tuple.SandboxID, 128) && validID(tuple.OperationID, 128) && tuple.OperationKind == OperatorBootProbeOperation && validDigest(tuple.EffectiveSpecDigest) && validDigest(tuple.CapabilityDigest) && validDigest(tuple.CanonicalRequestDigest)
}

func validM4Identity(identity TrustedM4Identity) bool {
	return validVMID(identity.VMID) && validFixtureVersion(identity.FixtureVersion) && validDigest(identity.PlanDigest) && validDigest(identity.FixtureDigest) && validDigest(identity.StageDigest) && validDigest(identity.AuthorityDigest)
}

func validDeadline(issuedAt, deadline time.Time) bool {
	return !issuedAt.IsZero() && issuedAt.Location() == time.UTC && !deadline.IsZero() && deadline.Location() == time.UTC && deadline.After(issuedAt) && deadline.Sub(issuedAt) <= 5*time.Minute
}

func validNonce(nonce string) bool {
	if len(nonce) == 0 || len(nonce) > 86 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	return err == nil && len(decoded) >= 16 && len(decoded) <= 64 && base64.RawURLEncoding.EncodeToString(decoded) == nonce
}

func validID(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && norm.NFC.IsNormalString(value) && !strings.ContainsRune(value, '\x00')
}

func validVMID(value string) bool {
	if len(value) == 0 || len(value) > 63 || !vmIDAlphaNumeric(value[0]) || !vmIDAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for index := 1; index < len(value)-1; index++ {
		if value[index] != '-' && !vmIDAlphaNumeric(value[index]) {
			return false
		}
	}
	return true
}

func vmIDAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

func validFixtureVersion(value string) bool {
	return validVMID(value) && value != "latest" && value != "main"
}

func validDigest(value sandbox.Digest) bool {
	if len(value) != 71 || !strings.HasPrefix(string(value), "sha256:") {
		return false
	}
	for _, character := range value[7:] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
