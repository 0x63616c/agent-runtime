package firecrackerbootprobeprotocol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/firecracker"
	"github.com/0x63616c/agent-runtime/internal/firecrackerbootprobev2"
	"github.com/0x63616c/agent-runtime/internal/firecrackerlaunchgrant"
	"github.com/0x63616c/agent-runtime/sandbox"
)

func TestCommandAndObservationBindOneExactAuthenticatedPrivateBootProbe(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostPublic, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state, grant, identity := validStateAndGrant(t, now)

	commandWire, err := SignCommand(authorizedSession(t, state, now), grant, "YW5vdGhlci1ncmFudC1ndWVzdC1ub25jZQ", controlPrivate)
	if err != nil {
		t.Fatalf("SignCommand() error = %v", err)
	}
	command, err := verifyCommand(context.Background(), commandWire, now, staticHostTrust{control: controlPublic, observation: hostPublic}, staticM4Identity{identity: identity}.VerifyTrustedM4Identity)
	if err != nil {
		t.Fatalf("VerifyCommand() error = %v", err)
	}

	accepted := command.Command()
	observationWire, err := SignObservation(Observation{
		ProtocolVersion:       Version,
		Kind:                  ObservationKind,
		HostInstanceSessionID: state.HostInstanceSessionID,
		EnvelopeID:            state.Current.EnvelopeID,
		DeliveryID:            state.Current.DeliveryID,
		Nonce:                 state.Current.Nonce,
		LeaseEpoch:            state.Current.LeaseEpoch,
		FencingToken:          state.Current.FencingToken,
		M4:                    identity,
		SerialMarker:          grant.SerialMarker,
		GuestNonce:            accepted.GuestNonce,
		GuestProtocolResult:   GuestProtocolPong,
		ObservedAt:            now.Add(time.Second),
	}, hostPrivate)
	if err != nil {
		t.Fatalf("SignObservation() error = %v", err)
	}
	observation, err := VerifyObservation(observationWire, command, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("VerifyObservation() error = %v", err)
	}
	if observation.GuestProtocolResult != GuestProtocolPong {
		t.Fatalf("VerifyObservation() result = %q, want %q", observation.GuestProtocolResult, GuestProtocolPong)
	}
}

func TestStageReadyBindsAPersistedPreparedSessionToTheDistinctObservationKey(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state, _, identity := validStateAndGrant(t, now)
	session, err := firecrackerbootprobev2.NewSession(state)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := firecrackerbootprobev2.EncodeSession(session)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := firecrackerbootprobev2.Snapshot{Version: 7, Session: session, Wire: wire}
	readyWire, err := signStageReady(snapshot, identity, "YW5vdGhlci1ncmFudC1ndWVzdC1ub25jZQ", hostPrivate)
	if err != nil {
		t.Fatalf("signStageReady() error = %v", err)
	}
	verified, err := VerifyStageReady(context.Background(), readyWire, now.Add(time.Second), staticHostTrust{observation: hostPrivate.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatalf("VerifyStageReady() error = %v", err)
	}
	ready := verified.StageReady()
	if ready.ExpectedVersion != snapshot.Version || ready.M4 != identity || ready.Delivery != state.Current {
		t.Fatalf("VerifyStageReady() = %#v, want exact persisted stage-ready binding", ready)
	}
}

func TestStageReadyRefusesAChangedIdentityOrControlSigningKey(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	controlPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state, _, identity := validStateAndGrant(t, now)
	session, err := firecrackerbootprobev2.NewSession(state)
	if err != nil {
		t.Fatal(err)
	}
	sessionWire, err := firecrackerbootprobev2.EncodeSession(session)
	if err != nil {
		t.Fatal(err)
	}
	readyWire, err := signStageReady(firecrackerbootprobev2.Snapshot{Version: 7, Session: session, Wire: sessionWire}, identity, "YW5vdGhlci1ncmFudC1ndWVzdC1ub25jZQ", hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyStageReady(context.Background(), readyWire, now.Add(time.Second), staticHostTrust{observation: controlPublic}); !errors.Is(err, ErrInvalidStageReady) {
		t.Fatalf("VerifyStageReady(control key) error = %v, want ErrInvalidStageReady", err)
	}
	ready, err := decodeStageReady(readyWire)
	if err != nil {
		t.Fatal(err)
	}
	ready.M4.StageDigest = digest('9')
	altered, err := encodeStageReady(ready)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyStageReady(context.Background(), altered, now.Add(time.Second), staticHostTrust{observation: hostPrivate.Public().(ed25519.PublicKey)}); !errors.Is(err, ErrInvalidStageReady) {
		t.Fatalf("VerifyStageReady(changed identity) error = %v, want ErrInvalidStageReady", err)
	}
}

func TestCommandRefusesGrantForAnotherEnvelopeOrSelfReportedM4Identity(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state, grant, identity := validStateAndGrant(t, now)
	grant.Envelope.EnvelopeID = "envelope_other"
	if _, err := SignCommand(authorizedSession(t, state, now), grant, "YW5vdGhlci1ncmFudC1ndWVzdC1ub25jZQ", controlPrivate); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("SignCommand(wrong envelope) error = %v, want ErrInvalidCommand", err)
	}

	_, grant, identity = validStateAndGrant(t, now)
	commandWire, err := SignCommand(authorizedSession(t, state, now), grant, "YW5vdGhlci1ncmFudC1ndWVzdC1ub25jZQ", controlPrivate)
	if err != nil {
		t.Fatalf("SignCommand() error = %v", err)
	}
	identity.AuthorityDigest = digest('9')
	if _, err := verifyCommand(context.Background(), commandWire, now, staticHostTrust{control: controlPublic, observation: controlPublic}, staticM4Identity{identity: identity}.VerifyTrustedM4Identity); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("VerifyCommand(self-reported different M4 identity) error = %v, want ErrInvalidCommand", err)
	}
}

func TestCommandRefusesUnpersistedLaunchIntent(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	_, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state, grant, _ := validStateAndGrant(t, now)
	session, err := firecrackerbootprobev2.NewSession(state)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	if _, err := SignCommand(session, grant, "YW5vdGhlci1ncmFudC1ndWVzdC1ub25jZQ", controlPrivate); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("SignCommand(prepared) error = %v, want ErrInvalidCommand", err)
	}
}

func TestCommandRefusesAResolverResultForAnotherHostGeneration(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state, grant, identity := validStateAndGrant(t, now)
	commandWire, err := SignCommand(authorizedSession(t, state, now), grant, "YW5vdGhlci1ncmFudC1ndWVzdC1ub25jZQ", controlPrivate)
	if err != nil {
		t.Fatalf("SignCommand() error = %v", err)
	}
	resolver := staticHostTrust{control: controlPublic, observation: hostPrivate.Public().(ed25519.PublicKey), returnedGeneration: 8}
	if _, err := verifyCommand(context.Background(), commandWire, now, resolver, staticM4Identity{identity: identity}.VerifyTrustedM4Identity); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("VerifyCommand(mismatched resolver result) error = %v, want ErrInvalidCommand", err)
	}
}

func TestCommandRefusesAnUnsealedM4Verifier(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state, grant, _ := validStateAndGrant(t, now)
	commandWire, err := SignCommand(authorizedSession(t, state, now), grant, "YW5vdGhlci1ncmFudC1ndWVzdC1ub25jZQ", controlPrivate)
	if err != nil {
		t.Fatalf("SignCommand() error = %v", err)
	}
	if _, err := VerifyCommand(context.Background(), commandWire, now, staticHostTrust{control: controlPublic, observation: hostPublic}, firecracker.CompiledM4IdentityVerifier{}); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("VerifyCommand(unsealed M4 verifier) error = %v, want ErrInvalidCommand", err)
	}
}

func TestObservationRefusesDelayedOrAlteredExactDelivery(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostPublic, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state, grant, identity := validStateAndGrant(t, now)
	commandWire, err := SignCommand(authorizedSession(t, state, now), grant, "YW5vdGhlci1ncmFudC1ndWVzdC1ub25jZQ", controlPrivate)
	if err != nil {
		t.Fatalf("SignCommand() error = %v", err)
	}
	command, err := verifyCommand(context.Background(), commandWire, now, staticHostTrust{control: controlPublic, observation: hostPublic}, staticM4Identity{identity: identity}.VerifyTrustedM4Identity)
	if err != nil {
		t.Fatalf("VerifyCommand() error = %v", err)
	}

	for name, mutate := range map[string]func(*Observation){
		"before delivery": func(observation *Observation) { observation.ObservedAt = state.Current.IssuedAt.Add(-time.Nanosecond) },
		"delayed":         func(observation *Observation) { observation.ObservedAt = state.Current.ExpiresAt },
		"wrong envelope":  func(observation *Observation) { observation.EnvelopeID = "envelope_replayed" },
		"wrong nonce":     func(observation *Observation) { observation.Nonce = "ZmVkY2JhOTg3NjU0MzIxMA" },
		"wrong marker":    func(observation *Observation) { observation.SerialMarker = "AGENT_RUNTIME_FC_SMOKE altered" },
	} {
		t.Run(name, func(t *testing.T) {
			observation := validObservation(state, grant, command, identity, now)
			mutate(&observation)
			wire, signErr := SignObservation(observation, hostPrivate)
			if signErr != nil {
				t.Fatalf("SignObservation() error = %v", signErr)
			}
			if _, verifyErr := VerifyObservation(wire, command, now.Add(time.Minute)); !errors.Is(verifyErr, ErrInvalidObservation) {
				t.Fatalf("VerifyObservation() error = %v, want ErrInvalidObservation", verifyErr)
			}
		})
	}
}

func TestObservationRefusesACommandThatDidNotPassVerification(t *testing.T) {
	now := time.Date(2026, time.August, 10, 18, 0, 0, 0, time.UTC)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyObservation([]byte(`{}`), VerifiedCommand{}, now); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("VerifyObservation(unverified command) error = %v, want ErrInvalidObservation", err)
	}
	if _, err := SignObservation(Observation{}, private); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("SignObservation(empty) error = %v, want ErrInvalidObservation", err)
	}
}

type staticHostTrust struct {
	control            ed25519.PublicKey
	observation        ed25519.PublicKey
	returnedGeneration uint64
}

func (trust staticHostTrust) ResolveBootProbeHostTrust(_ context.Context, hostID string, generation uint64) (HostTrust, error) {
	if hostID != "host_01" || generation != 7 {
		return HostTrust{}, errors.New("unexpected host")
	}
	if trust.returnedGeneration != 0 {
		generation = trust.returnedGeneration
	}
	return HostTrust{HostID: hostID, HostGeneration: generation, ControlPublicKey: trust.control, ObservationPublicKey: trust.observation}, nil
}

type staticM4Identity struct {
	identity firecrackerlaunchgrant.TrustedM4Identity
}

func (verifier staticM4Identity) VerifyTrustedM4Identity(candidate firecrackerlaunchgrant.TrustedM4Identity) error {
	if candidate != verifier.identity {
		return errors.New("unexpected M4 identity")
	}
	return nil
}

func validStateAndGrant(t *testing.T, now time.Time) (firecrackerbootprobev2.State, firecrackerlaunchgrant.Grant, firecrackerlaunchgrant.TrustedM4Identity) {
	t.Helper()
	binding := firecrackerbootprobev2.Binding{
		HostID: "host_01", HostGeneration: 7, AssignmentID: "assignment_01", Tenant: "tenant_01", Principal: "tenant_01:operator_01", SandboxID: "sbx_01", OperationID: "operation_01", OperationKind: "firecracker-boot-probe",
		EffectiveSpecDigest: digest('a'), CapabilityDigest: digest('b'), CanonicalRequestDigest: digest('c'),
	}
	delivery := firecrackerbootprobev2.Delivery{EnvelopeID: "envelope_01", DeliveryID: "delivery_01", Nonce: "MDEyMzQ1Njc4OWFiY2RlZg", IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute), LeaseEpoch: 4, FencingToken: 4}
	state, err := firecrackerbootprobev2.NewState(binding, "host-session-01", delivery, now)
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	identity := firecrackerlaunchgrant.TrustedM4Identity{VMID: "sandbox-001", FixtureVersion: "fixture-v1", PlanDigest: digest('d'), FixtureDigest: digest('e'), StageDigest: digest('f'), AuthorityDigest: digest('0')}
	grant, err := firecrackerlaunchgrant.New(firecrackerlaunchgrant.EnvelopeTuple{EnvelopeID: delivery.EnvelopeID, DeliveryID: delivery.DeliveryID, Nonce: delivery.Nonce, IssuedAt: delivery.IssuedAt, ExpiresAt: delivery.ExpiresAt, HostID: binding.HostID, HostGeneration: binding.HostGeneration, AssignmentID: binding.AssignmentID, LeaseEpoch: delivery.LeaseEpoch, FencingToken: delivery.FencingToken, Tenant: binding.Tenant, Principal: binding.Principal, SandboxID: binding.SandboxID, OperationID: binding.OperationID, OperationKind: binding.OperationKind, EffectiveSpecDigest: binding.EffectiveSpecDigest, CapabilityDigest: binding.CapabilityDigest, CanonicalRequestDigest: binding.CanonicalRequestDigest}, identity)
	if err != nil {
		t.Fatalf("firecrackerlaunchgrant.New() error = %v", err)
	}
	return state, grant, identity
}

func validObservation(state firecrackerbootprobev2.State, grant firecrackerlaunchgrant.Grant, command VerifiedCommand, identity firecrackerlaunchgrant.TrustedM4Identity, now time.Time) Observation {
	return Observation{ProtocolVersion: Version, Kind: ObservationKind, HostInstanceSessionID: state.HostInstanceSessionID, EnvelopeID: state.Current.EnvelopeID, DeliveryID: state.Current.DeliveryID, Nonce: state.Current.Nonce, LeaseEpoch: state.Current.LeaseEpoch, FencingToken: state.Current.FencingToken, M4: identity, SerialMarker: grant.SerialMarker, GuestNonce: command.Command().GuestNonce, GuestProtocolResult: GuestProtocolPong, ObservedAt: now.Add(time.Second)}
}

func authorizedSession(t *testing.T, state firecrackerbootprobev2.State, now time.Time) firecrackerbootprobev2.Session {
	t.Helper()
	session, err := firecrackerbootprobev2.NewSession(state)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	session, err = session.AuthorizeLaunch(now)
	if err != nil {
		t.Fatalf("AuthorizeLaunch() error = %v", err)
	}
	return session
}

func digest(nibble byte) sandbox.Digest {
	value := make([]byte, 64)
	for index := range value {
		value[index] = nibble
	}
	return sandbox.Digest("sha256:" + string(value))
}
