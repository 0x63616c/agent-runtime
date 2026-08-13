package runtimecontent_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0x63616c/agent-runtime/internal/runtimecontent"
	agentruntime "github.com/0x63616c/agent-runtime/sdk/go"
)

func TestStoreStagesAnIdentityFreeAgentSpecificationBodyAsTenantBoundHandoff(t *testing.T) {
	store, objects, tenant, _ := testStore(t)
	body := runtimecontent.AgentSpecificationBody{
		Name: "researcher", ModelProfile: "balanced", Instructions: "be safe",
		Tools: []agentruntime.ToolDefinition{{Name: "search", Description: "search"}},
	}

	handoff, err := store.StageAgentSpecificationBody(context.Background(), tenant, body)
	if err != nil {
		t.Fatalf("stage Agent specification body: %v", err)
	}
	commitment, err := store.ValidateAgentSpecificationBodyHandoff(handoff)
	if err != nil {
		t.Fatalf("validate Agent specification body handoff: %v", err)
	}
	if commitment.Tenant != tenant || commitment.Name != body.Name || commitment.ModelProfile != body.ModelProfile || commitment.Reference.MediaType != runtimecontent.AgentSpecificationBodyMediaTypeV1 {
		t.Fatalf("handoff commitment = %#v, want tenant-bound body reference", commitment)
	}
	if len(objects.keys) != 1 || bytes.Contains(objects.values[objects.keys[0]], []byte("agent_")) || bytes.Contains(objects.values[objects.keys[0]], []byte("arev_")) {
		t.Fatalf("staged Agent body must be identity-free, keys=%v bytes=%x", objects.keys, objects.values[objects.keys[0]])
	}
}

func TestStoreStagesCanonicalInputEnvelopeAsTenantBoundHandoff(t *testing.T) {
	store, objects, tenant, _ := testStore(t)
	parts := []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "raw input remains immutable content"}}

	handoff, err := store.StageInputEnvelope(context.Background(), tenant, parts)
	if err != nil {
		t.Fatalf("stage input envelope: %v", err)
	}
	commitment, err := store.ValidateInputEnvelopeHandoff(handoff)
	if err != nil {
		t.Fatalf("validate input envelope handoff: %v", err)
	}
	if commitment.Tenant != tenant || commitment.Reference.MediaType != runtimecontent.InputEnvelopeMediaTypeV1 || commitment.Reference.Digest == "" || commitment.Reference.SizeBytes <= 0 {
		t.Fatalf("handoff commitment = %#v, want tenant-bound input reference only", commitment)
	}
	if strings.Contains(fmt.Sprintf("%#v", commitment), parts[0].Text) {
		t.Fatalf("Input envelope commitment exposes raw input: %#v", commitment)
	}
	if len(objects.keys) != 1 || !bytes.Contains(objects.values[objects.keys[0]], []byte(parts[0].Text)) {
		t.Fatalf("staged input envelope = keys=%v bytes=%x, want immutable canonical raw input", objects.keys, objects.values[objects.keys[0]])
	}
	const wantCanonicalHex = "8201818201782372617720696e7075742072656d61696e7320696d6d757461626c6520636f6e74656e74"
	if got := fmt.Sprintf("%x", objects.values[objects.keys[0]]); got != wantCanonicalHex {
		t.Fatalf("canonical Input envelope changed: got %s, want %s", got, wantCanonicalHex)
	}
}

func TestStoreRejectsForeignAndWrongKindInputEnvelopeHandoffs(t *testing.T) {
	store, objects, tenant, _ := testStore(t)
	input, err := store.StageInputEnvelope(context.Background(), tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "safe input"}})
	if err != nil {
		t.Fatalf("stage input envelope: %v", err)
	}
	other, err := runtimecontent.New("runtime-content", objects)
	if err != nil {
		t.Fatalf("new other content authority: %v", err)
	}
	if _, err := other.ValidateInputEnvelopeHandoff(input); !errors.Is(err, runtimecontent.ErrNotFoundOrDenied) {
		t.Fatalf("foreign input handoff error = %v, want ErrNotFoundOrDenied", err)
	}
	body, err := store.StageAgentSpecificationBody(context.Background(), tenant, runtimecontent.AgentSpecificationBody{Name: "researcher", ModelProfile: "balanced", Instructions: "be safe"})
	if err != nil {
		t.Fatalf("stage Agent specification body: %v", err)
	}
	if _, err := store.ValidateInputEnvelopeHandoff(body); !errors.Is(err, runtimecontent.ErrNotFoundOrDenied) {
		t.Fatalf("body handoff accepted as Input envelope: %v", err)
	}
}

func TestStoreFencesCancellationAfterInputEnvelopeObjectWrite(t *testing.T) {
	store, objects, tenant, _ := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	objects.getHook = cancel

	_, err := store.StageInputEnvelope(ctx, tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "orphaned on cancellation"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("stage cancelled Input envelope error = %v, want context.Canceled", err)
	}
	if len(objects.keys) != 1 {
		t.Fatalf("writes = %v, want one reconciled immutable orphan", objects.keys)
	}
}

func TestStoreStagesArtifactInputEnvelopeWithinPublicContract(t *testing.T) {
	store, objects, tenant, _ := testStore(t)
	handoff, err := store.StageInputEnvelope(context.Background(), tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentArtifact, Artifact: &agentruntime.ArtifactReference{
		ID: "art_0000000000000001", MediaType: "text/plain", SizeBytes: 5,
		SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}}})
	if err != nil {
		t.Fatalf("stage artifact input envelope: %v", err)
	}
	if _, err := store.ValidateInputEnvelopeHandoff(handoff); err != nil {
		t.Fatalf("validate artifact input envelope: %v", err)
	}
	const wantCanonicalHex = "820181820284746172745f303030303030303030303030303030316a746578742f706c61696e05784061616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"
	if got := fmt.Sprintf("%x", objects.values[objects.keys[0]]); got != wantCanonicalHex {
		t.Fatalf("canonical artifact Input envelope changed: got %s, want %s", got, wantCanonicalHex)
	}
}

func TestArtifactReaderRequiresExactTenantPrincipalMetadataAuthorization(t *testing.T) {
	store, objects, tenant, _ := testStore(t)
	alice := testPrincipalID(t, "alice")
	bob := testPrincipalID(t, "bob")
	handoff, err := store.StageArtifact(context.Background(), tenant, "text/plain", []byte("approved report"))
	if err != nil {
		t.Fatalf("stage artifact: %v", err)
	}
	commitment, err := store.ValidateArtifactHandoff(handoff)
	if err != nil {
		t.Fatalf("validate artifact handoff: %v", err)
	}
	artifactID, err := agentruntime.ParseArtifactID("art_0000000000000001")
	if err != nil {
		t.Fatalf("parse artifact ID: %v", err)
	}
	repository := artifactRepository{record: runtimecontent.ArtifactRecord{Tenant: tenant, Principal: alice, ArtifactID: artifactID, Reference: commitment.Reference}}
	reader, err := runtimecontent.NewArtifactReader(store, repository)
	if err != nil {
		t.Fatalf("new artifact reader: %v", err)
	}
	got, err := reader.ReadArtifact(context.Background(), tenant, alice, artifactID)
	if err != nil {
		t.Fatalf("read authorized artifact: %v", err)
	}
	if string(got) != "approved report" {
		t.Fatalf("artifact bytes = %q, want approved report", got)
	}
	gets := objects.gets
	if _, err := reader.ReadArtifact(context.Background(), tenant, bob, artifactID); !errors.Is(err, runtimecontent.ErrNotFoundOrDenied) {
		t.Fatalf("cross-principal artifact read error = %v, want ErrNotFoundOrDenied", err)
	}
	if objects.gets != gets {
		t.Fatalf("cross-principal denial read object storage: gets=%d want=%d", objects.gets, gets)
	}
	if commitment.Reference.MediaType != "text/plain" || commitment.Reference.SizeBytes != int64(len("approved report")) {
		t.Fatalf("artifact commitment = %#v, want immutable digest metadata", commitment)
	}
}

func TestArtifactReaderOpensAnAuthorizedArtifactWithoutBufferingIt(t *testing.T) {
	store, objects, tenant, _ := testStore(t)
	alice := testPrincipalID(t, "alice")
	bob := testPrincipalID(t, "bob")
	handoff, err := store.StageArtifact(context.Background(), tenant, "text/plain", []byte("streamed report"))
	if err != nil {
		t.Fatalf("stage artifact: %v", err)
	}
	commitment, err := store.ValidateArtifactHandoff(handoff)
	if err != nil {
		t.Fatalf("validate artifact handoff: %v", err)
	}
	artifactID, err := agentruntime.ParseArtifactID("art_0000000000000001")
	if err != nil {
		t.Fatalf("parse artifact ID: %v", err)
	}
	reader, err := runtimecontent.NewArtifactReader(store, artifactRepository{record: runtimecontent.ArtifactRecord{Tenant: tenant, Principal: alice, ArtifactID: artifactID, Reference: commitment.Reference}})
	if err != nil {
		t.Fatalf("new artifact reader: %v", err)
	}
	getsBeforeOpen := objects.gets
	stream, err := reader.OpenArtifact(context.Background(), tenant, alice, artifactID)
	if err != nil {
		t.Fatalf("open authorized artifact: %v", err)
	}
	defer func() {
		if closeErr := stream.Body.Close(); closeErr != nil {
			t.Errorf("close artifact stream: %v", closeErr)
		}
	}()
	if stream.Reference != commitment.Reference || objects.opens != 1 || objects.gets != getsBeforeOpen {
		t.Fatalf("stream = %#v opens=%d gets=%d, want authorized streaming metadata only", stream.Reference, objects.opens, objects.gets)
	}
	body, err := io.ReadAll(stream.Body)
	if err != nil || string(body) != "streamed report" {
		t.Fatalf("read opened artifact = %q, %v", body, err)
	}
	if _, err := reader.OpenArtifact(context.Background(), tenant, bob, artifactID); !errors.Is(err, runtimecontent.ErrNotFoundOrDenied) || objects.opens != 1 {
		t.Fatalf("cross-principal stream error = %v opens=%d, want denied without object open", err, objects.opens)
	}
}

func TestToolActionDescriptorReaderRequiresExactWorkerProvenanceAndIntegrity(t *testing.T) {
	store, objects, tenant, _ := testStore(t)
	alice := testPrincipalID(t, "alice")
	bob := testPrincipalID(t, "bob")
	session := agentruntime.SessionID("sess_0000000000000001")
	turn := agentruntime.TurnID("turn_0000000000000001")
	handoff, err := store.StageToolActionDescriptor(context.Background(), tenant, []byte("canonical sandbox.control/v1 action"))
	if err != nil {
		t.Fatalf("stage tool descriptor: %v", err)
	}
	commitment, err := store.ValidateToolActionDescriptorHandoff(handoff)
	if err != nil {
		t.Fatalf("validate tool descriptor: %v", err)
	}
	repository := toolActionDescriptorRepository{tenant: tenant, principal: alice, session: session, turn: turn, toolCallID: "tcall_1234567890ABCDEF", commitment: commitment}
	reader, err := runtimecontent.NewToolActionDescriptorReader(store, repository)
	if err != nil {
		t.Fatalf("new tool descriptor reader: %v", err)
	}
	got, err := reader.ReadToolActionDescriptor(context.Background(), tenant, alice, session, turn, "tcall_1234567890ABCDEF")
	if err != nil || string(got) != "canonical sandbox.control/v1 action" {
		t.Fatalf("read authorized descriptor = %q, %v", got, err)
	}
	gets := objects.gets
	for _, denied := range []struct {
		name      string
		tenant    runtimecontent.TenantID
		principal runtimecontent.PrincipalID
		session   agentruntime.SessionID
		turn      agentruntime.TurnID
		tool      string
	}{
		{name: "cross principal", tenant: tenant, principal: bob, session: session, turn: turn, tool: "tcall_1234567890ABCDEF"},
		{name: "cross session", tenant: tenant, principal: alice, session: "sess_0000000000000002", turn: turn, tool: "tcall_1234567890ABCDEF"},
		{name: "cross turn", tenant: tenant, principal: alice, session: session, turn: "turn_0000000000000002", tool: "tcall_1234567890ABCDEF"},
		{name: "cross tool call", tenant: tenant, principal: alice, session: session, turn: turn, tool: "tcall_1234567890ABCDEG"},
	} {
		t.Run(denied.name, func(t *testing.T) {
			if _, err := reader.ReadToolActionDescriptor(context.Background(), denied.tenant, denied.principal, denied.session, denied.turn, denied.tool); !errors.Is(err, runtimecontent.ErrNotFoundOrDenied) {
				t.Fatalf("descriptor read error = %v, want ErrNotFoundOrDenied", err)
			}
		})
	}
	if objects.gets != gets {
		t.Fatalf("denied descriptor reads reached object storage: gets=%d want=%d", objects.gets, gets)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reader.ReadToolActionDescriptor(ctx, tenant, alice, session, turn, "tcall_1234567890ABCDEF"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled descriptor read error = %v, want context.Canceled", err)
	}
	if objects.gets != gets {
		t.Fatalf("cancelled descriptor read reached object storage: gets=%d want=%d", objects.gets, gets)
	}
	objects.values[objects.keys[0]][0] ^= 0xff
	if _, err := reader.ReadToolActionDescriptor(context.Background(), tenant, alice, session, turn, "tcall_1234567890ABCDEF"); !errors.Is(err, runtimecontent.ErrIntegrity) {
		t.Fatalf("corrupt descriptor read error = %v, want ErrIntegrity", err)
	}
}

func TestBoundToolActionDescriptorSealsCanonicalArgumentsAndKeepsLegacyReadable(t *testing.T) {
	descriptor := []byte(`{"kind":"workspace.write","path":"report.txt"}`)
	bound, err := runtimecontent.BindToolActionDescriptor(descriptor, []byte(`{"mode":"safe","path":"report.txt"}`))
	if err != nil {
		t.Fatal(err)
	}
	restoredDescriptor, arguments, err := runtimecontent.UnbindToolActionDescriptor(bound)
	if err != nil || string(restoredDescriptor) != string(descriptor) || string(arguments) != `{"mode":"safe","path":"report.txt"}` {
		t.Fatalf("unbind bound action = descriptor=%q arguments=%q err=%v", restoredDescriptor, arguments, err)
	}
	legacyDescriptor, legacyArguments, err := runtimecontent.UnbindToolActionDescriptor(descriptor)
	if err != nil || string(legacyDescriptor) != string(descriptor) || legacyArguments != nil {
		t.Fatalf("unbind legacy action = descriptor=%q arguments=%q err=%v", legacyDescriptor, legacyArguments, err)
	}
	for _, invalid := range [][]byte{
		[]byte(`{"version":"agent-runtime.bound-tool-action/v1","descriptor_b64":"not_base64","arguments":{}}`),
		[]byte(`{"version":"agent-runtime.bound-tool-action/v1","descriptor_b64":"YQ","arguments":{},"unexpected":true}`),
	} {
		if _, _, err := runtimecontent.UnbindToolActionDescriptor(invalid); err == nil {
			t.Fatalf("malformed bound action was accepted: %s", invalid)
		}
	}
}

func TestInputEnvelopeReaderAuthorizesAndHydratesExactInputMetadata(t *testing.T) {
	store, _, tenant, _ := testStore(t)
	principal := testPrincipalID(t, "alice")
	parts := []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "read through content authority"}}
	handoff, err := store.StageInputEnvelope(context.Background(), tenant, parts)
	if err != nil {
		t.Fatalf("stage Input envelope: %v", err)
	}
	commitment, err := store.ValidateInputEnvelopeHandoff(handoff)
	if err != nil {
		t.Fatalf("validate Input envelope handoff: %v", err)
	}
	repository := inputEnvelopeRepository{record: runtimecontent.InputEnvelopeRecord{
		Tenant: tenant, Principal: principal, SessionID: "sess_0000000000000001", InputID: "inpt_0000000000000001", Reference: commitment.Reference,
	}}
	reader, err := runtimecontent.NewInputEnvelopeReader(store, repository)
	if err != nil {
		t.Fatalf("new Input envelope reader: %v", err)
	}

	got, err := reader.ReadInputEnvelope(context.Background(), tenant, principal, repository.record.SessionID, repository.record.InputID)
	if err != nil {
		t.Fatalf("read Input envelope: %v", err)
	}
	if !reflect.DeepEqual(got, parts) {
		t.Fatalf("Input envelope = %#v, want %#v", got, parts)
	}
}

func TestInputEnvelopeReaderRejectsTenantMismatchesBeforeContentRead(t *testing.T) {
	store, objects, tenant, _ := testStore(t)
	principal := testPrincipalID(t, "alice")
	parts := []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "tenant bound input"}}
	handoff, err := store.StageInputEnvelope(context.Background(), tenant, parts)
	if err != nil {
		t.Fatalf("stage Input envelope: %v", err)
	}
	commitment, err := store.ValidateInputEnvelopeHandoff(handoff)
	if err != nil {
		t.Fatalf("validate Input envelope handoff: %v", err)
	}
	otherTenant, err := runtimecontent.ParseTenantID("tenant-b")
	if err != nil {
		t.Fatalf("parse other tenant: %v", err)
	}
	if _, err := store.StageInputEnvelope(context.Background(), otherTenant, parts); err != nil {
		t.Fatalf("stage same Input envelope for other tenant: %v", err)
	}
	if len(objects.keys) != 2 || objects.keys[0] == objects.keys[1] {
		t.Fatalf("tenant content keys = %v, want separate immutable object namespaces", objects.keys)
	}
	repository := inputEnvelopeRepository{record: runtimecontent.InputEnvelopeRecord{
		Tenant: tenant, Principal: principal, SessionID: "sess_0000000000000001", InputID: "inpt_0000000000000001", Reference: commitment.Reference,
	}}
	reader, err := runtimecontent.NewInputEnvelopeReader(store, repository)
	if err != nil {
		t.Fatalf("new Input envelope reader: %v", err)
	}
	if _, err := reader.ReadInputEnvelope(context.Background(), otherTenant, principal, repository.record.SessionID, repository.record.InputID); !errors.Is(err, runtimecontent.ErrNotFoundOrDenied) {
		t.Fatalf("cross-tenant Input read error = %v, want ErrNotFoundOrDenied", err)
	}
	if objects.gets != 2 {
		t.Fatalf("content reads = %d, want staging read-backs only", objects.gets)
	}
}

func TestInputEnvelopeReaderRejectsSameTenantDifferentPrincipalBeforeContentRead(t *testing.T) {
	store, objects, tenant, _ := testStore(t)
	handoff, err := store.StageInputEnvelope(context.Background(), tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "principal bound input"}})
	if err != nil {
		t.Fatalf("stage Input envelope: %v", err)
	}
	commitment, err := store.ValidateInputEnvelopeHandoff(handoff)
	if err != nil {
		t.Fatalf("validate Input envelope handoff: %v", err)
	}
	alice, err := runtimecontent.ParsePrincipalID("alice")
	if err != nil {
		t.Fatalf("parse alice principal: %v", err)
	}
	bob, err := runtimecontent.ParsePrincipalID("bob")
	if err != nil {
		t.Fatalf("parse bob principal: %v", err)
	}
	repository := inputEnvelopeRepository{record: runtimecontent.InputEnvelopeRecord{
		Tenant: tenant, Principal: alice, SessionID: "sess_0000000000000001", InputID: "inpt_0000000000000001", Reference: commitment.Reference,
	}}
	reader, err := runtimecontent.NewInputEnvelopeReader(store, repository)
	if err != nil {
		t.Fatalf("new Input envelope reader: %v", err)
	}
	if _, err := reader.ReadInputEnvelope(context.Background(), tenant, bob, repository.record.SessionID, repository.record.InputID); !errors.Is(err, runtimecontent.ErrNotFoundOrDenied) {
		t.Fatalf("cross-principal Input read error = %v, want ErrNotFoundOrDenied", err)
	}
	if objects.gets != 1 {
		t.Fatalf("content reads = %d, want staging read-back only", objects.gets)
	}
}

func TestInputEnvelopeReaderPreservesCancellationAndIntegrity(t *testing.T) {
	store, objects, tenant, _ := testStore(t)
	principal := testPrincipalID(t, "alice")
	handoff, err := store.StageInputEnvelope(context.Background(), tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "protected input"}})
	if err != nil {
		t.Fatalf("stage Input envelope: %v", err)
	}
	commitment, err := store.ValidateInputEnvelopeHandoff(handoff)
	if err != nil {
		t.Fatalf("validate Input envelope handoff: %v", err)
	}
	repository := inputEnvelopeRepository{record: runtimecontent.InputEnvelopeRecord{
		Tenant: tenant, Principal: principal, SessionID: "sess_0000000000000001", InputID: "inpt_0000000000000001", Reference: commitment.Reference,
	}}
	reader, err := runtimecontent.NewInputEnvelopeReader(store, repository)
	if err != nil {
		t.Fatalf("new Input envelope reader: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	objects.getHook = cancel
	if _, err := reader.ReadInputEnvelope(ctx, tenant, principal, repository.record.SessionID, repository.record.InputID); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-read cancellation error = %v, want context.Canceled", err)
	}
	objects.getHook = nil
	objects.values[objects.keys[0]] = append(objects.values[objects.keys[0]], 0)
	if _, err := reader.ReadInputEnvelope(context.Background(), tenant, principal, repository.record.SessionID, repository.record.InputID); !errors.Is(err, runtimecontent.ErrIntegrity) {
		t.Fatalf("tampered Input envelope error = %v, want ErrIntegrity", err)
	}
}

func TestStoreRejectsInputEnvelopeOutsidePublicContract(t *testing.T) {
	store, _, tenant, _ := testStore(t)
	if _, err := store.StageInputEnvelope(context.Background(), tenant, nil); err == nil {
		t.Fatal("empty Input envelope staged content, want refusal")
	}
	if _, err := store.StageInputEnvelope(context.Background(), tenant, []agentruntime.ContentPart{{Kind: agentruntime.ContentText, Text: "", Artifact: nil}}); err == nil {
		t.Fatal("empty text Input envelope staged content, want refusal")
	}
	tooMany := make([]agentruntime.ContentPart, agentruntime.MaxInputParts+1)
	for index := range tooMany {
		tooMany[index] = agentruntime.ContentPart{Kind: agentruntime.ContentText, Text: "x"}
	}
	if _, err := store.StageInputEnvelope(context.Background(), tenant, tooMany); err == nil {
		t.Fatal("oversized Input envelope staged content, want refusal")
	}
}

func TestAgentSpecificationBodyReaderAuthorizesAndSynthesizesRevisionMetadata(t *testing.T) {
	store, _, tenant, _ := testStore(t)
	body := runtimecontent.AgentSpecificationBody{
		Name: "researcher", ModelProfile: "balanced", Instructions: "be safe",
		Tools: []agentruntime.ToolDefinition{{Name: "search", Description: "search"}},
	}
	handoff, err := store.StageAgentSpecificationBody(context.Background(), tenant, body)
	if err != nil {
		t.Fatalf("stage Agent specification body: %v", err)
	}
	commitment, err := store.ValidateAgentSpecificationBodyHandoff(handoff)
	if err != nil {
		t.Fatalf("validate Agent specification body handoff: %v", err)
	}
	agentID, _ := agentruntime.ParseAgentID("agent_1234567890ABCDEF")
	revisionID, _ := agentruntime.ParseAgentRevisionID("arev_1234567890ABCDEF")
	createdAt := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	repository := bodyReaderRepository{record: runtimecontent.AgentSpecificationBodyRecord{
		Tenant: tenant, AgentID: agentID, RevisionID: revisionID, Revision: 1,
		Name: body.Name, ModelProfile: body.ModelProfile, Reference: commitment.Reference, CreatedAt: createdAt,
	}}
	reader, err := runtimecontent.NewAgentSpecificationBodyReader(store, repository)
	if err != nil {
		t.Fatalf("new Agent specification body reader: %v", err)
	}

	got, err := reader.ReadAgentSpecification(context.Background(), tenant, agentID, revisionID)
	if err != nil {
		t.Fatalf("read Agent specification body: %v", err)
	}
	want := agentruntime.AgentSpecification{ID: agentID, RevisionID: revisionID, Revision: 1, Name: body.Name, ModelProfile: body.ModelProfile, Instructions: body.Instructions, Tools: body.Tools, CreatedAt: createdAt}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("synthesized Agent specification = %#v, want %#v", got, want)
	}
}

func TestStoreRejectsAgentSpecificationBodyHandoffFromAnotherContentAuthority(t *testing.T) {
	store, objects, tenant, _ := testStore(t)
	handoff, err := store.StageAgentSpecificationBody(context.Background(), tenant, runtimecontent.AgentSpecificationBody{Name: "researcher", ModelProfile: "balanced", Instructions: "be safe"})
	if err != nil {
		t.Fatalf("stage Agent specification body: %v", err)
	}
	other, err := runtimecontent.New("runtime-content", objects)
	if err != nil {
		t.Fatalf("new other content authority: %v", err)
	}
	if _, err := other.ValidateAgentSpecificationBodyHandoff(handoff); !errors.Is(err, runtimecontent.ErrNotFoundOrDenied) {
		t.Fatalf("foreign handoff error = %v, want ErrNotFoundOrDenied", err)
	}
}

var _ runtimecontent.ContentHandoffValidator = (*runtimecontent.Store)(nil)

type bodyReaderRepository struct {
	record runtimecontent.AgentSpecificationBodyRecord
}

func (repository bodyReaderRepository) AuthorizeAgentSpecificationBodyRead(context.Context, runtimecontent.TenantID, agentruntime.AgentID, agentruntime.AgentRevisionID) (runtimecontent.AgentSpecificationBodyRecord, error) {
	return repository.record, nil
}

type inputEnvelopeRepository struct {
	record runtimecontent.InputEnvelopeRecord
}

func (repository inputEnvelopeRepository) AuthorizeInputEnvelopeRead(context.Context, runtimecontent.TenantID, runtimecontent.PrincipalID, agentruntime.SessionID, agentruntime.InputID) (runtimecontent.InputEnvelopeRecord, error) {
	return repository.record, nil
}

type artifactRepository struct {
	record runtimecontent.ArtifactRecord
}

type toolActionDescriptorRepository struct {
	tenant     runtimecontent.TenantID
	principal  runtimecontent.PrincipalID
	session    agentruntime.SessionID
	turn       agentruntime.TurnID
	toolCallID string
	commitment runtimecontent.ToolActionDescriptorCommitment
}

func (repository toolActionDescriptorRepository) AuthorizeToolActionDescriptorRead(_ context.Context, tenant runtimecontent.TenantID, principal runtimecontent.PrincipalID, session agentruntime.SessionID, turn agentruntime.TurnID, toolCallID string) (runtimecontent.ToolActionDescriptorCommitment, error) {
	if tenant != repository.tenant || principal != repository.principal || session != repository.session || turn != repository.turn || toolCallID != repository.toolCallID {
		return runtimecontent.ToolActionDescriptorCommitment{}, runtimecontent.ErrNotFoundOrDenied
	}
	return repository.commitment, nil
}

func (repository artifactRepository) AuthorizeArtifactRead(context.Context, runtimecontent.TenantID, runtimecontent.PrincipalID, agentruntime.ArtifactID) (runtimecontent.ArtifactRecord, error) {
	return repository.record, nil
}

func testPrincipalID(t *testing.T, value string) runtimecontent.PrincipalID {
	t.Helper()
	principal, err := runtimecontent.ParsePrincipalID(value)
	if err != nil {
		t.Fatalf("parse principal %q: %v", value, err)
	}
	return principal
}
