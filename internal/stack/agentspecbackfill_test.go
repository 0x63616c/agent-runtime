package stack_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfillcrd"
	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Static Agent specification backfill declaration", func() {
	It("keeps a legacy Stack absent and binds a declared CRD to its generated digest", func() {
		legacy, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		_, found := legacy.StaticAgentSpecBackfill()
		Expect(found).To(BeFalse())

		declared, err := stack.Parse(strings.NewReader(stackWithStaticBackfill(validStaticBackfillDeclaration())))
		Expect(err).NotTo(HaveOccurred())
		backfill, found := declared.StaticAgentSpecBackfill()
		Expect(found).To(BeTrue())
		Expect(backfill.CRDDigest).To(Equal(staticCRDDigest()))

		_, err = stack.Parse(strings.NewReader(stackWithStaticBackfill(strings.Replace(validStaticBackfillDeclaration(), staticCRDDigest(), "sha256:"+strings.Repeat("0", 64), 1))))
		Expect(err).To(MatchError(ContainSubstring("CRD digest")))
	})

	It("requires complete bounded static control-plane authority", func() {
		valid := validStaticBackfillDeclaration()
		_, err := stack.Parse(strings.NewReader(stackWithStaticBackfill(valid)))
		Expect(err).NotTo(HaveOccurred())

		for _, declaration := range []string{
			strings.Replace(valid, "@sha256:"+strings.Repeat("a", 64), ":latest", 1),
			strings.Replace(valid, `"evidence_retention_days":30,`, "", 1),
			strings.Replace(valid, `"controller_role":"agent-spec-backfill-controller"`, `"controller_role":"other-controller-role"`, 1),
			strings.Replace(valid, `"operator_role_binding":"agent-spec-backfill-operator"`, `"operator_role_binding":"other-operator-role-binding"`, 1),
			strings.Replace(valid, `"kind":"kubernetes_api","namespace":"kube-system"`, `"kind":"kubernetes_api","namespace":"other"`, 1),
			strings.Replace(valid, `"kind":"kubernetes_api","namespace":"kube-system","service":"kubernetes"`, `"kind":"kubernetes_api","namespace":"kube-system","service":"other"`, 1),
			strings.Replace(valid, `"kind":"kubernetes_api","namespace":"kube-system","service":"kubernetes","port_name":"https"`, `"kind":"kubernetes_api","namespace":"kube-system","service":"kubernetes","port_name":"other"`, 1),
			strings.Replace(valid, `"port_name":"https","port_number":443,"protocol":"TCP","authority_digest":"sha256:111`, `"port_name":"https","port_number":8443,"protocol":"TCP","authority_digest":"sha256:111`, 1),
			strings.Replace(valid, `"port_name":"https","port_number":443,"protocol":"TCP","authority_digest":"sha256:111`, `"port_name":"https","port_number":443,"protocol":"UDP","authority_digest":"sha256:111`, 1),
			strings.Replace(valid, `"kind":"database","namespace":"runtime"`, `"kind":"database","namespace":"other"`, 1),
			strings.Replace(valid, `"kind":"database","namespace":"runtime","service":"postgres"`, `"kind":"database","namespace":"runtime","service":"other"`, 1),
			strings.Replace(valid, `"kind":"database","namespace":"runtime","service":"postgres","port_name":"postgres"`, `"kind":"database","namespace":"runtime","service":"postgres","port_name":"other"`, 1),
			strings.Replace(valid, `"port_name":"postgres","port_number":5432,"protocol":"TCP","authority_digest":"sha256:222`, `"port_name":"postgres","port_number":15432,"protocol":"TCP","authority_digest":"sha256:222`, 1),
			strings.Replace(valid, `"port_name":"postgres","port_number":5432,"protocol":"TCP","authority_digest":"sha256:222`, `"port_name":"postgres","port_number":5432,"protocol":"UDP","authority_digest":"sha256:222`, 1),
			strings.Replace(valid, `"kind":"blob","namespace":"runtime"`, `"kind":"blob","namespace":"other"`, 1),
			strings.Replace(valid, `"kind":"blob","namespace":"runtime","service":"object-store"`, `"kind":"blob","namespace":"runtime","service":"other"`, 1),
			strings.Replace(valid, `"kind":"blob","namespace":"runtime","service":"object-store","port_name":"https"`, `"kind":"blob","namespace":"runtime","service":"object-store","port_name":"other"`, 1),
			strings.Replace(valid, `"port_name":"https","port_number":443,"protocol":"TCP","authority_digest":"sha256:333`, `"port_name":"https","port_number":8443,"protocol":"TCP","authority_digest":"sha256:333`, 1),
			strings.Replace(valid, `"port_name":"https","port_number":443,"protocol":"TCP","authority_digest":"sha256:333`, `"port_name":"https","port_number":443,"protocol":"UDP","authority_digest":"sha256:333`, 1),
			strings.Replace(valid, `"teardown_inventory":["agentspecbackfill-crd","agentspecbackfill-validating-admission-policy","agentspecbackfill-validating-admission-policy-binding","agent-spec-backfill-controller","agent-spec-backfill-controller-role-binding","agent-spec-backfill-controller-role","agent-spec-backfill-controller-service-account","agent-spec-backfill-operator-role-binding","agent-spec-backfill-operator-role","agent-spec-backfill-operator-service-account","agent-spec-backfill-routes","agent-spec-backfill-credentials"]`, `"teardown_inventory":["agentspecbackfill-crd","agentspecbackfill-crd","agent-spec-backfill-routes"]`, 1),
			strings.Replace(valid, `"routes":[`, `"raw_dsn":"postgres://secret@example.invalid/runtime","routes":[`, 1),
			strings.Replace(valid, `"kind":"kubernetes_api"`, `"kind":"database"`, 1),
		} {
			_, err := stack.Parse(strings.NewReader(stackWithStaticBackfill(declaration)))
			Expect(err).To(HaveOccurred(), declaration)
		}
	})

	It("renders a canonical not-applied control-plane plan only when declared", func() {
		legacy, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		_, err = stack.RenderStaticAgentSpecBackfill(legacy)
		Expect(err).To(MatchError(ContainSubstring("not declared")))

		declared, err := stack.Parse(strings.NewReader(stackWithStaticBackfill(validStaticBackfillDeclaration())))
		Expect(err).NotTo(HaveOccurred())
		first, err := stack.RenderStaticAgentSpecBackfill(declared)
		Expect(err).NotTo(HaveOccurred())
		second, err := stack.RenderStaticAgentSpecBackfill(declared)
		Expect(err).NotTo(HaveOccurred())
		Expect(first.Digest()).To(MatchRegexp(`^sha256:[a-f0-9]{64}$`))
		Expect(first.JSON()).To(Equal(second.JSON()))
		plan := string(first.JSON())
		Expect(plan).To(ContainSubstring(`"not_applied": true`))
		Expect(strings.Index(plan, `"kind": "blob"`)).To(BeNumerically("<", strings.Index(plan, `"kind": "database"`)))
		Expect(strings.Index(plan, `"kind": "database"`)).To(BeNumerically("<", strings.Index(plan, `"kind": "dns_tcp"`)))
	})

	It("compiles explicit static authority facts into a canonical non-applying inventory", func() {
		declaration := staticBackfillWithAdmissionInventory(validStaticBackfillDeclaration())
		declared, err := stack.Parse(strings.NewReader(stackWithStaticBackfill(declaration)))
		Expect(err).NotTo(HaveOccurred())

		first, err := stack.CompileStaticAgentSpecBackfillInventory(declared)
		Expect(err).NotTo(HaveOccurred())
		second, err := stack.CompileStaticAgentSpecBackfillInventory(declared)
		Expect(err).NotTo(HaveOccurred())
		Expect(first.Digest()).To(MatchRegexp(`^sha256:[a-f0-9]{64}$`))
		Expect(first.JSON()).To(Equal(second.JSON()))
		Expect(string(first.JSON())).To(ContainSubstring(`"not_applied": true`))
		Expect(string(first.JSON())).To(ContainSubstring(`"profile": "production"`))
	})

	It("refuses an inventory that leaves authority, identity, profile, route, or UID-handshake facts implicit", func() {
		valid := staticBackfillWithAdmissionInventory(validStaticBackfillDeclaration())
		for _, declaration := range []string{
			validStaticBackfillDeclaration(),
			strings.Replace(valid, `"profile":"production"`, `"profile":""`, 1),
			strings.Replace(valid, `"owner":"platform-control-plane"`, `"owner":""`, 1),
			strings.Replace(valid, `"subject_kind":"external"`, `"subject_kind":""`, 1),
			strings.Replace(valid, `"kind":"database","namespace":"runtime"`, `"kind":"database","namespace":""`, 1),
			strings.Replace(valid, `"uid_handshake_digest":"sha256:dddd`, `"uid_handshake_digest":"not-a-digest`, 1),
		} {
			declared, err := stack.Parse(strings.NewReader(stackWithStaticBackfill(declaration)))
			if err == nil {
				_, err = stack.CompileStaticAgentSpecBackfillInventory(declared)
			}
			Expect(err).To(HaveOccurred(), declaration)
		}
	})

	It("canonicalizes the declared static identity permissions without widening them", func() {
		firstDeclaration := staticBackfillWithAdmissionInventory(validStaticBackfillDeclaration())
		secondDeclaration := strings.Replace(firstDeclaration,
			`"permissions":[{"api_group":"runtime.0x63616c.dev","resource":"agentspecbackfills","verbs":["get","list","watch"]},{"api_group":"runtime.0x63616c.dev","resource":"agentspecbackfills/status","verbs":["patch","update"]}]`,
			`"permissions":[{"api_group":"runtime.0x63616c.dev","resource":"agentspecbackfills/status","verbs":["update","patch"]},{"api_group":"runtime.0x63616c.dev","resource":"agentspecbackfills","verbs":["watch","get","list"]}]`, 1)
		first, err := stack.Parse(strings.NewReader(stackWithStaticBackfill(firstDeclaration)))
		Expect(err).NotTo(HaveOccurred())
		second, err := stack.Parse(strings.NewReader(stackWithStaticBackfill(secondDeclaration)))
		Expect(err).NotTo(HaveOccurred())

		firstInventory, err := stack.CompileStaticAgentSpecBackfillInventory(first)
		Expect(err).NotTo(HaveOccurred())
		secondInventory, err := stack.CompileStaticAgentSpecBackfillInventory(second)
		Expect(err).NotTo(HaveOccurred())
		Expect(secondInventory.JSON()).To(Equal(firstInventory.JSON()))

		broadened := strings.Replace(firstDeclaration, `"verbs":["create","get"]`, `"verbs":["create","get","list"]`, 1)
		declared, err := stack.Parse(strings.NewReader(stackWithStaticBackfill(broadened)))
		Expect(err).NotTo(HaveOccurred())
		_, err = stack.CompileStaticAgentSpecBackfillInventory(declared)
		Expect(err).To(HaveOccurred())
	})

	It("requires explicit immutable admission policy and binding authority", func() {
		complete := staticBackfillWithAdmissionInventory(validStaticBackfillDeclaration())
		declared, err := stack.Parse(strings.NewReader(stackWithStaticBackfill(complete)))
		Expect(err).NotTo(HaveOccurred())
		_, err = stack.CompileStaticAgentSpecBackfillInventory(declared)
		Expect(err).NotTo(HaveOccurred())

		incomplete, err := stack.Parse(strings.NewReader(stackWithStaticBackfill(staticBackfillWithInventory(validStaticBackfillDeclaration()))))
		Expect(err).NotTo(HaveOccurred())
		_, err = stack.CompileStaticAgentSpecBackfillInventory(incomplete)
		Expect(err).To(HaveOccurred())
	})

	It("refuses an inventory that reuses distinct identity credential authority", func() {
		declaration := strings.Replace(staticBackfillWithAdmissionInventory(validStaticBackfillDeclaration()), `"credential_reference_digest":"sha256:`+strings.Repeat("1", 64)+`"`, `"credential_reference_digest":"sha256:`+strings.Repeat("d", 64)+`"`, 1)
		declared, err := stack.Parse(strings.NewReader(stackWithStaticBackfill(declaration)))
		Expect(err).NotTo(HaveOccurred())
		_, err = stack.CompileStaticAgentSpecBackfillInventory(declared)
		Expect(err).To(HaveOccurred())
	})
})

func stackWithStaticBackfill(declaration string) string {
	return strings.Replace(validIdentityStack, `"profiles":`, `"static_agent_spec_backfill":`+declaration+`,"profiles":`, 1)
}

func staticCRDDigest() string {
	encoded, err := agentspecbackfillcrd.Render()
	Expect(err).NotTo(HaveOccurred())
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validStaticBackfillDeclaration() string {
	return `{
  "version":1,
  "crd_digest":"` + staticCRDDigest() + `",
  "controller":{
    "image":"registry.example.invalid/agent-spec-backfill-controller@sha256:` + strings.Repeat("a", 64) + `",
    "command":["agent-spec-backfill-controller"],
    "arguments":["--config","/etc/agent-runtime/controller.json"],
    "config_digest":"sha256:` + strings.Repeat("b", 64) + `",
    "resources":{"request_milli_cpu":100,"limit_milli_cpu":500,"request_memory_bytes":134217728,"limit_memory_bytes":268435456}
  },
  "identities":{
    "namespace":"agent-spec-backfill",
    "controller_service_account":"agent-spec-backfill-controller",
    "controller_role":"agent-spec-backfill-controller",
    "controller_role_binding":"agent-spec-backfill-controller",
    "operator_service_account":"agent-spec-backfill-operator",
    "operator_role":"agent-spec-backfill-operator",
    "operator_role_binding":"agent-spec-backfill-operator"
  },
  "routes":[
    {"kind":"kubernetes_api","namespace":"kube-system","service":"kubernetes","port_name":"https","port_number":443,"protocol":"TCP","authority_digest":"sha256:` + strings.Repeat("1", 64) + `"},
    {"kind":"database","namespace":"runtime","service":"postgres","port_name":"postgres","port_number":5432,"protocol":"TCP","authority_digest":"sha256:` + strings.Repeat("2", 64) + `"},
    {"kind":"blob","namespace":"runtime","service":"object-store","port_name":"https","port_number":443,"protocol":"TCP","authority_digest":"sha256:` + strings.Repeat("3", 64) + `"},
    {"kind":"dns_tcp","namespace":"kube-system","service":"kube-dns","port_name":"dns-tcp","port_number":53,"protocol":"TCP","authority_digest":"sha256:` + strings.Repeat("4", 64) + `"},
    {"kind":"dns_udp","namespace":"kube-system","service":"kube-dns","port_name":"dns-udp","port_number":53,"protocol":"UDP","authority_digest":"sha256:` + strings.Repeat("5", 64) + `"}
  ],
  "rbac":{"controller_digest":"sha256:` + strings.Repeat("6", 64) + `","operator_digest":"sha256:` + strings.Repeat("7", 64) + `"},
  "credentials":{"controller_reference_digest":"sha256:` + strings.Repeat("8", 64) + `","database_read_capability_digest":"sha256:` + strings.Repeat("9", 64) + `","blob_read_capability_digest":"sha256:` + strings.Repeat("c", 64) + `"},
  "evidence_retention_days":30,
  "teardown_inventory":["agentspecbackfill-crd","agentspecbackfill-validating-admission-policy","agentspecbackfill-validating-admission-policy-binding","agent-spec-backfill-controller","agent-spec-backfill-controller-role-binding","agent-spec-backfill-controller-role","agent-spec-backfill-controller-service-account","agent-spec-backfill-operator-role-binding","agent-spec-backfill-operator-role","agent-spec-backfill-operator-service-account","agent-spec-backfill-routes","agent-spec-backfill-credentials"]
}`
}

func staticBackfillWithInventory(declaration string) string {
	return strings.TrimSuffix(declaration, `}`) + `,
  "inventory":{
    "profile":"production",
    "cluster_ownership":{"owner":"platform-control-plane","authority_digest":"sha256:` + strings.Repeat("a", 64) + `"},
	    "controller_identity":{"subject_kind":"service_account","subject":"agent-spec-backfill-controller","namespace":"agent-spec-backfill","credential_reference_digest":"sha256:` + strings.Repeat("8", 64) + `","rbac_digest":"sha256:` + strings.Repeat("6", 64) + `","permissions":[{"api_group":"runtime.0x63616c.dev","resource":"agentspecbackfills","verbs":["get","list","watch"]},{"api_group":"runtime.0x63616c.dev","resource":"agentspecbackfills/status","verbs":["patch","update"]}]},
    "operator_identity":{"subject_kind":"external","subject":"platform-preflight-operator","namespace":"","credential_reference_digest":"sha256:` + strings.Repeat("c", 64) + `","rbac_digest":"sha256:` + strings.Repeat("7", 64) + `","permissions":[{"api_group":"runtime.0x63616c.dev","resource":"agentspecbackfills","verbs":["create","get"]}]},
    "lifecycle_identity":{"name":"agent-spec-backfill-lifecycle","credential_reference_digest":"sha256:` + strings.Repeat("d", 64) + `","rbac_digest":"sha256:` + strings.Repeat("e", 64) + `","observation_authority_digest":"sha256:` + strings.Repeat("f", 64) + `"},
    "archive_identity":{"name":"agent-spec-backfill-archive","credential_reference_digest":"sha256:` + strings.Repeat("1", 64) + `","rbac_digest":"sha256:` + strings.Repeat("2", 64) + `","archive_policy_digest":"sha256:` + strings.Repeat("3", 64) + `"},
    "runtime_target":{"namespace":"runtime","target_ingress_digest":"sha256:` + strings.Repeat("4", 64) + `","uid_handshake_digest":"sha256:` + strings.Repeat("d", 64) + `"}
  }
}`
}

func staticBackfillWithAdmissionInventory(declaration string) string {
	return strings.Replace(staticBackfillWithInventory(declaration), `"runtime_target":`, `"admission":{"policy_digest":"sha256:`+strings.Repeat("5", 64)+`","binding_digest":"sha256:`+strings.Repeat("6", 64)+`"},"runtime_target":`, 1)
}
