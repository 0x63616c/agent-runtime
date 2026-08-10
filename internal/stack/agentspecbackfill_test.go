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
			strings.Replace(valid, `"teardown_inventory":["agentspecbackfill-crd","agentspecbackfill-validating-admission-policy","agent-spec-backfill-controller","agent-spec-backfill-controller-role-binding","agent-spec-backfill-controller-role","agent-spec-backfill-controller-service-account","agent-spec-backfill-operator-role-binding","agent-spec-backfill-operator-role","agent-spec-backfill-operator-service-account","agent-spec-backfill-routes","agent-spec-backfill-credentials"]`, `"teardown_inventory":["agentspecbackfill-crd","agentspecbackfill-crd","agent-spec-backfill-routes"]`, 1),
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
  "teardown_inventory":["agentspecbackfill-crd","agentspecbackfill-validating-admission-policy","agent-spec-backfill-controller","agent-spec-backfill-controller-role-binding","agent-spec-backfill-controller-role","agent-spec-backfill-controller-service-account","agent-spec-backfill-operator-role-binding","agent-spec-backfill-operator-role","agent-spec-backfill-operator-service-account","agent-spec-backfill-routes","agent-spec-backfill-credentials"]
}`
}
