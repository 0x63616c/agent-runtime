package stack_test

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Typed Kubernetes manifests", func() {
	It("renders an explicit namespace, bounded workload, least-privilege RBAC, and default-deny egress policy", func() {
		spec, err := stack.Parse(strings.NewReader(stackDocument(kubernetesManifestResources, kubernetesManifestResources, kubernetesManifestResources)))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())

		manifests, err := stack.RenderKubernetes(rendered)
		Expect(err).NotTo(HaveOccurred())
		Expect(manifests.Namespace().Kind).To(Equal("Namespace"))
		Expect(manifests.Namespace().Metadata.Name).To(Equal("ar-feature-a"))
		Expect(manifests.Objects()).To(HaveLen(7))
		var compact bytes.Buffer
		Expect(json.Compact(&compact, manifests.JSON())).To(Succeed())
		Expect(compact.String()).To(ContainSubstring(`"agent-runtime.dev/stack":"feature-a"`))
		Expect(compact.String()).To(ContainSubstring(`"kind":"NetworkPolicy"`))
		Expect(compact.String()).To(ContainSubstring(`"podSelector":{"matchLabels":{"agent-runtime.dev/resource":"api"}}`))
		Expect(compact.String()).To(ContainSubstring(`"resources":{"limits":{"cpu":"500m","memory":"256Mi"},"requests":{"cpu":"100m","memory":"128Mi"}}`))
	})
})

const kubernetesManifestResources = `[
  {"id":"runtime-account","kind":"kubernetes","owner":"platform-operator","scope":"namespace","dependencies":[],"retention":{"policy":"ephemeral","days":0},"backup_restore_owner":"none","delete_behavior":"delete","external_controller":false,"kubernetes":{"api_version":"v1","kind":"ServiceAccount","name":"runtime-account"}},
  {"id":"runtime-role","kind":"kubernetes","owner":"platform-operator","scope":"namespace","dependencies":[],"retention":{"policy":"ephemeral","days":0},"backup_restore_owner":"none","delete_behavior":"delete","external_controller":false,"kubernetes":{"api_version":"rbac.authorization.k8s.io/v1","kind":"Role","name":"runtime-role","permissions":[{"api_group":"","resource":"configmaps","verbs":["get"]}]}},
  {"id":"runtime-binding","kind":"kubernetes","owner":"platform-operator","scope":"namespace","dependencies":["runtime-account","runtime-role"],"retention":{"policy":"ephemeral","days":0},"backup_restore_owner":"none","delete_behavior":"delete","external_controller":false,"kubernetes":{"api_version":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","name":"runtime-binding","service_account":"runtime-account","role":"runtime-role"}},
  {"id":"runtime-config","kind":"kubernetes","owner":"platform-operator","scope":"namespace","dependencies":[],"retention":{"policy":"ephemeral","days":0},"backup_restore_owner":"none","delete_behavior":"delete","external_controller":false,"kubernetes":{"api_version":"v1","kind":"ConfigMap","name":"runtime-config","data":{"mode":"test"}}},
  {"id":"api","kind":"kubernetes","owner":"platform-operator","scope":"namespace","dependencies":["runtime-account"],"retention":{"policy":"ephemeral","days":0},"backup_restore_owner":"none","delete_behavior":"delete","external_controller":false,"kubernetes":{"api_version":"apps/v1","kind":"Deployment","name":"api","image":"registry.invalid/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","service_account":"runtime-account","ports":[{"name":"http","number":8080,"protocol":"TCP"}],"compute":{"request_milli_cpu":100,"limit_milli_cpu":500,"request_memory_bytes":134217728,"limit_memory_bytes":268435456},"storage":[]}},
  {"id":"api-service","kind":"kubernetes","owner":"platform-operator","scope":"namespace","dependencies":["api"],"retention":{"policy":"ephemeral","days":0},"backup_restore_owner":"none","delete_behavior":"delete","external_controller":false,"kubernetes":{"api_version":"v1","kind":"Service","name":"api-service","selector":"api","ports":[{"name":"http","number":8080,"protocol":"TCP"}]}},
  {"id":"deny-api-egress","kind":"kubernetes","owner":"platform-operator","scope":"namespace","dependencies":["api"],"retention":{"policy":"ephemeral","days":0},"backup_restore_owner":"none","delete_behavior":"delete","external_controller":false,"kubernetes":{"api_version":"networking.k8s.io/v1","kind":"NetworkPolicy","name":"deny-api-egress","network":{"default_deny":true,"subject":"api","allowed_egress":[]}}}
]`
