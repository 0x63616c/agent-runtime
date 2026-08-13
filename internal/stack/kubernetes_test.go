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
		Expect(compact.String()).To(ContainSubstring(`"automountServiceAccountToken":false`))
	})

	It("renders DNS egress only to kube-system CoreDNS over UDP and TCP port 53", func() {
		resources := strings.Replace(kubernetesManifestResources, `"default_deny":true,"subject":"api","allowed_egress":[]`, `"default_deny":true,"subject":"api","allow_dns":true,"allowed_egress":[]`, 1)
		spec, err := stack.Parse(strings.NewReader(stackDocument(resources, resources, resources)))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		manifests, err := stack.RenderKubernetes(rendered)
		Expect(err).NotTo(HaveOccurred())

		var compact bytes.Buffer
		Expect(json.Compact(&compact, manifests.JSON())).To(Succeed())
		Expect(compact.String()).To(ContainSubstring(`"egress":[{"to":[{"podSelector":{"matchLabels":{"k8s-app":"kube-dns"}},"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"kube-system"}}}],"ports":[{"protocol":"UDP","port":53},{"protocol":"TCP","port":53}]}]`))
		Expect(compact.String()).NotTo(ContainSubstring(`"ipBlock"`))
	})

	It("renders an explicit ingress allowlist without admitting external traffic", func() {
		resources := strings.Replace(kubernetesManifestResources, `"allowed_egress":[]`, `"allowed_egress":[],"allowed_ingress":["api"]`, 1)
		spec, err := stack.Parse(strings.NewReader(stackDocument(resources, resources, resources)))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		manifests, err := stack.RenderKubernetes(rendered)
		Expect(err).NotTo(HaveOccurred())
		var compact bytes.Buffer
		Expect(json.Compact(&compact, manifests.JSON())).To(Succeed())
		Expect(compact.String()).To(ContainSubstring(`"policyTypes":["Egress","Ingress"]`))
		Expect(compact.String()).To(ContainSubstring(`"ingress":[{"from":[{"podSelector":{"matchLabels":{"agent-runtime.dev/resource":"api"}}}]}]`))
	})

	It("projects declared secret references and persistent claims without serializing secret values", func() {
		resources := `[
  {"id":"database-credentials","kind":"secret_reference","owner":"platform-operator","scope":"namespace","dependencies":[],"retention":{"policy":"external","days":0},"backup_restore_owner":"platform-operator","delete_behavior":"retain","external_controller":true,"secret_reference":{"provider":"local-generated","reference":"database-credentials","version":"v1","keys":["POSTGRES_PASSWORD"]}},
  {"id":"runtime-account","kind":"kubernetes","owner":"platform-operator","scope":"namespace","dependencies":[],"retention":{"policy":"ephemeral","days":0},"backup_restore_owner":"none","delete_behavior":"delete","external_controller":false,"kubernetes":{"api_version":"v1","kind":"ServiceAccount","name":"runtime-account"}},
  {"id":"postgres-data","kind":"kubernetes","owner":"platform-operator","scope":"namespace","dependencies":[],"retention":{"policy":"ephemeral","days":0},"backup_restore_owner":"none","delete_behavior":"delete","external_controller":false,"kubernetes":{"api_version":"v1","kind":"PersistentVolumeClaim","name":"postgres-data","storage":[{"name":"data","size_bytes":1073741824,"class":"local-path"}]}},
  {"id":"postgres","kind":"kubernetes","owner":"platform-operator","scope":"namespace","dependencies":["database-credentials","runtime-account","postgres-data"],"retention":{"policy":"ephemeral","days":0},"backup_restore_owner":"none","delete_behavior":"delete","external_controller":false,"kubernetes":{"api_version":"apps/v1","kind":"Deployment","name":"postgres","image":"registry.invalid/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","service_account":"runtime-account","secret_environment":[{"name":"POSTGRES_PASSWORD","secret":"database-credentials","key":"POSTGRES_PASSWORD"}],"volume_mounts":[{"claim":"postgres-data","path":"/var/lib/postgresql/data","read_only":false}],"ports":[],"compute":{"request_milli_cpu":100,"limit_milli_cpu":500,"request_memory_bytes":134217728,"limit_memory_bytes":268435456},"storage":[]}}
]`
		spec, err := stack.Parse(strings.NewReader(stackDocument(resources, resources, resources)))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		manifests, err := stack.RenderKubernetes(rendered)
		Expect(err).NotTo(HaveOccurred())
		var compactBuffer bytes.Buffer
		Expect(json.Compact(&compactBuffer, manifests.JSON())).To(Succeed())
		compact := compactBuffer.String()
		Expect(compact).To(ContainSubstring(`"secretKeyRef"`))
		Expect(compact).To(ContainSubstring(`"claimName":"postgres-data"`))
		Expect(compact).NotTo(ContainSubstring(`"value":"POSTGRES_PASSWORD"`))
	})

	It("projects declared ConfigMap keys into a read-only workload path", func() {
		resources := strings.Replace(kubernetesManifestResources, `"dependencies":["runtime-account"]`, `"dependencies":["runtime-account","runtime-config"]`, 1)
		resources = strings.Replace(resources, `"storage":[]}}`, `"storage":[],"config_map_mounts":[{"config_map":"runtime-config","key":"mode","path":"/etc/runtime/mode"}]}}`, 1)
		spec, err := stack.Parse(strings.NewReader(stackDocument(resources, resources, resources)))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		manifests, err := stack.RenderKubernetes(rendered)
		Expect(err).NotTo(HaveOccurred())
		var compact bytes.Buffer
		Expect(json.Compact(&compact, manifests.JSON())).To(Succeed())
		Expect(compact.String()).To(ContainSubstring(`"configMap":{"name":"runtime-config","items":[{"key":"mode","path":"mode"}]}`))
		Expect(compact.String()).To(ContainSubstring(`"mountPath":"/etc/runtime/mode","readOnly":true`))
	})

	It("renders an explicit replica count and declared ingress service route", func() {
		resources := strings.Replace(kubernetesManifestResources, `"name":"api","image"`, `"name":"api","replicas":3,"image"`, 1)
		resources = strings.TrimSuffix(resources, `]`) + `,
  {"id":"api-ingress","kind":"kubernetes","owner":"platform-operator","scope":"namespace","dependencies":["api-service"],"retention":{"policy":"ephemeral","days":0},"backup_restore_owner":"none","delete_behavior":"delete","external_controller":false,"kubernetes":{"api_version":"networking.k8s.io/v1","kind":"Ingress","name":"api-ingress","ingress_rules":[{"host":"api.localhost","path":"/","path_type":"Prefix","service":"api-service","service_port":"http"}]}}
]`
		spec, err := stack.Parse(strings.NewReader(stackDocument(resources, resources, resources)))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		manifests, err := stack.RenderKubernetes(rendered)
		Expect(err).NotTo(HaveOccurred())
		var compact bytes.Buffer
		Expect(json.Compact(&compact, manifests.JSON())).To(Succeed())
		Expect(compact.String()).To(ContainSubstring(`"replicas":3`))
		Expect(compact.String()).To(ContainSubstring(`"pathType":"Prefix"`))
		Expect(compact.String()).To(ContainSubstring(`"service":{"name":"api-service","port":{"name":"http"}}`))
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
