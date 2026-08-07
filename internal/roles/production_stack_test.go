package roles_test

import (
	"context"
	"os"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/roles"
	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Self-hosted production Stack", func() {
	It("renders explicit trust-scoped roles, secrets, defaults, ingress, and operator dependencies", func() {
		file, err := os.Open("../../deploy/production/stack.json")
		Expect(err).NotTo(HaveOccurred())
		spec, err := stack.Parse(file)
		Expect(file.Close()).To(Succeed())
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileProduction)
		Expect(err).NotTo(HaveOccurred())
		manifests, err := stack.RenderKubernetes(rendered)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(manifests.JSON())).To(ContainSubstring(`"name": "codec-ingress"`))
		Expect(string(manifests.JSON())).To(ContainSubstring(`"host": "codec.agent-runtime.example.invalid"`))
		Expect(string(manifests.JSON())).To(ContainSubstring(`"enableServiceLinks": false`))

		resources := rendered.Resources()
		for _, role := range []stack.ResourceID{"api", "orchestration", "model", "tool", "blob-role", "codec", "sandbox-control", "sandbox-host"} {
			resource := findResource(resources, role)
			Expect(resource.Kubernetes.Replicas).To(BeNumerically(">", 0), role)
			Expect(resource.Kubernetes.ServiceAccount).To(Not(BeEmpty()), role)
			Expect(resource.Kubernetes.Network).To(BeNil(), "network authority is declared by a separate NetworkPolicy resource")
			policy := findResource(resources, stack.ResourceID(string(role)+"-egress"))
			Expect(policy.Kubernetes.Network.DefaultDeny).To(BeTrue(), role)
		}

		Expect(secretEnvironmentNames(findResource(resources, "orchestration"))).To(ContainElement("TEMPORAL_AUTH_TOKEN"))
		Expect(secretEnvironmentNames(findResource(resources, "model"))).NotTo(ContainElement("TEMPORAL_AUTH_TOKEN"))
		Expect(findResource(resources, "model-egress").Kubernetes.Network.AllowedEgress).To(ContainElement(stack.ResourceID("egress-proxy")))
		Expect(findResource(resources, "temporal-namespace").Orchestration.RetentionDays).To(BeNumerically(">", 0))
		Expect(findResource(resources, "runtime-database").Database.Migrations).ToNot(BeEmpty())
		Expect(findResource(resources, "state").Kubernetes.Image).To(Equal("postgres@sha256:e5507c984377515b8c9922b0eb19f55aba2063fdc7bccf268cefd53133f97054"))
		temporal := findResource(resources, "temporal")
		Expect(temporal.Kubernetes.Image).To(Equal("temporalio/auto-setup@sha256:b44cbfeb43dbeae42db113b44fb8414c3452f05643b3d6b1592f955277d73526"))
		bindAddress, found := environmentValue(temporal, "BIND_ON_IP")
		Expect(found).To(BeTrue())
		Expect(bindAddress).To(Equal("0.0.0.0"))
		Expect(temporal.Kubernetes.Readiness.Command).To(ContainElements("--address", "127.0.0.1:7233", "cluster", "health"))
		Expect(findResource(resources, "blob").Kubernetes.Image).To(Equal("minio/minio@sha256:a1ea29fa28355559ef137d71fc570e508a214ec84ff8083e39bc5428980b015e"))
		Expect(findResource(resources, "telemetry").Kubernetes.Image).To(Equal("jaegertracing/all-in-one@sha256:12fa17a231abded2c3b5b715bd252a043678495c588cbe772173991fbdcdf7c8"))
		Expect(findResource(resources, "migration-runner").Kubernetes.Image).To(Equal("postgres@sha256:e5507c984377515b8c9922b0eb19f55aba2063fdc7bccf268cefd53133f97054"))
		for role, fileName := range map[stack.ResourceID]string{
			"api": "api.json", "orchestration": "orchestration.json", "model": "model.json", "tool": "tool.json",
			"blob-role": "blob.json", "codec": "codec.json", "sandbox-control": "sandbox-control.json", "sandbox-host": "sandbox-host.json",
		} {
			configured, readErr := os.ReadFile("../../deploy/production/role-configs/" + fileName)
			Expect(readErr).NotTo(HaveOccurred(), role)
			stackConfig, found := environmentValue(findResource(resources, role), "RUNTIME_ROLE_CONFIG")
			Expect(found).To(BeTrue(), role)
			roleConfig, parseErr := roles.Parse(strings.NewReader(stackConfig))
			Expect(parseErr).NotTo(HaveOccurred(), role)
			referenceConfig, referenceErr := roles.Parse(strings.NewReader(string(configured)))
			Expect(referenceErr).NotTo(HaveOccurred(), role)
			Expect(roleConfig.Role()).To(Equal(referenceConfig.Role()), role)
			Expect(roleConfig.Namespace()).To(Equal(referenceConfig.Namespace()), role)
			plan, prepareErr := roles.Prepare(context.Background(), referenceConfig, universalFixtureSecrets{})
			Expect(prepareErr).NotTo(HaveOccurred(), role)
			Expect(secretEnvironmentNames(findResource(resources, role))).To(ConsistOf(plan.SecretEnvironmentNames()), role)
		}
	})
})

func findResource(resources []stack.Resource, id stack.ResourceID) stack.Resource {
	for _, resource := range resources {
		if resource.ID == id {
			return resource
		}
	}
	Fail("expected declared resource " + string(id))
	return stack.Resource{}
}

func secretEnvironmentNames(resource stack.Resource) []string {
	result := make([]string, 0, len(resource.Kubernetes.SecretEnvironment))
	for _, variable := range resource.Kubernetes.SecretEnvironment {
		result = append(result, variable.Name)
	}
	return result
}

func environmentValue(resource stack.Resource, name string) (string, bool) {
	for _, variable := range resource.Kubernetes.Environment {
		if variable.Name == name {
			return variable.Value, true
		}
	}
	return "", false
}
