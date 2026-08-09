package architecture_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/afkevidence"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("M1 deployment safety boundaries", func() {
	It("uses audited bootstrap and teardown with generated file-backed smoke credentials", func() {
		script := read("deploy/production/run-kubernetes-smoke.sh")
		for _, required := range []string{
			`AGENT_RUNTIME_SMOKE_KUBECONFIG:?`,
			`AGENT_RUNTIME_SMOKE_CONTEXT:?`,
			`AGENT_RUNTIME_SMOKE_AUDIT:?`,
			`AGENT_RUNTIME_SMOKE_EVIDENCE:?`,
			`profile="local"`,
			`stackctl" bootstrap`,
			`stackctl" apply`,
			`stackctl" teardown`,
			`mktemp -d`,
			`openssl rand -hex 32`,
			`tr -d '\n'`,
			`--from-file=`,
			`create -f -`,
			`stackctl" reconcile`,
			`http://sandbox-control:8086/readyz`,
			`credential_matrix:{expected_rejections:$expected_rejections,rejected:$rejected,allowed_paths:$allowed_paths,secret_values_redacted:true}`,
		} {
			Expect(script).To(ContainSubstring(required))
		}
		Expect(script).To(ContainSubstring(`operator_arguments+=(--bootstrap-capability-file "$bootstrap_capability_file")`))
		Expect(script).To(ContainSubstring(`wait --for=delete "namespace/$namespace" --timeout=120s`))
		for _, forbidden := range []string{
			"delete namespace",
			"--from-literal",
			"fixture-password",
			"minioadmin",
			`SMOKE_CONTEXT:-`,
			`apply -f -`,
		} {
			Expect(script).NotTo(ContainSubstring(forbidden))
		}
	})

	It("validates every AFK record and keeps integration-specific evidence outside that schema", func() {
		paths, err := filepath.Glob(filepath.Join("..", "..", "evidence", "afk", "*.json"))
		Expect(err).NotTo(HaveOccurred())
		Expect(paths).NotTo(BeEmpty())
		for _, path := range paths {
			file, openErr := os.Open(path)
			Expect(openErr).NotTo(HaveOccurred(), path)
			_, parseErr := afkevidence.Parse(file)
			Expect(file.Close()).To(Succeed())
			Expect(parseErr).NotTo(HaveOccurred(), path)
		}
		_, err = os.Stat(filepath.Join("..", "..", "evidence", "afk", "m1-self-hosted-runtime.json"))
		Expect(os.IsNotExist(err)).To(BeTrue())
		Expect(read("evidence/issue-14-deployment-e2e.json")).To(ContainSubstring(`"milestone": "M1 self-hosted roles and deployment"`))
		var proof struct {
			ImplementationRevision string `json:"implementation_revision"`
			CredentialMatrix       struct {
				Expected       int  `json:"expected_rejections"`
				Rejected       int  `json:"rejected"`
				AllowedPaths   int  `json:"allowed_paths"`
				SecretRedacted bool `json:"secret_values_redacted"`
			} `json:"credential_matrix"`
			Cleanup struct {
				NamespaceAbsent bool `json:"namespace_absent_after_run"`
				Residuals       int  `json:"labelled_residual_resources"`
			} `json:"cleanup"`
		}
		Expect(json.Unmarshal([]byte(read("evidence/issue-14-deployment-e2e.json")), &proof)).To(Succeed())
		Expect(proof.ImplementationRevision).To(HaveLen(40))
		Expect(proof.CredentialMatrix.Expected).To(Equal(76))
		Expect(proof.CredentialMatrix.Rejected).To(Equal(76))
		Expect(proof.CredentialMatrix.AllowedPaths).To(Equal(8))
		Expect(proof.CredentialMatrix.SecretRedacted).To(BeTrue())
		Expect(proof.Cleanup.NamespaceAbsent).To(BeTrue())
		Expect(proof.Cleanup.Residuals).To(BeZero())

		auditLines := strings.Split(strings.TrimSpace(read("evidence/issue-14-deployment-audit.jsonl")), "\n")
		Expect(auditLines).To(HaveLen(4))
		expected := []struct {
			action string
			result string
		}{{"bootstrap", "bootstrapped"}, {"apply", "applied"}, {"reconcile", "reconciled"}, {"teardown", "torn_down"}}
		for index, line := range auditLines {
			var record struct {
				Action string `json:"action"`
				Result string `json:"result"`
			}
			Expect(json.Unmarshal([]byte(line), &record)).To(Succeed())
			Expect(record.Action).To(Equal(expected[index].action))
			Expect(record.Result).To(Equal(expected[index].result))
		}
		Expect(read("Justfile")).To(ContainSubstring(`for evidence_file in evidence/afk/*.json`))
	})

	It("invokes the real two-Stack isolation proof in a disposable CI cluster", func() {
		workflow := read(".github/workflows/ci.yml")
		for _, required := range []string{
			"two-stack-isolation:",
			"k3d-io/k3d/releases/download/v5.9.0/k3d-linux-amd64",
			"06d8f25bc3a971c4eb29e0ff08429b180402db0f4dec838c9eac427e296800a0",
			"tilt.0.37.6.linux.x86_64.tar.gz",
			"e9672b8a18d43501f35dcfe98465969a7db0e436b36cf0c50c7e6f8d40de5fe6",
			"k3d cluster create agent-runtime-isolated",
			"--api-port 127.0.0.1:6447",
			"--kubeconfig-update-default=false",
			"--kubeconfig-switch-context=false",
			"k3d kubeconfig get agent-runtime-isolated > \"$KUBECONFIG\"",
			"refusing to reuse occupied loopback API port 6447",
			"refusing to reuse occupied loopback registry port 5111",
			"k3d registry create agent-runtime-registry.localhost",
			"registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373",
			"--registry-use k3d-agent-runtime-registry.localhost:5111",
			`api_endpoint="$(kubectl config view --raw --minify`,
			`[[ "$api_endpoint" == https://127.0.0.1:6447 ]]`,
			`[[ "$api_port" =~ ^[1-9][0-9]{0,4}$ ]]`,
			"rancher/k3s:v1.33.9-k3s1@sha256:f17e43023cce2b9c613e198f26e73637bf734b5156d37c9f44819d97bac4d655",
			"Preload and prove the local-path helper image",
			"rancher/mirrored-library-busybox@sha256:101b4afd76732482eff9b95cae5f94bcf295e521fbec4e01b69c5421f3f3f3e5",
			"docker buildx imagetools inspect --raw",
			"timeout 120s docker pull \"$helper_digest_ref\"",
			"node_arch=\"$(kubectl --context \"$context\" get node --no-headers -o json | jq -er '.items | if length == 1 then .[0].status.nodeInfo.architecture else error(\"expected exactly one isolated K3s node\") end')\"",
			"helper_platform_digest=\"$(jq -er --arg architecture \"$node_arch\"",
			"timeout 120s docker pull --platform \"linux/$node_arch\" \"$helper_platform_ref\"",
			"k3d image import \"$helper_image\" --cluster \"$cluster\" --mode direct",
			"timeout 120s docker exec \"k3d-${cluster}-server-0\" crictl pull \"$helper_digest_ref\"",
			"local-path-helper-readiness",
			"local-path-helper-consumer",
			"persistentVolumeClaim:\n                  claimName: local-path-helper-readiness",
			"wait --for=jsonpath='{.status.phase}'=Running pod/local-path-helper-consumer --timeout=120s",
			`docker exec "k3d-${cluster}-server-0" crictl images -o json`,
			"preflight_namespace_absent:true",
			"AGENT_RUNTIME_DEV_CONTEXT: k3d-agent-runtime-isolated",
			"just two-stack-smoke",
			"if: always()",
			"k3d cluster delete agent-runtime-isolated",
			"k3d registry delete agent-runtime-registry.localhost",
			"actions/upload-artifact@",
		} {
			Expect(workflow).To(ContainSubstring(required))
		}
		Expect(read("Tiltfile")).To(ContainSubstring("k3d-agent-runtime-isolated"))
		Expect(read("Tiltfile")).To(ContainSubstring("host_from_cluster='k3d-agent-runtime-registry.localhost:5111'"))
		Expect(read("Tiltfile")).To(ContainSubstring("ci_settings(readiness_timeout=ci_readiness_timeout)"))
		Expect(read("Tiltfile")).To(ContainSubstring("ci_readiness_timeout = '12m' if profile == 'ci' else '10m'"))
		Expect(read("Justfile")).To(ContainSubstring(`two-stack-smoke profile="local"`))
		twoStackScript := read("deploy/dev/run-two-stack-smoke.sh")
		for _, required := range []string{
			`AGENT_RUNTIME_DEV_PROFILE:-local`,
			`AGENT_RUNTIME_TWO_STACK_EVIDENCE`,
			`AGENT_RUNTIME_TWO_STACK_DIAGNOSTICS`,
			`readiness_timeout=12m`,
			`--output-snapshot-on-exit`,
			`tilt-ci.log`,
			`capture_stack_diagnostics`,
			`redact_diagnostics`,
			`[REDACTED]`,
			`declared_egress_consecutive_successes`,
			`default_deny_consecutive_failures`,
			`tilt alpha tiltfile-result`,
			`refuse to adopt pre-existing local Stack state`,
			`remove_local_state "$stack"`,
			`.DefaultRegistry.host == "localhost:5111"`,
			`.CISettings.readinessTimeout == "12m0s"`,
			`contains("docker.io/agent-runtime-dev")`,
			`both_stacks_concurrently_ready:true`,
			`first_teardown_left_second_unchanged:true`,
			`"does not claim Linux KVM or Firecracker isolation"`,
		} {
			Expect(twoStackScript).To(ContainSubstring(required))
		}

		var proof struct {
			ImplementationRevision string `json:"implementation_revision"`
			ConcurrentReady        bool   `json:"both_stacks_concurrently_ready"`
			FirstTeardownIsolated  bool   `json:"first_teardown_left_second_unchanged"`
			NetworkPolicy          struct {
				Allowed int `json:"declared_egress_consecutive_successes"`
				Denied  int `json:"default_deny_consecutive_failures"`
			} `json:"network_policy"`
			Cleanup struct {
				NamespacesAbsent bool `json:"namespaces_absent"`
				LocalStateAbsent bool `json:"local_state_absent"`
			} `json:"cleanup"`
		}
		Expect(json.Unmarshal([]byte(read("evidence/issue-14-two-stack-e2e.json")), &proof)).To(Succeed())
		Expect(proof.ImplementationRevision).To(HaveLen(40))
		Expect(proof.ConcurrentReady).To(BeTrue())
		Expect(proof.FirstTeardownIsolated).To(BeTrue())
		Expect(proof.NetworkPolicy.Allowed).To(Equal(3))
		Expect(proof.NetworkPolicy.Denied).To(Equal(3))
		Expect(proof.Cleanup.NamespacesAbsent).To(BeTrue())
		Expect(proof.Cleanup.LocalStateAbsent).To(BeTrue())
	})

	It("keeps repository-reading deployment assertions out of product package tests", func() {
		_, err := os.Stat(filepath.Join("..", "..", "internal", "roles", "production_stack_test.go"))
		Expect(os.IsNotExist(err)).To(BeTrue())
		Expect(read("tests/architecture/production_stack_test.go")).To(ContainSubstring("Self-hosted production Stack"))
	})
})
