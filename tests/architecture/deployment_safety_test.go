package architecture_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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

	It("bootstraps the disposable NetworkPolicy harness before applying reviewed state", func() {
		script := read("deploy/harness/run-k3s-networkpolicy-evidence.sh")
		for _, required := range []string{
			`bootstrap_capability_file="$harness_tmp/bootstrap-capability.json"`,
			`stackctl bootstrap --stack-file "$v1" --stack issue10-work --profile ci --bootstrap-capability-file "$bootstrap_capability_file"`,
			`stackctl apply --stack-file "$v1" --stack issue10-work --profile ci --bootstrap-capability-file "$bootstrap_capability_file"`,
			`stackctl apply --stack-file "$v2" --stack issue10-work --profile ci --bootstrap-capability-file "$bootstrap_capability_file"`,
		} {
			Expect(script).To(ContainSubstring(required))
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
			ImplementationRevision string          `json:"implementation_revision"`
			ProofProvenance        proofProvenance `json:"proof_provenance"`
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
		verifyRetainedProof("evidence/issue-14-deployment-e2e.json", proof.ImplementationRevision, proof.ProofProvenance)
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
			"fetch-depth: 0",
			"k3d cluster list -o json",
			"k3d registry list -o json",
			`run_identity="${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"`,
			`cluster="ar-ci-$run_identity"`,
			`registry="ar-reg-$run_identity.localhost"`,
			`context="k3d-$cluster"`,
			`kubeconfig="$RUNNER_TEMP/$cluster.kubeconfig"`,
			"refusing to reuse pre-existing generated k3d cluster",
			"refusing to reuse pre-existing generated k3d registry",
			"cluster_create_succeeded=false",
			"registry_create_succeeded=false",
			"k3d-ownership.json",
			"k3d cluster create \"$cluster\"",
			`api_port="$(python3 - "$run_identity"`,
			`--api-port "127.0.0.1:$api_port"`,
			"--kubeconfig-update-default=false",
			"--kubeconfig-switch-context=false",
			"k3d kubeconfig get \"$cluster\" > \"$kubeconfig\"",
			`registry_port="$(python3 - "$run_identity"`,
			`--port "127.0.0.1:$registry_port"`,
			"k3d registry create \"$registry\"",
			"registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373",
			`registry_host="localhost:$registry_host_port"`,
			`registry_host_from_cluster="k3d-$registry:5000"`,
			`--arg port "5000/tcp"`,
			"--registry-use \"$registry_host_from_cluster\"",
			`api_endpoint="$(kubectl config view --raw --minify`,
			`[[ "$api_endpoint" == "https://127.0.0.1:$api_port" ]]`,
			`[[ "$api_port" =~ ^[1-9][0-9]{0,4}$ ]]`,
			"rancher/k3s:v1.33.9-k3s1@sha256:f17e43023cce2b9c613e198f26e73637bf734b5156d37c9f44819d97bac4d655",
			"Preload and prove the local-path helper image",
			"Run M1 Stack contract gate",
			"go test ./internal/stack ./tests/architecture -count=1",
			"m1-stack-contract-evidence.json",
			"local-path helper configuration did not become available",
			"unexpected local-path helper configuration",
			`tr -d '"'`,
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
			"AGENT_RUNTIME_DEV_CONTEXT: ${{ env.AGENT_RUNTIME_CI_CONTEXT }}",
			"AGENT_RUNTIME_CI_CONTEXT: ${{ env.AGENT_RUNTIME_CI_CONTEXT }}",
			"AGENT_RUNTIME_CI_REGISTRY_HOST: ${{ env.AGENT_RUNTIME_CI_REGISTRY_HOST }}",
			"AGENT_RUNTIME_CI_REGISTRY_HOST_FROM_CLUSTER: ${{ env.AGENT_RUNTIME_CI_REGISTRY_HOST_FROM_CLUSTER }}",
			"just two-stack-smoke",
			"if: always()",
			"k3d cluster delete \"$cluster\"",
			"k3d registry delete \"$registry\"",
			"AGENT_RUNTIME_TWO_STACK_DIAGNOSTICS: ${{ runner.temp }}/two-stack-diagnostics",
			"two-stack-diagnostics/*.summary.json",
			"actions/upload-artifact@",
		} {
			Expect(workflow).To(ContainSubstring(required))
		}
		for _, forbidden := range []string{
			"kubernetes-diagnostics.txt",
			"k3s-server.log",
			"kubectl get nodes,namespaces,pods,persistentvolumeclaims --all-namespaces",
			"docker logs k3d-agent-runtime-isolated-server-0",
		} {
			Expect(workflow).NotTo(ContainSubstring(forbidden))
		}
		Expect(read("Tiltfile")).To(ContainSubstring("config.define_string('ci-context'"))
		Expect(read("Tiltfile")).To(ContainSubstring("config.define_string('fixture-scenario'"))
		Expect(read("Tiltfile")).To(ContainSubstring("--fixture-scenario=' + fixture_scenario"))
		Expect(read("Tiltfile")).To(ContainSubstring("config.define_string('ci-registry-host'"))
		Expect(read("Tiltfile")).To(ContainSubstring("config.define_string('ci-registry-host-from-cluster'"))
		Expect(read("Tiltfile")).To(ContainSubstring("default_registry(ci_registry_host, host_from_cluster=ci_registry_host_from_cluster)"))
		Expect(read("Tiltfile")).To(ContainSubstring("ci_settings(readiness_timeout=ci_readiness_timeout)"))
		Expect(read("Tiltfile")).To(ContainSubstring("ci_readiness_timeout = '12m' if profile == 'ci' else '10m'"))
		Expect(read("Tiltfile")).To(ContainSubstring("if profile == 'local':\n    local_resource('stack-reconcile'"))
		Expect(read("Tiltfile")).To(ContainSubstring("deploy/dev/reconcile-ci-stack.sh --stack=' + stack + ' --context=' + ci_context"))
		Expect(read("Tiltfile")).To(ContainSubstring("resource_deps=['state', 'temporal', 'telemetry', 'stack-reconcile']"))
		ciBootstrap := read("deploy/dev/bootstrap-ci-stack.sh")
		for _, required := range []string{"go run ./tools/dev render", "stackctl bootstrap", "--profile ci", "--bootstrap-capability-file", "k3d-ar-ci-*", "CI Stack bootstrap accepts only --stack and --context"} {
			Expect(ciBootstrap).To(ContainSubstring(required))
		}
		unsafeCIBootstrap := exec.Command("bash", "deploy/dev/bootstrap-ci-stack.sh", "--stack=ci-fixture", "--context=orbstack")
		unsafeCIBootstrap.Dir = "../.."
		unsafeBootstrapOutput, unsafeBootstrapErr := unsafeCIBootstrap.CombinedOutput()
		Expect(unsafeBootstrapErr).To(HaveOccurred())
		Expect(string(unsafeBootstrapOutput)).To(ContainSubstring("requires a generated Stack and private k3d context"))
		ciReconcile := read("deploy/dev/reconcile-ci-stack.sh")
		for _, required := range []string{"--profile ci", "--providers-only", "--bootstrap-capability-file", "k3d-ar-ci-*", "CI Stack reconciliation accepts only --stack and --context", "requires existing rendered state and private authority"} {
			Expect(ciReconcile).To(ContainSubstring(required))
		}
		unsafeCIReconcile := exec.Command("bash", "deploy/dev/reconcile-ci-stack.sh", "--stack=ci-fixture", "--context=orbstack")
		unsafeCIReconcile.Dir = "../.."
		unsafeOutput, unsafeErr := unsafeCIReconcile.CombinedOutput()
		Expect(unsafeErr).To(HaveOccurred())
		Expect(string(unsafeOutput)).To(ContainSubstring("requires a generated Stack and private k3d context"))
		// Tilt's restricted build context must include every local source tree
		// copied by the production image, or CI deploys before discovering that
		// the image cannot be built.
		for _, required := range []string{"'cmd/agent-runtime-api'", "'internal'", "'sandbox'", "'temporalpayload'", "'sdk/go'"} {
			Expect(read("Tiltfile")).To(ContainSubstring(required))
		}
		Expect(read("Justfile")).To(ContainSubstring(`two-stack-smoke profile="local"`))
		twoStackScript := read("deploy/dev/run-two-stack-smoke.sh")
		Expect(twoStackScript).To(ContainSubstring("deploy/dev/bootstrap-ci-stack.sh --stack=\"$stack\" --context=\"$context\""))
		Expect(strings.Index(twoStackScript, "deploy/dev/bootstrap-ci-stack.sh --stack=\"$stack\" --context=\"$context\"\n")).To(BeNumerically("<", strings.Index(twoStackScript, "tilt ci --context \"$context\"")), "CI bootstrap must establish namespace authority before Tilt applies the topology")
		for _, required := range []string{
			`AGENT_RUNTIME_DEV_PROFILE:-local`,
			`AGENT_RUNTIME_TWO_STACK_EVIDENCE`,
			`AGENT_RUNTIME_TWO_STACK_DIAGNOSTICS`,
			`readiness_timeout=12m`,
			`write_safe_diagnostic_summary`,
			`diagnostic-summary/v1`,
			`runtime_role_status`,
			`capture_plan_failure_diagnostics`,
			`--self-test-diagnostics`,
			`capture_stack_diagnostics`,
			`declared_egress_consecutive_successes`,
			`default_deny_consecutive_failures`,
			`tilt alpha tiltfile-result`,
			`refuse to adopt pre-existing local Stack state`,
			`remove_local_state "$stack"`,
			`.DefaultRegistry.host == $registry_host`,
			`.DefaultRegistry.hostFromContainerRuntime == $registry_host_from_cluster`,
			`.CISettings.readinessTimeout == "12m0s"`,
			`contains("docker.io/agent-runtime-dev")`,
			`both_stacks_concurrently_ready:true`,
			`first_teardown_left_second_unchanged:true`,
			`"does not claim Linux KVM or Firecracker isolation"`,
			`tilt_down_status=0`,
			`if [[ "$tilt_down_status" != 0 ]] && kubectl --context "$context" get "namespace/$namespace" >/dev/null 2>&1; then`,
			`prepare_evidence_draft`,
			`refusing destructive teardown because the owned two-Stack evidence draft is invalid`,
			`finalize_evidence`,
			`refusing to retain two-Stack evidence before contained teardown is observed`,
			`mv -- "$evidence_temporary" "$evidence_file"`,
		} {
			Expect(twoStackScript).To(ContainSubstring(required))
		}
		Expect(strings.Index(twoStackScript, "prepare_evidence_draft\ndown_stack \"$stack_a\"")).To(BeNumerically(">", 0), "evidence draft must be validated before the first destructive teardown")
		Expect(strings.Index(twoStackScript, "down_stack \"$stack_b\"\ncreated_b=false")).To(BeNumerically("<", strings.LastIndex(twoStackScript, "finalize_evidence")), "final evidence must only be retained after both teardowns")
		for _, forbidden := range []string{
			"redact_diagnostics",
			"tilt-session.raw.json",
			"tilt-ci.raw.log",
			"workload-logs.raw",
			"kubectl --context \"$context\" --namespace \"$namespace\" logs",
		} {
			Expect(twoStackScript).NotTo(ContainSubstring(forbidden))
		}
		selfTest := exec.Command("bash", "deploy/dev/run-two-stack-smoke.sh", "--self-test-diagnostics")
		selfTest.Dir = "../.."
		output, err := selfTest.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(output))
		Expect(string(output)).To(ContainSubstring("safe diagnostic summary rejects raw JSON, header, and environment payloads"))

		var proof struct {
			ImplementationRevision string          `json:"implementation_revision"`
			ProofProvenance        proofProvenance `json:"proof_provenance"`
			ConcurrentReady        bool            `json:"both_stacks_concurrently_ready"`
			FirstTeardownIsolated  bool            `json:"first_teardown_left_second_unchanged"`
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
		verifyRetainedProof("evidence/issue-14-two-stack-e2e.json", proof.ImplementationRevision, proof.ProofProvenance)
		Expect(proof.ConcurrentReady).To(BeTrue())
		Expect(proof.FirstTeardownIsolated).To(BeTrue())
		Expect(proof.NetworkPolicy.Allowed).To(Equal(3))
		Expect(proof.NetworkPolicy.Denied).To(Equal(3))
		Expect(proof.Cleanup.NamespacesAbsent).To(BeTrue())
		Expect(proof.Cleanup.LocalStateAbsent).To(BeTrue())

		var contractProof struct {
			ImplementationRevision string          `json:"implementation_revision"`
			ProofProvenance        proofProvenance `json:"proof_provenance"`
			RenderProfiles         []string        `json:"render_profiles"`
			SchemaPolicyOwnership  bool            `json:"schema_policy_ownership"`
			MigrationRollback      bool            `json:"migration_upgrade_rollback"`
			RBACNegative           bool            `json:"rbac_negative"`
			NetworkPolicyAdmission bool            `json:"network_policy_admission"`
			Result                 string          `json:"result"`
		}
		Expect(json.Unmarshal([]byte(read("evidence/issue-14-m1-stack-contract-e2e.json")), &contractProof)).To(Succeed())
		verifyRetainedProof("evidence/issue-14-m1-stack-contract-e2e.json", contractProof.ImplementationRevision, contractProof.ProofProvenance)
		Expect(contractProof.RenderProfiles).To(ConsistOf("local", "ci", "production"))
		Expect(contractProof.SchemaPolicyOwnership).To(BeTrue())
		Expect(contractProof.MigrationRollback).To(BeTrue())
		Expect(contractProof.RBACNegative).To(BeTrue())
		Expect(contractProof.NetworkPolicyAdmission).To(BeTrue())
		Expect(contractProof.Result).To(Equal("passed"))
	})

	It("describes deterministic CI loopback-port selection truthfully", func() {
		for _, document := range []string{
			read("docs/operations/self-hosted-deployment.md"),
			read("website/src/content/docs/docs/build-and-run/local-stack.mdx"),
		} {
			Expect(document).To(ContainSubstring("availability-checks"))
			Expect(document).To(ContainSubstring("TOCTOU"))
			Expect(document).To(ContainSubstring("fails safely"))
			Expect(document).To(ContainSubstring("OS-selected port"))
			Expect(document).NotTo(ContainSubstring("OS-selected loopback"))
		}
	})

	It("never treats a failed or raced k3d create as authority to delete", func() {
		workflow := read(".github/workflows/ci.yml")
		for _, required := range []string{
			"registry_create_succeeded=false",
			"cluster_create_succeeded=false",
			`if k3d registry create "$registry"`,
			`if k3d cluster create "$cluster"`,
			"registry_create_succeeded=true",
			"cluster_create_succeeded=true",
			`if [[ "$cluster_create_succeeded" == true ]]`,
			`if [[ "$registry_create_succeeded" == true ]]`,
			"failed k3d registry creation is retained for diagnosis without deletion",
			"failed k3d cluster creation is retained for diagnosis without deletion",
			"${{ runner.temp }}/k3d-ownership.json",
		} {
			Expect(workflow).To(ContainSubstring(required))
		}
		for _, forbidden := range []string{
			"cluster_creation_started",
			"registry_creation_started",
		} {
			Expect(workflow).NotTo(ContainSubstring(forbidden))
		}

		registryCreate := strings.Index(workflow, `if k3d registry create "$registry"`)
		registrySuccess := strings.Index(workflow, "registry_create_succeeded=true")
		clusterCreate := strings.Index(workflow, `if k3d cluster create "$cluster"`)
		clusterSuccess := strings.Index(workflow, "cluster_create_succeeded=true")
		Expect(registryCreate).To(BeNumerically(">=", 0))
		Expect(registrySuccess).To(BeNumerically(">", registryCreate))
		Expect(clusterCreate).To(BeNumerically(">=", 0))
		Expect(clusterSuccess).To(BeNumerically(">", clusterCreate))
	})

	It("refuses cleanup when a same-named k3d resource was replaced", func() {
		workflow := read(".github/workflows/ci.yml")
		for _, required := range []string{
			`registry_container="k3d-$registry"`,
			`cluster_server_container="k3d-${cluster}-server-0"`,
			`registry_container_id="$(docker container inspect --format '{{.Id}}' "$registry_container")"`,
			`cluster_server_container_id="$(docker container inspect --format '{{.Id}}' "$cluster_server_container")"`,
			"registry_container_id:$registry_container_id",
			"cluster_server_container_id:$cluster_server_container_id",
			"container_identity_matches",
			`if container_identity_matches "$cluster_server_container" "$cluster_server_container_id"; then`,
			`if container_identity_matches "$registry_container" "$registry_container_id"; then`,
			"refusing to delete k3d cluster with mismatched server container identity",
			"refusing to delete k3d registry with mismatched container identity",
		} {
			Expect(workflow).To(ContainSubstring(required))
		}

		registrySuccess := strings.Index(workflow, "registry_create_succeeded=true")
		registryIdentity := strings.Index(workflow, `registry_container_id="$(docker container inspect`)
		clusterSuccess := strings.Index(workflow, "cluster_create_succeeded=true")
		clusterIdentity := strings.Index(workflow, `cluster_server_container_id="$(docker container inspect`)
		Expect(registryIdentity).To(BeNumerically(">", registrySuccess))
		Expect(clusterIdentity).To(BeNumerically(">", clusterSuccess))
	})

	It("keeps repository-reading deployment assertions out of product package tests", func() {
		_, err := os.Stat(filepath.Join("..", "..", "internal", "roles", "production_stack_test.go"))
		Expect(os.IsNotExist(err)).To(BeTrue())
		Expect(read("tests/architecture/production_stack_test.go")).To(ContainSubstring("Self-hosted production Stack"))
	})
})

type proofProvenance struct {
	SourceRevision         string `json:"source_revision"`
	SourceTreeID           string `json:"source_tree_id"`
	RetentionRevision      string `json:"retention_revision"`
	RetainedArtifactSHA256 string `json:"retained_artifact_sha256"`
}

func verifyRetainedProof(path, implementationRevision string, provenance proofProvenance) {
	Expect(provenance.SourceRevision).To(Equal(implementationRevision), path)
	Expect(provenance.SourceRevision).To(HaveLen(40), path)
	Expect(provenance.RetentionRevision).To(HaveLen(40), path)
	Expect(provenance.RetentionRevision).NotTo(Equal(provenance.SourceRevision), path)
	Expect(provenance.SourceTreeID).To(HaveLen(40), path)
	Expect(provenance.RetainedArtifactSHA256).To(MatchRegexp(`^sha256:[a-f0-9]{64}$`), path)

	root := "../.."
	ancestor := exec.Command("git", "merge-base", "--is-ancestor", provenance.SourceRevision, provenance.RetentionRevision)
	ancestor.Dir = root
	output, err := ancestor.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), string(output), path)

	treeID := gitOutput(root, "rev-parse", provenance.SourceRevision+"^{tree}")
	Expect(provenance.SourceTreeID).To(Equal(treeID), path)
	historical := gitBytes(root, "show", provenance.RetentionRevision+":"+path)
	sum := sha256.Sum256([]byte(historical))
	Expect(provenance.RetainedArtifactSHA256).To(Equal(fmt.Sprintf("sha256:%x", sum)), path)
	var historicalProof struct {
		ImplementationRevision string `json:"implementation_revision"`
	}
	Expect(json.Unmarshal([]byte(historical), &historicalProof)).To(Succeed(), path)
	Expect(historicalProof.ImplementationRevision).To(Equal(provenance.SourceRevision), path)
}

func gitOutput(directory string, arguments ...string) string {
	return strings.TrimSpace(gitBytes(directory, arguments...))
}

func gitBytes(directory string, arguments ...string) string {
	command := exec.Command("git", arguments...)
	command.Dir = directory
	output, err := command.Output()
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), strings.Join(arguments, " "))
	return string(output)
}
