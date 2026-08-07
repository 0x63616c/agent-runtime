package stack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/cockroachdb/errors"
)

const reconcileBlobScript = `set -eu
mc alias set declared "$3" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null
mc mb --ignore-existing "declared/$1" >/dev/null
printf '%s' "$2" | mc pipe "declared/$1/$2/.agent-runtime-prefix" >/dev/null
test "$(mc cat "declared/$1/$2/.agent-runtime-prefix")" = "$2"`

const teardownBlobScript = `set -eu
mc alias set declared "$3" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null
bucket_listing="$(mc ls "declared/$1" 2>&1)" || {
  status=$?
  case "$bucket_listing" in
    *"does not exist."*) exit 0 ;;
    *) printf '%s\n' "$bucket_listing" >&2; exit "$status" ;;
  esac
}
mc rm --recursive --force "declared/$1/$2" >/dev/null
mc rb "declared/$1" >/dev/null`

const (
	externalControllerLabel = "agent-runtime.dev/external-controller"
	bootstrapUIDAnnotation  = "agent-runtime.dev/bootstrap-uid"
	renderDigestAnnotation  = "agent-runtime.dev/render-digest"
)

// KubectlDeclaredProviderAdapter reconciles the complete non-Kubernetes portion
// of a Stack through explicitly declared in-cluster operator workloads.
type KubectlDeclaredProviderAdapter struct {
	runner        KubectlCommandRunner
	orchestration TemporalCLIAdapter
}

// NewKubectlDeclaredProviderAdapter constructs the provider-complete adapter.
func NewKubectlDeclaredProviderAdapter(runner KubectlCommandRunner) (KubectlDeclaredProviderAdapter, error) {
	if runner == nil {
		return KubectlDeclaredProviderAdapter{}, errors.New("construct declared provider adapter: command runner is required")
	}
	orchestration, err := NewTemporalCLIAdapter(runner)
	if err != nil {
		return KubectlDeclaredProviderAdapter{}, err
	}
	return KubectlDeclaredProviderAdapter{runner: runner, orchestration: orchestration}, nil
}

// ReconcileDeclared reconciles or verifies every non-Kubernetes resource.
func (adapter KubectlDeclaredProviderAdapter) ReconcileDeclared(ctx context.Context, target OperatorTarget, rendered Rendered, authority BootstrapAuthority) ([]ResourceID, error) {
	document, resources, err := declaredProviderDocument(rendered)
	if err != nil {
		return nil, err
	}
	if err := adapter.verifyBootstrapAuthority(ctx, target, rendered, authority); err != nil {
		return nil, err
	}
	ids := make([]ResourceID, 0)
	for _, resource := range document.Resources {
		if resource.Kind == ResourceKubernetes {
			continue
		}
		if err := adapter.verifyBootstrapAuthority(ctx, target, rendered, authority); err != nil {
			return nil, err
		}
		var reconcileErr error
		switch resource.Kind {
		case ResourceSecretReference:
			_, reconcileErr = adapter.verifySecretReference(ctx, target, document, resource)
		case ResourceDatabase:
			reconcileErr = adapter.verifyDatabase(ctx, target, document.Namespace, resource, resources)
		case ResourceOrchestration:
			_, reconcileErr = adapter.orchestration.ReconcileOrchestration(ctx, target, rendered, authority)
		case ResourceBlob:
			reconcileErr = adapter.reconcileBlob(ctx, target, document.Namespace, resource, resources)
		case ResourceTelemetry:
			reconcileErr = adapter.verifyTelemetry(ctx, target, document.Namespace, resource, resources)
		default:
			reconcileErr = errors.Newf("reconcile declared provider resource %s: unsupported kind %s", resource.ID, resource.Kind)
		}
		if reconcileErr != nil {
			return nil, errors.Wrapf(reconcileErr, "reconcile declared provider resource %s", resource.ID)
		}
		ids = append(ids, resource.ID)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	return ids, nil
}

// TeardownDeclared applies explicit provider delete behavior before Kubernetes dependencies disappear.
func (adapter KubectlDeclaredProviderAdapter) TeardownDeclared(ctx context.Context, target OperatorTarget, rendered Rendered, authority BootstrapAuthority) ([]ResourceID, error) {
	document, resources, err := declaredProviderDocument(rendered)
	if err != nil {
		return nil, err
	}
	if err := adapter.verifyBootstrapAuthority(ctx, target, rendered, authority); err != nil {
		return nil, err
	}
	capability := authority
	for _, resource := range document.Resources {
		if resource.Kind != ResourceSecretReference || resource.DeleteBehavior != DeleteOwned || resource.SecretReference.Provider != "local-generated" {
			continue
		}
		if _, _, err := adapter.preflightLocalGeneratedSecretDelete(ctx, target, document, resource, capability); err != nil {
			return nil, errors.Wrapf(err, "preflight declared provider resource %s", resource.ID)
		}
	}
	ids := make([]ResourceID, 0)
	for index := len(document.Resources) - 1; index >= 0; index-- {
		resource := document.Resources[index]
		if resource.Kind == ResourceKubernetes {
			continue
		}
		if err := adapter.verifyBootstrapAuthority(ctx, target, rendered, authority); err != nil {
			return nil, err
		}
		if resource.DeleteBehavior == DeleteTombstone {
			return nil, errors.Newf("teardown declared provider resource %s: tombstone adapter is required", resource.ID)
		}
		if resource.DeleteBehavior == DeleteOwned {
			switch resource.Kind {
			case ResourceBlob:
				if err := adapter.teardownBlob(ctx, target, document.Namespace, resource, resources); err != nil {
					return nil, errors.Wrapf(err, "teardown declared provider resource %s", resource.ID)
				}
			case ResourceOrchestration:
				if err := adapter.orchestration.TeardownOrchestration(ctx, target, rendered, resource.ID, authority); err != nil {
					return nil, errors.Wrapf(err, "teardown declared provider resource %s", resource.ID)
				}
			case ResourceDatabase, ResourceTelemetry:
				// Their declared authority is physically contained by identity-bound
				// Kubernetes storage and is removed by the following Kubernetes plan.
			case ResourceSecretReference:
				if resource.SecretReference.Provider != "local-generated" {
					return nil, errors.Newf("teardown declared provider resource %s: only local-generated secret references can be deleted", resource.ID)
				}
				identity, alreadyDeleted, verifyErr := adapter.preflightLocalGeneratedSecretDelete(ctx, target, document, resource, capability)
				if verifyErr != nil {
					return nil, errors.Wrapf(verifyErr, "teardown declared provider resource %s", resource.ID)
				}
				if alreadyDeleted {
					break
				}
				if progressErr := RecordDeletedSecret(&capability, resource.ID, identity.uid); progressErr != nil {
					return nil, errors.Wrapf(progressErr, "record pending teardown declared provider resource %s", resource.ID)
				}
				result, deleteErr := adapter.deleteVerifiedSecret(ctx, target, document.Namespace, resource.SecretReference.Reference, identity)
				if deleteErr != nil {
					return nil, errors.Wrapf(deleteErr, "teardown declared provider resource %s", resource.ID)
				}
				if result.ExitCode != 0 {
					return nil, errors.Wrapf(kubectlExitError("delete declared local-generated Secret", result.ExitCode), "teardown declared provider resource %s", resource.ID)
				}
			}
		}
		ids = append(ids, resource.ID)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	return ids, nil
}

func (adapter KubectlDeclaredProviderAdapter) preflightLocalGeneratedSecretDelete(ctx context.Context, target OperatorTarget, document renderedDocument, resource Resource, authority BootstrapAuthority) (verifiedSecretIdentity, bool, error) {
	result, err := adapter.run(ctx, target, []string{"get", "Secret/" + resource.SecretReference.Reference, "--namespace", document.Namespace, "-o", "json"}, nil)
	if err != nil {
		return verifiedSecretIdentity{}, false, err
	}
	if result.ExitCode != 0 {
		if strings.Contains(string(result.Output), "NotFound") && authority.DeletedSecrets[resource.ID] != "" {
			return verifiedSecretIdentity{uid: authority.DeletedSecrets[resource.ID]}, true, nil
		}
		return verifiedSecretIdentity{}, false, kubectlExitError("get declared Secret reference", result.ExitCode)
	}
	identity, err := adapter.verifySecretReference(ctx, target, document, resource)
	if err != nil {
		return verifiedSecretIdentity{}, false, err
	}
	if recorded := authority.DeletedSecrets[resource.ID]; recorded != "" && recorded != identity.uid {
		return verifiedSecretIdentity{}, false, errors.New("verify declared Secret reference: pending deletion identity changed")
	}
	return identity, false, nil
}

func declaredProviderDocument(rendered Rendered) (renderedDocument, map[ResourceID]Resource, error) {
	document, err := parseRenderedBytes(rendered.JSON())
	if err != nil {
		return renderedDocument{}, nil, errors.Wrap(err, "prepare declared provider reconciliation")
	}
	return document, resourcesByID(document.Resources), nil
}

type verifiedSecretIdentity struct {
	uid             ObservedUID
	resourceVersion string
}

func (adapter KubectlDeclaredProviderAdapter) verifySecretReference(ctx context.Context, target OperatorTarget, document renderedDocument, resource Resource) (verifiedSecretIdentity, error) {
	result, err := adapter.run(ctx, target, []string{"get", "Secret/" + resource.SecretReference.Reference, "--namespace", document.Namespace, "-o", "json"}, nil)
	if err != nil {
		return verifiedSecretIdentity{}, err
	}
	if result.ExitCode != 0 {
		return verifiedSecretIdentity{}, kubectlExitError("get declared Secret reference", result.ExitCode)
	}
	var secret struct {
		Metadata struct {
			UID             ObservedUID       `json:"uid"`
			ResourceVersion string            `json:"resourceVersion"`
			Labels          map[string]string `json:"labels"`
			Annotations     map[string]string `json:"annotations"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(result.Output, &secret); err != nil {
		return verifiedSecretIdentity{}, errors.Wrap(err, "decode declared Secret reference")
	}
	actual := make([]string, 0, len(secret.Data))
	for key := range secret.Data {
		actual = append(actual, key)
	}
	expected := append([]string(nil), resource.SecretReference.Keys...)
	sort.Strings(actual)
	sort.Strings(expected)
	if strings.Join(actual, "\x00") != strings.Join(expected, "\x00") {
		return verifiedSecretIdentity{}, errors.New("verify declared Secret reference: key inventory differs from desired state")
	}
	if resource.SecretReference.Provider != "local-generated" {
		return verifiedSecretIdentity{}, nil
	}
	namespaceResult, err := adapter.run(ctx, target, []string{"get", "Namespace/" + document.Namespace, "-o", "json"}, nil)
	if err != nil {
		return verifiedSecretIdentity{}, err
	}
	if namespaceResult.ExitCode != 0 {
		return verifiedSecretIdentity{}, kubectlExitError("get Namespace for local-generated Secret proof", namespaceResult.ExitCode)
	}
	var namespace struct {
		Metadata struct {
			UID    string            `json:"uid"`
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(namespaceResult.Output, &namespace); err != nil {
		return verifiedSecretIdentity{}, errors.Wrap(err, "decode Namespace for local-generated Secret proof")
	}
	expectedNamespaceLabels := map[string]string{partOfLabel: document.Labels.PartOf, stackLabel: document.Stack, profileLabel: string(document.Profile)}
	if namespace.Metadata.UID == "" || !containsStringMap(namespace.Metadata.Labels, expectedNamespaceLabels) || !onlyExpectedNamespaceLabels(namespace.Metadata.Labels, document.Namespace) {
		return verifiedSecretIdentity{}, errors.New("verify local-generated Secret reference: Namespace identity or labels differ from desired state")
	}
	expectedSecretLabels := map[string]string{partOfLabel: document.Labels.PartOf, stackLabel: document.Stack, profileLabel: string(document.Profile), externalControllerLabel: "local-generated"}
	expectedAnnotations := map[string]string{bootstrapUIDAnnotation: namespace.Metadata.UID, renderDigestAnnotation: document.Digest}
	if secret.Metadata.UID == "" || secret.Metadata.ResourceVersion == "" || !equalStringMap(secret.Metadata.Labels, expectedSecretLabels) || !equalStringMap(secret.Metadata.Annotations, expectedAnnotations) {
		return verifiedSecretIdentity{}, errors.New("verify local-generated Secret reference: identity binding differs from desired state")
	}
	return verifiedSecretIdentity{uid: secret.Metadata.UID, resourceVersion: secret.Metadata.ResourceVersion}, nil
}

func (adapter KubectlDeclaredProviderAdapter) verifyBootstrapAuthority(ctx context.Context, target OperatorTarget, rendered Rendered, authority BootstrapAuthority) error {
	manifests, err := RenderKubernetes(rendered)
	if err != nil {
		return err
	}
	kubernetes := KubectlAdapter{runner: adapter.runner}
	return kubernetes.verifyBootstrapAuthority(ctx, target, manifests, authority)
}

func (adapter KubectlDeclaredProviderAdapter) deleteVerifiedSecret(ctx context.Context, target OperatorTarget, namespace, name string, identity verifiedSecretIdentity) (KubectlCommandResult, error) {
	if identity.uid == "" || identity.resourceVersion == "" {
		return KubectlCommandResult{}, errors.New("delete declared local-generated Secret: verified UID and resource version are required")
	}
	deleteOptions := struct {
		APIVersion    string `json:"apiVersion"`
		Kind          string `json:"kind"`
		Preconditions struct {
			UID             ObservedUID `json:"uid"`
			ResourceVersion string      `json:"resourceVersion"`
		} `json:"preconditions"`
	}{APIVersion: "v1", Kind: "DeleteOptions"}
	deleteOptions.Preconditions.UID = identity.uid
	deleteOptions.Preconditions.ResourceVersion = identity.resourceVersion
	input, err := json.Marshal(deleteOptions)
	if err != nil {
		return KubectlCommandResult{}, errors.Wrap(err, "encode declared local-generated Secret delete preconditions")
	}
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/secrets/" + url.PathEscape(name)
	result, err := adapter.run(ctx, target, []string{"delete", "--raw", path, "-f", "-"}, append(input, '\n'))
	if err != nil {
		return KubectlCommandResult{}, err
	}
	if result.ExitCode != 0 {
		return KubectlCommandResult{}, kubectlExitError("delete declared local-generated Secret with verified preconditions", result.ExitCode)
	}
	return result, nil
}

func equalStringMap(actual, expected map[string]string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func containsStringMap(actual, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func onlyExpectedNamespaceLabels(labels map[string]string, namespace string) bool {
	for key, value := range labels {
		switch key {
		case partOfLabel, stackLabel, profileLabel:
			continue
		case "kubernetes.io/metadata.name":
			if value == namespace {
				continue
			}
		}
		return false
	}
	return true
}

func (adapter KubectlDeclaredProviderAdapter) verifyDatabase(ctx context.Context, target OperatorTarget, namespace string, resource Resource, resources map[ResourceID]Resource) error {
	workload := resources[resource.Database.MigrationTarget]
	if err := adapter.waitForWorkload(ctx, target, namespace, workload.Kubernetes); err != nil {
		return err
	}
	user := "postgres"
	for _, variable := range workload.Kubernetes.Environment {
		if variable.Name == "POSTGRES_USER" {
			user = variable.Value
			break
		}
	}
	query := fmt.Sprintf("SELECT 1 FROM information_schema.schemata WHERE schema_name = '%s'", resource.Database.Schema)
	arguments := []string{"exec", workload.Kubernetes.Kind + "/" + workload.Kubernetes.Name, "--namespace", namespace, "--", "psql", "-At", "-U", user, "-d", resource.Database.Database, "-c", query}
	result, err := adapter.run(ctx, target, arguments, nil)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 || strings.TrimSpace(string(result.Output)) != "1" {
		return errors.New("verify declared database schema: reviewed schema is unavailable")
	}
	return nil
}

func (adapter KubectlDeclaredProviderAdapter) reconcileBlob(ctx context.Context, target OperatorTarget, namespace string, resource Resource, resources map[ResourceID]Resource) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := adapter.runBlobScript(ctx, target, namespace, resource, resources, reconcileBlobScript); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if err := ctx.Err(); err != nil {
			return errors.Wrap(err, "reconcile declared blob")
		}
	}
	return errors.Wrap(lastErr, "reconcile declared blob after 3 bounded attempts")
}

func (adapter KubectlDeclaredProviderAdapter) teardownBlob(ctx context.Context, target OperatorTarget, namespace string, resource Resource, resources map[ResourceID]Resource) error {
	return adapter.runBlobScript(ctx, target, namespace, resource, resources, teardownBlobScript)
}

func (adapter KubectlDeclaredProviderAdapter) runBlobScript(ctx context.Context, target OperatorTarget, namespace string, resource Resource, resources map[ResourceID]Resource, script string) error {
	declaration := resource.Blob
	reconciler := resources[declaration.ReconcilerReference]
	service := resources[declaration.EndpointReference]
	if err := adapter.waitForWorkload(ctx, target, namespace, reconciler.Kubernetes); err != nil {
		return err
	}
	port, err := servicePort(service, declaration.EndpointPortName)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("http://%s:%d", service.Kubernetes.Name, port)
	arguments := []string{"exec", reconciler.Kubernetes.Kind + "/" + reconciler.Kubernetes.Name, "--namespace", namespace, "--", "/bin/sh", "-c", script, "provider-blob", declaration.Bucket, declaration.Prefix, endpoint}
	result, err := adapter.run(ctx, target, arguments, nil)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return kubectlExitError("reconcile declared blob", result.ExitCode)
	}
	return nil
}

func (adapter KubectlDeclaredProviderAdapter) verifyTelemetry(ctx context.Context, target OperatorTarget, namespace string, resource Resource, resources map[ResourceID]Resource) error {
	service := resources[resource.Telemetry.CollectorService]
	collector := resources[service.Kubernetes.Selector]
	if err := adapter.waitForWorkload(ctx, target, namespace, collector.Kubernetes); err != nil {
		return err
	}
	expectedTTL := fmt.Sprintf("%dh", resource.Telemetry.RetentionDays*24)
	actualTTL := ""
	for _, variable := range collector.Kubernetes.Environment {
		if variable.Name == "BADGER_SPAN_STORE_TTL" {
			actualTTL = variable.Value
			break
		}
	}
	if actualTTL != expectedTTL {
		return errors.New("verify declared telemetry pipeline: collector retention differs from desired state")
	}
	selector := "kubernetes.io/service-name=" + service.Kubernetes.Name
	result, err := adapter.run(ctx, target, []string{"get", "EndpointSlice", "--namespace", namespace, "--selector", selector, "-o", "json"}, nil)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return kubectlExitError("get declared telemetry endpoints", result.ExitCode)
	}
	var slices struct {
		Items []struct {
			Endpoints []struct {
				Addresses  []string `json:"addresses"`
				Conditions struct {
					Ready bool `json:"ready"`
				} `json:"conditions"`
			} `json:"endpoints"`
			Ports []struct {
				Name string `json:"name"`
			} `json:"ports"`
		} `json:"items"`
	}
	if err := json.Unmarshal(result.Output, &slices); err != nil {
		return errors.Wrap(err, "decode declared telemetry EndpointSlices")
	}
	for _, slice := range slices.Items {
		ready := false
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready && len(endpoint.Addresses) > 0 {
				ready = true
				break
			}
		}
		if !ready {
			continue
		}
		for _, port := range slice.Ports {
			if port.Name == resource.Telemetry.PortName {
				return nil
			}
		}
	}
	return errors.New("verify declared telemetry pipeline: collector has no ready declared EndpointSlice")
}

func servicePort(service Resource, name string) (int, error) {
	if service.Kubernetes == nil || service.Kubernetes.Kind != "Service" {
		return 0, errors.New("resolve declared provider endpoint: reference is not a Service")
	}
	for _, port := range service.Kubernetes.Ports {
		if port.Name == name {
			return port.Number, nil
		}
	}
	return 0, errors.Newf("resolve declared provider endpoint: Service has no %s port", name)
}

func (adapter KubectlDeclaredProviderAdapter) waitForWorkload(ctx context.Context, target OperatorTarget, namespace string, workload *KubernetesResource) error {
	if workload == nil || (workload.Kind != "Deployment" && workload.Kind != "StatefulSet") {
		return errors.New("await declared provider reconciler: workload reference is invalid")
	}
	result, err := adapter.run(ctx, target, []string{"rollout", "status", workload.Kind + "/" + workload.Name, "--namespace", namespace, "--timeout=120s"}, nil)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return kubectlExitError("await declared provider reconciler", result.ExitCode)
	}
	return nil
}

func (adapter KubectlDeclaredProviderAdapter) run(ctx context.Context, target OperatorTarget, action []string, input []byte) (KubectlCommandResult, error) {
	if err := validateOperatorRequest(OperatorRequest{Actor: "provider-adapter", Target: target}); err != nil {
		return KubectlCommandResult{}, err
	}
	arguments := append([]string{"--kubeconfig", target.Kubeconfig, "--context", target.Context}, action...)
	result, err := adapter.runner.Run(ctx, "kubectl", arguments, input)
	if err != nil {
		return KubectlCommandResult{}, errors.Wrap(err, "run explicit declared provider command")
	}
	return result, nil
}
