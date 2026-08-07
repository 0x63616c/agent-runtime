package stack

import (
	"context"
	"encoding/json"
	"fmt"
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
mc rm --recursive --force "declared/$1/$2" >/dev/null
mc rb --force "declared/$1" >/dev/null`

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
func (adapter KubectlDeclaredProviderAdapter) ReconcileDeclared(ctx context.Context, target OperatorTarget, rendered Rendered) ([]ResourceID, error) {
	document, resources, err := declaredProviderDocument(rendered)
	if err != nil {
		return nil, err
	}
	ids := make([]ResourceID, 0)
	for _, resource := range document.Resources {
		if resource.Kind == ResourceKubernetes {
			continue
		}
		var reconcileErr error
		switch resource.Kind {
		case ResourceSecretReference:
			reconcileErr = adapter.verifySecretReference(ctx, target, document.Namespace, resource)
		case ResourceDatabase:
			reconcileErr = adapter.verifyDatabase(ctx, target, document.Namespace, resource, resources)
		case ResourceOrchestration:
			_, reconcileErr = adapter.orchestration.ReconcileOrchestration(ctx, target, rendered)
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
func (adapter KubectlDeclaredProviderAdapter) TeardownDeclared(ctx context.Context, target OperatorTarget, rendered Rendered) ([]ResourceID, error) {
	document, resources, err := declaredProviderDocument(rendered)
	if err != nil {
		return nil, err
	}
	ids := make([]ResourceID, 0)
	for index := len(document.Resources) - 1; index >= 0; index-- {
		resource := document.Resources[index]
		if resource.Kind == ResourceKubernetes {
			continue
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
				if err := adapter.orchestration.TeardownOrchestration(ctx, target, rendered, resource.ID); err != nil {
					return nil, errors.Wrapf(err, "teardown declared provider resource %s", resource.ID)
				}
			case ResourceDatabase, ResourceTelemetry:
				// Their declared authority is physically contained by identity-bound
				// Kubernetes storage and is removed by the following Kubernetes plan.
			case ResourceSecretReference:
				return nil, errors.Newf("teardown declared provider resource %s: externally controlled secret references cannot be deleted", resource.ID)
			}
		}
		ids = append(ids, resource.ID)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	return ids, nil
}

func declaredProviderDocument(rendered Rendered) (renderedDocument, map[ResourceID]Resource, error) {
	document, err := parseRenderedBytes(rendered.JSON())
	if err != nil {
		return renderedDocument{}, nil, errors.Wrap(err, "prepare declared provider reconciliation")
	}
	return document, resourcesByID(document.Resources), nil
}

func (adapter KubectlDeclaredProviderAdapter) verifySecretReference(ctx context.Context, target OperatorTarget, namespace string, resource Resource) error {
	result, err := adapter.run(ctx, target, []string{"get", "Secret/" + resource.SecretReference.Reference, "--namespace", namespace, "-o", "json"}, nil)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return kubectlExitError("get declared Secret reference", result.ExitCode)
	}
	var secret struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(result.Output, &secret); err != nil {
		return errors.Wrap(err, "decode declared Secret reference")
	}
	actual := make([]string, 0, len(secret.Data))
	for key := range secret.Data {
		actual = append(actual, key)
	}
	expected := append([]string(nil), resource.SecretReference.Keys...)
	sort.Strings(actual)
	sort.Strings(expected)
	if strings.Join(actual, "\x00") != strings.Join(expected, "\x00") {
		return errors.New("verify declared Secret reference: key inventory differs from desired state")
	}
	return nil
}

func (adapter KubectlDeclaredProviderAdapter) verifyDatabase(ctx context.Context, target OperatorTarget, namespace string, resource Resource, resources map[ResourceID]Resource) error {
	workload := resources[resource.Database.MigrationTarget]
	if err := adapter.waitForWorkload(ctx, target, namespace, workload.Kubernetes); err != nil {
		return err
	}
	query := fmt.Sprintf("SELECT 1 FROM information_schema.schemata WHERE schema_name = '%s'", resource.Database.Schema)
	arguments := []string{"exec", workload.Kubernetes.Kind + "/" + workload.Kubernetes.Name, "--namespace", namespace, "--", "psql", "-At", "-U", "postgres", "-d", resource.Database.Database, "-c", query}
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
	return adapter.runBlobScript(ctx, target, namespace, resource, resources, reconcileBlobScript)
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
	result, err := adapter.run(ctx, target, []string{"get", "Endpoints/" + service.Kubernetes.Name, "--namespace", namespace, "-o", "json"}, nil)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return kubectlExitError("get declared telemetry endpoints", result.ExitCode)
	}
	var endpoints struct {
		Subsets []struct {
			Addresses []json.RawMessage `json:"addresses"`
			Ports     []struct {
				Name string `json:"name"`
			} `json:"ports"`
		} `json:"subsets"`
	}
	if err := json.Unmarshal(result.Output, &endpoints); err != nil {
		return errors.Wrap(err, "decode declared telemetry endpoints")
	}
	for _, subset := range endpoints.Subsets {
		if len(subset.Addresses) == 0 {
			continue
		}
		for _, port := range subset.Ports {
			if port.Name == resource.Telemetry.PortName {
				return nil
			}
		}
	}
	return errors.New("verify declared telemetry pipeline: collector has no ready declared endpoint")
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
