package stack

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
)

// TemporalCLIAdapter reconciles namespaces through the declared Temporal deployment only.
type TemporalCLIAdapter struct{ runner KubectlCommandRunner }

const temporalDescribeAttempts = 3

// NewTemporalCLIAdapter constructs a bounded operator-only Temporal CLI adapter.
func NewTemporalCLIAdapter(runner KubectlCommandRunner) (TemporalCLIAdapter, error) {
	if runner == nil {
		return TemporalCLIAdapter{}, errors.New("construct Temporal CLI adapter: command runner is required")
	}
	return TemporalCLIAdapter{runner: runner}, nil
}

// ReconcileOrchestration describes then creates each declared namespace idempotently.
func (adapter TemporalCLIAdapter) ReconcileOrchestration(ctx context.Context, target OperatorTarget, rendered Rendered, authority BootstrapAuthority) ([]ResourceID, error) {
	if err := adapter.verifyBootstrapAuthority(ctx, target, rendered, authority); err != nil {
		return nil, err
	}
	doc, err := parseRenderedBytes(rendered.JSON())
	if err != nil {
		return nil, errors.Wrap(err, "reconcile orchestration declarations")
	}
	ids := []ResourceID{}
	for _, r := range doc.Resources {
		if r.Kind != ResourceOrchestration {
			continue
		}
		if len(r.Orchestration.SearchAttributes) != 0 || len(r.Orchestration.Schedules) != 0 {
			return nil, errors.New("reconcile orchestration declarations: search attributes and schedules are not implemented by the Temporal CLI adapter")
		}
		retention, retentionErr := temporalRetention(r.Orchestration.RetentionDays)
		if retentionErr != nil {
			return nil, retentionErr
		}
		if readyErr := adapter.awaitTemporalReady(ctx, target, doc.Namespace); readyErr != nil {
			return nil, readyErr
		}
		description, missing, describeErr := adapter.describeNamespace(ctx, target, doc.Namespace, r.Orchestration.Namespace)
		if describeErr != nil {
			return nil, describeErr
		}
		if missing {
			create := []string{"--kubeconfig", target.Kubeconfig, "--context", target.Context, "exec", "Deployment/temporal", "--namespace", doc.Namespace, "--", "temporal", "--address", "127.0.0.1:7233", "--command-timeout", "30s", "operator", "namespace", "create", "--namespace", r.Orchestration.Namespace, "--retention", fmt.Sprintf("%dh", int64(retention/time.Hour))}
			created, createErr := adapter.runner.Run(ctx, "kubectl", create, nil)
			if createErr != nil {
				return nil, errors.Wrap(createErr, "create declared Temporal namespace")
			}
			if created.ExitCode != 0 {
				if temporalNamespaceAlreadyExists(created.Output) {
					if updateErr := adapter.updateRetention(ctx, target, doc.Namespace, r.Orchestration.Namespace, retention); updateErr != nil {
						return nil, updateErr
					}
					ids = append(ids, r.ID)
					continue
				}
				return nil, errors.Newf("create declared Temporal namespace: exit status %d: %s", created.ExitCode, safeTemporalOutput(created.Output))
			}
		} else if description.Retention != retention {
			if updateErr := adapter.updateRetention(ctx, target, doc.Namespace, r.Orchestration.Namespace, retention); updateErr != nil {
				return nil, updateErr
			}
		}
		ids = append(ids, r.ID)
	}
	return ids, nil
}

// TeardownOrchestration deletes one explicitly owned namespace only when its
// rendered resource identity and lifecycle authorize deletion.
func (adapter TemporalCLIAdapter) TeardownOrchestration(ctx context.Context, target OperatorTarget, rendered Rendered, resourceID ResourceID, authority BootstrapAuthority) error {
	if err := adapter.verifyBootstrapAuthority(ctx, target, rendered, authority); err != nil {
		return err
	}
	document, err := parseRenderedBytes(rendered.JSON())
	if err != nil {
		return errors.Wrap(err, "teardown orchestration declaration")
	}
	for _, resource := range document.Resources {
		if resource.ID != resourceID {
			continue
		}
		if resource.Kind != ResourceOrchestration || resource.DeleteBehavior != DeleteOwned {
			return errors.New("teardown orchestration declaration: resource is not an owned orchestration namespace")
		}
		description, missing, describeErr := adapter.describeNamespace(ctx, target, document.Namespace, resource.Orchestration.Namespace)
		_ = description
		if describeErr != nil {
			return describeErr
		}
		if missing {
			return nil
		}
		arguments := []string{"--kubeconfig", target.Kubeconfig, "--context", target.Context, "exec", "Deployment/temporal", "--namespace", document.Namespace, "--", "temporal", "--address", "127.0.0.1:7233", "--command-timeout", "30s", "operator", "namespace", "delete", "--namespace", resource.Orchestration.Namespace, "--yes"}
		result, runErr := adapter.runner.Run(ctx, "kubectl", arguments, nil)
		if runErr != nil {
			return errors.Wrap(runErr, "delete declared Temporal namespace")
		}
		if result.ExitCode != 0 {
			return errors.Newf("delete declared Temporal namespace: exit status %d: %s", result.ExitCode, safeTemporalOutput(result.Output))
		}
		return nil
	}
	return errors.New("teardown orchestration declaration: resource is not declared")
}

func (adapter TemporalCLIAdapter) verifyBootstrapAuthority(ctx context.Context, target OperatorTarget, rendered Rendered, authority BootstrapAuthority) error {
	manifests, err := RenderKubernetes(rendered)
	if err != nil {
		return err
	}
	return (KubectlAdapter{runner: adapter.runner}).verifyBootstrapAuthority(ctx, target, manifests, authority)
}

type temporalNamespaceDescription struct {
	Retention time.Duration
}

func temporalRetention(days int) (time.Duration, error) {
	if days <= 0 || int64(days) > int64(time.Duration(1<<63-1)/(24*time.Hour)) {
		return 0, errors.New("reconcile declared Temporal namespace: retention days are invalid")
	}
	return time.Duration(days) * 24 * time.Hour, nil
}

func (adapter TemporalCLIAdapter) awaitTemporalReady(ctx context.Context, target OperatorTarget, namespace string) error {
	args := []string{"--kubeconfig", target.Kubeconfig, "--context", target.Context, "rollout", "status", "Deployment/temporal", "--namespace", namespace, "--timeout=120s"}
	result, err := adapter.runner.Run(ctx, "kubectl", args, nil)
	if err != nil {
		return errors.Wrap(err, "await declared Temporal deployment readiness")
	}
	if result.ExitCode != 0 {
		return errors.Newf("await declared Temporal deployment readiness: exit status %d: %s", result.ExitCode, safeTemporalOutput(result.Output))
	}
	return nil
}

func (adapter TemporalCLIAdapter) describeNamespace(ctx context.Context, target OperatorTarget, deploymentNamespace, temporalNamespace string) (temporalNamespaceDescription, bool, error) {
	args := []string{"--kubeconfig", target.Kubeconfig, "--context", target.Context, "exec", "Deployment/temporal", "--namespace", deploymentNamespace, "--", "temporal", "--address", "127.0.0.1:7233", "--command-timeout", "30s", "--output", "json", "operator", "namespace", "describe", "--namespace", temporalNamespace}
	var lastResult KubectlCommandResult
	var lastErr error
	for attempt := 0; attempt < temporalDescribeAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return temporalNamespaceDescription{}, false, errors.Wrap(err, "describe declared Temporal namespace")
		}
		lastResult, lastErr = adapter.runner.Run(ctx, "kubectl", args, nil)
		if lastErr == nil && lastResult.ExitCode == 0 {
			description, err := parseTemporalNamespaceDescription(lastResult.Output)
			if err != nil {
				return temporalNamespaceDescription{}, false, err
			}
			return description, false, nil
		}
		if lastErr == nil && temporalNamespaceNotFound(lastResult.Output) {
			return temporalNamespaceDescription{}, true, nil
		}
	}
	if lastErr != nil {
		return temporalNamespaceDescription{}, false, errors.Wrap(lastErr, "describe declared Temporal namespace")
	}
	return temporalNamespaceDescription{}, false, errors.Newf("describe declared Temporal namespace: exit status %d after %d attempts: %s", lastResult.ExitCode, temporalDescribeAttempts, safeTemporalOutput(lastResult.Output))
}

func parseTemporalNamespaceDescription(output []byte) (temporalNamespaceDescription, error) {
	var document struct {
		Config struct {
			Retention string `json:"workflowExecutionRetentionTtl"`
		} `json:"config"`
	}
	if err := json.Unmarshal(output, &document); err != nil {
		return temporalNamespaceDescription{}, errors.Wrap(err, "decode declared Temporal namespace description")
	}
	retention, err := time.ParseDuration(document.Config.Retention)
	if err != nil || retention <= 0 {
		return temporalNamespaceDescription{}, errors.New("decode declared Temporal namespace description: positive retention is required")
	}
	return temporalNamespaceDescription{Retention: retention}, nil
}

func (adapter TemporalCLIAdapter) updateRetention(ctx context.Context, target OperatorTarget, deploymentNamespace, temporalNamespace string, retention time.Duration) error {
	args := []string{"--kubeconfig", target.Kubeconfig, "--context", target.Context, "exec", "Deployment/temporal", "--namespace", deploymentNamespace, "--", "temporal", "--address", "127.0.0.1:7233", "--command-timeout", "30s", "operator", "namespace", "update", "--namespace", temporalNamespace, "--retention", fmt.Sprintf("%dh", int64(retention/time.Hour))}
	result, err := adapter.runner.Run(ctx, "kubectl", args, nil)
	if err != nil {
		return errors.Wrap(err, "update declared Temporal namespace retention")
	}
	if result.ExitCode != 0 {
		return errors.Newf("update declared Temporal namespace retention: exit status %d: %s", result.ExitCode, safeTemporalOutput(result.Output))
	}
	return nil
}

func temporalNamespaceNotFound(output []byte) bool {
	value := strings.ToLower(string(output))
	return strings.Contains(value, "namespace ") && strings.Contains(value, " is not found")
}

func temporalNamespaceAlreadyExists(output []byte) bool {
	value := strings.ToLower(string(output))
	return strings.Contains(value, "namespace ") && strings.Contains(value, " already exists")
}

func safeTemporalOutput(output []byte) string {
	value := strings.TrimSpace(string(output))
	lower := strings.ToLower(value)
	for _, unsafe := range []string{"token", "password", "authorization", "credential", "secret"} {
		if strings.Contains(lower, unsafe) {
			return "output redacted"
		}
	}
	if len(value) > 512 {
		value = value[:512]
	}
	if value == "" {
		return "no safe output"
	}
	return value
}
