package stack

import (
	"context"
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
)

// TemporalCLIAdapter reconciles namespaces through the declared Temporal deployment only.
type TemporalCLIAdapter struct{ runner KubectlCommandRunner }

// NewTemporalCLIAdapter constructs a bounded operator-only Temporal CLI adapter.
func NewTemporalCLIAdapter(runner KubectlCommandRunner) (TemporalCLIAdapter, error) {
	if runner == nil {
		return TemporalCLIAdapter{}, errors.New("construct Temporal CLI adapter: command runner is required")
	}
	return TemporalCLIAdapter{runner: runner}, nil
}

// ReconcileOrchestration describes then creates each declared namespace idempotently.
func (adapter TemporalCLIAdapter) ReconcileOrchestration(ctx context.Context, target OperatorTarget, rendered Rendered) ([]ResourceID, error) {
	doc, err := parseRenderedBytes(rendered.JSON())
	if err != nil {
		return nil, errors.Wrap(err, "reconcile orchestration declarations")
	}
	ids := []ResourceID{}
	for _, r := range doc.Resources {
		if r.Kind != ResourceOrchestration {
			continue
		}
		args := []string{"--kubeconfig", target.Kubeconfig, "--context", target.Context, "exec", "Deployment/temporal", "--namespace", doc.Namespace, "--", "temporal", "--address", "127.0.0.1:7233", "--command-timeout", "30s", "operator", "namespace", "describe", "--namespace", r.Orchestration.Namespace}
		result, runErr := adapter.runner.Run(ctx, "kubectl", args, nil)
		if runErr != nil {
			return nil, errors.Wrap(runErr, "describe declared Temporal namespace")
		}
		if result.ExitCode != 0 {
			if r.Orchestration.RetentionDays <= 0 || int64(r.Orchestration.RetentionDays) > int64(time.Duration(1<<63-1)/(24*time.Hour)) {
				return nil, errors.New("reconcile declared Temporal namespace: retention days are invalid")
			}
			retention := time.Duration(r.Orchestration.RetentionDays) * 24 * time.Hour
			create := []string{"--kubeconfig", target.Kubeconfig, "--context", target.Context, "exec", "Deployment/temporal", "--namespace", doc.Namespace, "--", "temporal", "--address", "127.0.0.1:7233", "--command-timeout", "30s", "operator", "namespace", "create", "--namespace", r.Orchestration.Namespace, "--retention", fmt.Sprintf("%dh", int64(retention/time.Hour))}
			created, createErr := adapter.runner.Run(ctx, "kubectl", create, nil)
			if createErr != nil || created.ExitCode != 0 {
				return nil, errors.New("create declared Temporal namespace")
			}
		}
		ids = append(ids, r.ID)
	}
	return ids, nil
}
