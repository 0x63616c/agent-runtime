package stack

import (
	"context"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/cockroachdb/errors"
)

var operatorActorPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9@._-]{0,127}$`)

// OperatorAction identifies one separately authorized infrastructure operation.
type OperatorAction string

const (
	// OperatorActionApply applies reviewed Kubernetes manifests.
	OperatorActionApply OperatorAction = "apply"
	// OperatorActionObserve reads provider identity without mutation.
	OperatorActionObserve OperatorAction = "observe"
	// OperatorActionDiff compares provider state with reviewed manifests.
	OperatorActionDiff OperatorAction = "diff"
	// OperatorActionReconcile applies only after observing bounded drift.
	OperatorActionReconcile OperatorAction = "reconcile"
	// OperatorActionRollback restores a separately rendered previous Stack state.
	OperatorActionRollback OperatorAction = "rollback"
	// OperatorActionTeardown deletes only after containment verification.
	OperatorActionTeardown OperatorAction = "teardown"
)

// OperatorTarget pins operator authority to an explicit client configuration and Kubernetes context.
type OperatorTarget struct {
	// Kubeconfig is an absolute, caller-supplied configuration path. It is never inferred from the environment.
	Kubeconfig string
	// Context is an explicit context selected from Kubeconfig. It is never inferred from current-context.
	Context string
	// MigrationRoot is the absolute, caller-supplied root containing reviewed migration artifacts.
	MigrationRoot string
}

// OperatorRequest identifies the human or automation actor and exact infrastructure target.
type OperatorRequest struct {
	// Actor is the bounded authenticated operator identity retained in the audit record.
	Actor string
	// Target is the explicit credentials and Kubernetes context boundary.
	Target OperatorTarget
}

// KubernetesObservation contains bounded Kubernetes object identities observed by an adapter.
type KubernetesObservation struct {
	// ObjectIDs are the Stack resource IDs successfully observed in sorted order.
	ObjectIDs []ResourceID
}

// KubernetesDifference contains provider-observed bounded manifest drift.
type KubernetesDifference struct {
	// Changes are sorted Stack resource changes. Empty means the provider matches desired manifests.
	Changes []Change
}

// KubernetesOperatorAdapter performs provider effects only when explicitly called by KubernetesOperator.
type KubernetesOperatorAdapter interface {
	// Apply applies one canonical manifest set and returns its re-observed identities.
	Apply(context.Context, OperatorTarget, KubernetesManifests) (KubernetesObservation, error)
	// Observe reads the concrete provider objects for one canonical manifest set.
	Observe(context.Context, OperatorTarget, KubernetesManifests) (KubernetesObservation, error)
	// Diff reads provider state and returns only bounded resource-level changes.
	Diff(context.Context, OperatorTarget, KubernetesManifests) (KubernetesDifference, error)
	// Teardown re-observes UID and labels before any containment-safe deletion.
	Teardown(context.Context, OperatorTarget, Rendered, KubernetesManifests) error
}

// KubernetesMigrationAdapter executes only digest-verified, declared migration artifacts.
type KubernetesMigrationAdapter interface {
	// Upgrade applies every declared migration artifact for the rendered Stack profile.
	Upgrade(context.Context, OperatorTarget, Rendered) error
	// Rollback reverts only migrations present in current and absent from previous rendered state.
	Rollback(context.Context, OperatorTarget, Rendered, Rendered) error
}

// OrchestrationAdapter reconciles only reviewed durable orchestration declarations.
type OrchestrationAdapter interface {
	ReconcileOrchestration(context.Context, OperatorTarget, Rendered) ([]ResourceID, error)
}

// OperatorAuditRecord is a secret-safe retained record of a requested operator action.
type OperatorAuditRecord struct {
	// Action is the explicit operator operation.
	Action OperatorAction `json:"action"`
	// Actor is the supplied operator identity.
	Actor string `json:"actor"`
	// Context identifies the explicit Kubernetes target, without recording credential material.
	Context string `json:"context"`
	// Stack is the reviewed Stack identity.
	Stack string `json:"stack"`
	// Profile is the reviewed Stack profile.
	Profile Profile `json:"profile"`
	// Digest is the immutable rendered desired-state digest.
	Digest string `json:"digest"`
	// Result is applied, unchanged, observed, differed, rolled_back, torn_down, or failed.
	Result string `json:"result"`
	// Resources is a bounded sorted affected resource identity list.
	Resources []ResourceID `json:"resources,omitempty"`
}

// OperatorAuditSink retains each operator result outside runtime startup.
type OperatorAuditSink interface {
	// Append durably records one secret-safe operator result.
	Append(context.Context, OperatorAuditRecord) error
}

// KubernetesOperator is the only Stack package service that can call a Kubernetes mutation adapter.
// Construction alone grants no infrastructure authority; callers must supply an explicit request.
type KubernetesOperator struct {
	adapter       KubernetesOperatorAdapter
	orchestration OrchestrationAdapter
	audit         OperatorAuditSink
}

// NewKubernetesOperatorWithOrchestration constructs an operator with an explicit orchestration control plane.
func NewKubernetesOperatorWithOrchestration(adapter KubernetesOperatorAdapter, orchestration OrchestrationAdapter, audit OperatorAuditSink) (KubernetesOperator, error) {
	operator, err := NewKubernetesOperator(adapter, audit)
	if err != nil {
		return KubernetesOperator{}, err
	}
	if orchestration == nil {
		return KubernetesOperator{}, errors.New("construct Kubernetes operator: orchestration adapter is required")
	}
	operator.orchestration = orchestration
	return operator, nil
}

// ReconcileResult describes whether observed drift required an explicit apply action.
type ReconcileResult struct {
	// Applied is true only when declared provider drift was reconciled.
	Applied bool
	// Changes is the bounded sorted observed drift considered by reconciliation.
	Changes []Change
}

// NewKubernetesOperator constructs an audited operator boundary with no ambient target or credentials.
func NewKubernetesOperator(adapter KubernetesOperatorAdapter, audit OperatorAuditSink) (KubernetesOperator, error) {
	if adapter == nil {
		return KubernetesOperator{}, errors.New("construct Kubernetes operator: adapter is required")
	}
	if audit == nil {
		return KubernetesOperator{}, errors.New("construct Kubernetes operator: audit sink is required")
	}
	return KubernetesOperator{adapter: adapter, audit: audit}, nil
}

// Apply renders and applies one reviewed Stack profile as an explicit audited operator action.
func (operator KubernetesOperator) Apply(ctx context.Context, request OperatorRequest, rendered Rendered) (KubernetesObservation, error) {
	manifests, document, err := operator.prepare(ctx, request, rendered)
	if err != nil {
		return KubernetesObservation{}, err
	}
	observation, applyErr := operator.adapter.Apply(ctx, request.Target, manifests)
	if applyErr != nil {
		return KubernetesObservation{}, operator.recordFailure(ctx, request, document, OperatorActionApply, applyErr)
	}
	if migrationErr := operator.upgradeMigrations(ctx, request.Target, rendered, document); migrationErr != nil {
		return KubernetesObservation{}, operator.recordFailure(ctx, request, document, OperatorActionApply, migrationErr)
	}
	if operator.orchestration != nil {
		if _, orchestrationErr := operator.orchestration.ReconcileOrchestration(ctx, request.Target, rendered); orchestrationErr != nil {
			return KubernetesObservation{}, operator.recordFailure(ctx, request, document, OperatorActionApply, orchestrationErr)
		}
	}
	if err := operator.record(ctx, request, document, OperatorActionApply, "applied", observation.ObjectIDs); err != nil {
		return KubernetesObservation{}, err
	}
	return observation, nil
}

// Observe reads one reviewed Stack profile through the audited operator boundary without mutation.
func (operator KubernetesOperator) Observe(ctx context.Context, request OperatorRequest, rendered Rendered) (KubernetesObservation, error) {
	manifests, document, err := operator.prepare(ctx, request, rendered)
	if err != nil {
		return KubernetesObservation{}, err
	}
	observation, observeErr := operator.adapter.Observe(ctx, request.Target, manifests)
	if observeErr != nil {
		return KubernetesObservation{}, operator.recordFailure(ctx, request, document, OperatorActionObserve, observeErr)
	}
	if err := operator.record(ctx, request, document, OperatorActionObserve, "observed", observation.ObjectIDs); err != nil {
		return KubernetesObservation{}, err
	}
	return observation, nil
}

// Diff reads provider state and returns bounded drift against one reviewed Stack profile.
func (operator KubernetesOperator) Diff(ctx context.Context, request OperatorRequest, rendered Rendered) (KubernetesDifference, error) {
	manifests, document, err := operator.prepare(ctx, request, rendered)
	if err != nil {
		return KubernetesDifference{}, err
	}
	difference, diffErr := operator.adapter.Diff(ctx, request.Target, manifests)
	if diffErr != nil {
		return KubernetesDifference{}, operator.recordFailure(ctx, request, document, OperatorActionDiff, diffErr)
	}
	canonicalizeChanges(difference.Changes)
	result := "unchanged"
	if len(difference.Changes) > 0 {
		result = "differed"
	}
	if err := operator.record(ctx, request, document, OperatorActionDiff, result, changeResources(difference.Changes)); err != nil {
		return KubernetesDifference{}, err
	}
	return difference, nil
}

// Reconcile observes declared provider drift, then applies only the selected reviewed manifest set.
func (operator KubernetesOperator) Reconcile(ctx context.Context, request OperatorRequest, rendered Rendered) (ReconcileResult, error) {
	manifests, document, err := operator.prepare(ctx, request, rendered)
	if err != nil {
		return ReconcileResult{}, err
	}
	difference, diffErr := operator.adapter.Diff(ctx, request.Target, manifests)
	if diffErr != nil {
		return ReconcileResult{}, operator.recordFailure(ctx, request, document, OperatorActionReconcile, diffErr)
	}
	canonicalizeChanges(difference.Changes)
	result := ReconcileResult{Changes: append([]Change(nil), difference.Changes...)}
	auditResult := "unchanged"
	if len(difference.Changes) > 0 {
		if _, applyErr := operator.adapter.Apply(ctx, request.Target, manifests); applyErr != nil {
			return ReconcileResult{}, operator.recordFailure(ctx, request, document, OperatorActionReconcile, applyErr)
		}
		result.Applied = true
		auditResult = "applied"
	}
	if err := operator.record(ctx, request, document, OperatorActionReconcile, auditResult, changeResources(difference.Changes)); err != nil {
		return ReconcileResult{}, err
	}
	return result, nil
}

// Rollback applies a separately rendered previous Stack state through the same explicit operator boundary.
func (operator KubernetesOperator) Rollback(ctx context.Context, request OperatorRequest, current, previous Rendered) (KubernetesObservation, error) {
	manifests, document, err := operator.prepare(ctx, request, previous)
	if err != nil {
		return KubernetesObservation{}, err
	}
	if migrationErr := operator.rollbackMigrations(ctx, request.Target, current, previous, document); migrationErr != nil {
		return KubernetesObservation{}, operator.recordFailure(ctx, request, document, OperatorActionRollback, migrationErr)
	}
	observation, rollbackErr := operator.adapter.Apply(ctx, request.Target, manifests)
	if rollbackErr != nil {
		return KubernetesObservation{}, operator.recordFailure(ctx, request, document, OperatorActionRollback, rollbackErr)
	}
	if err := operator.record(ctx, request, document, OperatorActionRollback, "rolled_back", observation.ObjectIDs); err != nil {
		return KubernetesObservation{}, err
	}
	return observation, nil
}

// Teardown delegates only containment-safe, re-observed deletion to the explicit operator adapter.
func (operator KubernetesOperator) Teardown(ctx context.Context, request OperatorRequest, rendered Rendered) error {
	manifests, document, err := operator.prepare(ctx, request, rendered)
	if err != nil {
		return err
	}
	if teardownErr := operator.adapter.Teardown(ctx, request.Target, rendered, manifests); teardownErr != nil {
		return operator.recordFailure(ctx, request, document, OperatorActionTeardown, teardownErr)
	}
	return operator.record(ctx, request, document, OperatorActionTeardown, "torn_down", manifestResources(manifests))
}

func (operator KubernetesOperator) prepare(ctx context.Context, request OperatorRequest, rendered Rendered) (KubernetesManifests, renderedDocument, error) {
	if err := ctx.Err(); err != nil {
		return KubernetesManifests{}, renderedDocument{}, errors.Wrap(err, "run Kubernetes operator action")
	}
	if err := validateOperatorRequest(request); err != nil {
		return KubernetesManifests{}, renderedDocument{}, err
	}
	document, err := parseRenderedBytes(rendered.JSON())
	if err != nil {
		return KubernetesManifests{}, renderedDocument{}, errors.Wrap(err, "prepare Kubernetes operator action")
	}
	if containsDatabaseResource(document.Resources) && (request.Target.MigrationRoot == "" || !filepath.IsAbs(request.Target.MigrationRoot)) {
		return KubernetesManifests{}, renderedDocument{}, errors.New("validate Kubernetes operator request: explicit absolute migration root is required for declared database migrations")
	}
	manifests, err := RenderKubernetes(rendered)
	if err != nil {
		return KubernetesManifests{}, renderedDocument{}, err
	}
	return manifests, document, nil
}

func (operator KubernetesOperator) upgradeMigrations(ctx context.Context, target OperatorTarget, rendered Rendered, document renderedDocument) error {
	if !containsDatabaseResource(document.Resources) {
		return nil
	}
	migrator, ok := operator.adapter.(KubernetesMigrationAdapter)
	if !ok {
		return errors.New("run Kubernetes operator migration: adapter does not implement declared migration execution")
	}
	if err := migrator.Upgrade(ctx, target, rendered); err != nil {
		return errors.Wrap(err, "run Kubernetes operator migration upgrade")
	}
	return nil
}

func (operator KubernetesOperator) rollbackMigrations(ctx context.Context, target OperatorTarget, current, previous Rendered, previousDocument renderedDocument) error {
	currentDocument, err := parseRenderedBytes(current.JSON())
	if err != nil {
		return errors.Wrap(err, "prepare Kubernetes operator rollback migration")
	}
	if !containsDatabaseResource(currentDocument.Resources) && !containsDatabaseResource(previousDocument.Resources) {
		return nil
	}
	migrator, ok := operator.adapter.(KubernetesMigrationAdapter)
	if !ok {
		return errors.New("run Kubernetes operator migration rollback: adapter does not implement declared migration execution")
	}
	if err := migrator.Rollback(ctx, target, current, previous); err != nil {
		return errors.Wrap(err, "run Kubernetes operator migration rollback")
	}
	return nil
}

func containsDatabaseResource(resources []Resource) bool {
	for _, resource := range resources {
		if resource.Kind == ResourceDatabase {
			return true
		}
	}
	return false
}

func validateOperatorRequest(request OperatorRequest) error {
	if !operatorActorPattern.MatchString(request.Actor) {
		return errors.New("validate Kubernetes operator request: bounded actor is required")
	}
	if request.Target.Kubeconfig == "" || !filepath.IsAbs(request.Target.Kubeconfig) || request.Target.Context == "" || len(request.Target.Context) > 253 {
		return errors.New("validate Kubernetes operator request: explicit absolute kubeconfig and context are required")
	}
	return nil
}

func (operator KubernetesOperator) recordFailure(ctx context.Context, request OperatorRequest, document renderedDocument, action OperatorAction, cause error) error {
	if err := operator.record(ctx, request, document, action, "failed", nil); err != nil {
		return errors.Wrapf(err, "%s; retain operator failure", cause.Error())
	}
	return errors.Wrapf(cause, "run Kubernetes operator %s", action)
}

func (operator KubernetesOperator) record(ctx context.Context, request OperatorRequest, document renderedDocument, action OperatorAction, result string, resources []ResourceID) error {
	record := OperatorAuditRecord{Action: action, Actor: request.Actor, Context: request.Target.Context, Stack: document.Stack, Profile: document.Profile, Digest: document.Digest, Result: result, Resources: append([]ResourceID(nil), resources...)}
	sort.Slice(record.Resources, func(left, right int) bool { return record.Resources[left] < record.Resources[right] })
	if err := operator.audit.Append(ctx, record); err != nil {
		return errors.Wrap(err, "retain Kubernetes operator audit record")
	}
	return nil
}

func canonicalizeChanges(changes []Change) {
	sort.Slice(changes, func(left, right int) bool { return changes[left].Resource < changes[right].Resource })
}

func changeResources(changes []Change) []ResourceID {
	resources := make([]ResourceID, 0, len(changes))
	for _, change := range changes {
		resources = append(resources, change.Resource)
	}
	return resources
}

func manifestResources(manifests KubernetesManifests) []ResourceID {
	objects := manifests.Objects()
	resources := make([]ResourceID, 0, len(objects))
	for _, object := range objects {
		resources = append(resources, object.Resource)
	}
	return resources
}
