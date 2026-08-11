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
	// OperatorActionBootstrap atomically creates and records only an absent rendered Namespace.
	OperatorActionBootstrap OperatorAction = "bootstrap"
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
	// BootstrapAuthority is the explicit, identity-bound authority established by bootstrap.
	// Every mutating lifecycle action must present it; it is re-observed at the provider.
	BootstrapAuthority BootstrapAuthority
}

// BootstrapAuthority binds a mutating operator action to one Namespace that
// bootstrap created for exactly one reviewed Stack rendering.
type BootstrapAuthority struct {
	// Stack is the reviewed Stack identity.
	Stack string `json:"stack"`
	// Profile is the reviewed Stack profile.
	Profile Profile `json:"profile"`
	// Namespace is the exact rendered Namespace.
	Namespace string `json:"namespace"`
	// NamespaceUID is the immutable provider identity returned by bootstrap.
	NamespaceUID ObservedUID `json:"namespace_uid"`
	// RenderDigest records the reviewed rendering that created the Namespace.
	// Later reviewed revisions retain this namespace-bound authority.
	RenderDigest string `json:"render_digest"`
	// Nonce is private capability material; only its digest is stored on the Namespace.
	Nonce string `json:"nonce"`
	// DeletedSecrets records only exact Secret UIDs already removed by this capability.
	DeletedSecrets map[ResourceID]ObservedUID `json:"deleted_secrets,omitempty"`
	capabilityFile string
}

// KubernetesObservation contains bounded Kubernetes object identities observed by an adapter.
type KubernetesObservation struct {
	// ObjectIDs are the Stack resource IDs successfully observed in sorted order.
	ObjectIDs []ResourceID
}

// KubernetesNamespaceObservation binds a newly bootstrapped Namespace to reviewed desired state.
type KubernetesNamespaceObservation struct {
	// Namespace is the exact rendered Namespace name.
	Namespace string `json:"namespace"`
	// UID is the provider-assigned immutable object identity.
	UID ObservedUID `json:"uid"`
	// Labels are the complete containment identity re-observed after creation.
	Labels OwnershipLabels `json:"labels"`
	// RenderDigest binds the observation to the canonical Stack profile.
	RenderDigest string `json:"render_digest"`
}

// KubernetesDifference contains provider-observed bounded manifest drift.
type KubernetesDifference struct {
	// Changes are sorted Stack resource changes. Empty means the provider matches desired manifests.
	Changes []Change
}

// KubernetesOperatorAdapter performs provider effects only when explicitly called by KubernetesOperator.
type KubernetesOperatorAdapter interface {
	// BootstrapNamespace atomically creates only an absent rendered Namespace and re-observes its identity.
	BootstrapNamespace(context.Context, OperatorTarget, KubernetesManifests, string) (KubernetesNamespaceObservation, error)
	// Apply applies one canonical manifest set and returns its re-observed identities.
	Apply(context.Context, OperatorTarget, KubernetesManifests, BootstrapAuthority) (KubernetesObservation, error)
	// Observe reads the concrete provider objects for one canonical manifest set.
	Observe(context.Context, OperatorTarget, KubernetesManifests) (KubernetesObservation, error)
	// Diff reads provider state and returns only bounded resource-level changes.
	Diff(context.Context, OperatorTarget, KubernetesManifests) (KubernetesDifference, error)
	// Teardown re-observes UID and labels before any containment-safe deletion.
	Teardown(context.Context, OperatorTarget, Rendered, KubernetesManifests, BootstrapAuthority) error
}

// KubernetesMigrationAdapter executes only digest-verified, declared migration artifacts.
type KubernetesMigrationAdapter interface {
	// Upgrade applies every declared migration artifact for the rendered Stack profile.
	Upgrade(context.Context, OperatorTarget, Rendered, BootstrapAuthority) error
	// Rollback reverts only migrations present in current and absent from previous rendered state.
	Rollback(context.Context, OperatorTarget, Rendered, Rendered, BootstrapAuthority) error
}

// OrchestrationAdapter reconciles only reviewed durable orchestration declarations.
type OrchestrationAdapter interface {
	ReconcileOrchestration(context.Context, OperatorTarget, Rendered, BootstrapAuthority) ([]ResourceID, error)
}

// DeclaredProviderAdapter reconciles every non-Kubernetes resource in one rendered Stack.
// Returning the complete affected identity set makes omission and accidental provider authority observable.
type DeclaredProviderAdapter interface {
	// ReconcileDeclared reconciles all declared non-Kubernetes resources and returns their exact IDs.
	ReconcileDeclared(context.Context, OperatorTarget, Rendered, BootstrapAuthority) ([]ResourceID, error)
	// TeardownDeclared applies each declared non-Kubernetes delete behavior before Kubernetes dependencies disappear.
	TeardownDeclared(context.Context, OperatorTarget, Rendered, BootstrapAuthority) ([]ResourceID, error)
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
	// TransitionFromDigest records the reviewed source revision of an explicit rollback.
	// It is empty for non-transition actions.
	TransitionFromDigest string `json:"transition_from_digest,omitempty"`
	// Result is applied, unchanged, observed, differed, rolled_back, torn_down, or failed.
	Result string `json:"result"`
	// Resources is a bounded sorted affected resource identity list.
	Resources []ResourceID `json:"resources,omitempty"`
	// NamespaceUID is retained only for bootstrap, proving which new Namespace was created.
	NamespaceUID ObservedUID `json:"namespace_uid,omitempty"`
	// NamespaceLabels are retained only for bootstrap and bind its containment identity.
	NamespaceLabels *OwnershipLabels `json:"namespace_labels,omitempty"`
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
	providers     DeclaredProviderAdapter
	audit         OperatorAuditSink
}

// NewKubernetesOperatorWithProviders constructs an operator that owns the complete
// Kubernetes and non-Kubernetes desired-state reconciliation boundary.
func NewKubernetesOperatorWithProviders(adapter KubernetesOperatorAdapter, providers DeclaredProviderAdapter, audit OperatorAuditSink) (KubernetesOperator, error) {
	operator, err := NewKubernetesOperator(adapter, audit)
	if err != nil {
		return KubernetesOperator{}, err
	}
	if providers == nil {
		return KubernetesOperator{}, errors.New("construct Kubernetes operator: declared provider adapter is required")
	}
	operator.providers = providers
	return operator, nil
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

// Bootstrap atomically creates only the rendered Namespace after proving it is absent.
// External controllers may then populate exact declared Secret references before Apply.
func (operator KubernetesOperator) Bootstrap(ctx context.Context, request OperatorRequest, rendered Rendered) (KubernetesNamespaceObservation, error) {
	manifests, document, err := operator.prepare(ctx, request, rendered)
	if err != nil {
		return KubernetesNamespaceObservation{}, err
	}
	if err := validateBootstrapIntent(request.BootstrapAuthority, document); err != nil {
		return KubernetesNamespaceObservation{}, operator.recordFailure(ctx, request, document, OperatorActionBootstrap, err)
	}
	observation, bootstrapErr := operator.adapter.BootstrapNamespace(ctx, request.Target, manifests, request.BootstrapAuthority.NonceDigest())
	if bootstrapErr != nil {
		return KubernetesNamespaceObservation{}, operator.recordFailure(ctx, request, document, OperatorActionBootstrap, bootstrapErr)
	}
	expectedLabels := OwnershipLabels{PartOf: document.Labels.PartOf, Stack: document.Labels.Stack, Profile: document.Labels.Profile}
	if observation.Namespace != document.Namespace || observation.UID == "" || observation.Labels != expectedLabels || observation.RenderDigest != document.Digest {
		return KubernetesNamespaceObservation{}, operator.recordFailure(ctx, request, document, OperatorActionBootstrap, errors.New("namespace observation does not match rendered desired state"))
	}
	record := OperatorAuditRecord{
		Action: OperatorActionBootstrap, Actor: request.Actor, Context: request.Target.Context,
		Stack: document.Stack, Profile: document.Profile, Digest: document.Digest, Result: "bootstrapped",
		Resources: []ResourceID{"namespace"}, NamespaceUID: observation.UID, NamespaceLabels: &observation.Labels,
	}
	if err := operator.audit.Append(ctx, record); err != nil {
		return KubernetesNamespaceObservation{}, errors.Wrap(err, "retain Kubernetes operator bootstrap audit record")
	}
	return observation, nil
}

// Apply renders and applies one reviewed Stack profile as an explicit audited operator action.
func (operator KubernetesOperator) Apply(ctx context.Context, request OperatorRequest, rendered Rendered) (KubernetesObservation, error) {
	manifests, document, err := operator.prepare(ctx, request, rendered)
	if err != nil {
		return KubernetesObservation{}, err
	}
	if err := validateBootstrapAuthority(request.BootstrapAuthority, document); err != nil {
		return KubernetesObservation{}, operator.recordFailure(ctx, request, document, OperatorActionApply, err)
	}
	observation, applyErr := operator.adapter.Apply(ctx, request.Target, manifests, request.BootstrapAuthority)
	if applyErr != nil {
		return KubernetesObservation{}, operator.recordFailure(ctx, request, document, OperatorActionApply, applyErr)
	}
	if migrationErr := operator.upgradeMigrations(ctx, request.Target, rendered, document, request.BootstrapAuthority); migrationErr != nil {
		return KubernetesObservation{}, operator.recordFailure(ctx, request, document, OperatorActionApply, migrationErr)
	}
	if operator.orchestration != nil {
		if _, orchestrationErr := operator.orchestration.ReconcileOrchestration(ctx, request.Target, rendered, request.BootstrapAuthority); orchestrationErr != nil {
			return KubernetesObservation{}, operator.recordFailure(ctx, request, document, OperatorActionApply, orchestrationErr)
		}
	}
	affected := append([]ResourceID(nil), observation.ObjectIDs...)
	if operator.providers != nil {
		providerIDs, providerErr := operator.providers.ReconcileDeclared(ctx, request.Target, rendered, request.BootstrapAuthority)
		if providerErr != nil {
			return KubernetesObservation{}, operator.recordFailure(ctx, request, document, OperatorActionApply, providerErr)
		}
		if providerErr := validateDeclaredProviderIDs(document.Resources, providerIDs); providerErr != nil {
			return KubernetesObservation{}, operator.recordFailure(ctx, request, document, OperatorActionApply, providerErr)
		}
		affected = append(affected, providerIDs...)
	}
	if err := operator.record(ctx, request, document, OperatorActionApply, "applied", affected); err != nil {
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

// ReconcileProviders verifies every declared non-Kubernetes provider without
// diffing Kubernetes fields that a separate declared controller owns. It is an
// explicit operator action for topologies such as local Tilt where the
// controller replaces only development image references after rendering.
func (operator KubernetesOperator) ReconcileProviders(ctx context.Context, request OperatorRequest, rendered Rendered) (ReconcileResult, error) {
	_, document, err := operator.prepare(ctx, request, rendered)
	if err != nil {
		return ReconcileResult{}, err
	}
	if err := validateBootstrapAuthority(request.BootstrapAuthority, document); err != nil {
		return ReconcileResult{}, operator.recordFailure(ctx, request, document, OperatorActionReconcile, err)
	}
	if operator.providers == nil {
		return ReconcileResult{}, operator.recordFailure(ctx, request, document, OperatorActionReconcile, errors.New("reconcile declared providers: provider adapter is required"))
	}
	if migrationErr := operator.upgradeMigrations(ctx, request.Target, rendered, document, request.BootstrapAuthority); migrationErr != nil {
		return ReconcileResult{}, operator.recordFailure(ctx, request, document, OperatorActionReconcile, migrationErr)
	}
	providerIDs, providerErr := operator.providers.ReconcileDeclared(ctx, request.Target, rendered, request.BootstrapAuthority)
	if providerErr != nil {
		return ReconcileResult{}, operator.recordFailure(ctx, request, document, OperatorActionReconcile, providerErr)
	}
	if providerErr := validateDeclaredProviderIDs(document.Resources, providerIDs); providerErr != nil {
		return ReconcileResult{}, operator.recordFailure(ctx, request, document, OperatorActionReconcile, providerErr)
	}
	if err := operator.record(ctx, request, document, OperatorActionReconcile, "reconciled", providerIDs); err != nil {
		return ReconcileResult{}, err
	}
	return ReconcileResult{}, nil
}

// Reconcile observes declared provider drift, then applies only the selected reviewed manifest set.
func (operator KubernetesOperator) Reconcile(ctx context.Context, request OperatorRequest, rendered Rendered) (ReconcileResult, error) {
	manifests, document, err := operator.prepare(ctx, request, rendered)
	if err != nil {
		return ReconcileResult{}, err
	}
	if err := validateBootstrapAuthority(request.BootstrapAuthority, document); err != nil {
		return ReconcileResult{}, operator.recordFailure(ctx, request, document, OperatorActionReconcile, err)
	}
	difference, diffErr := operator.adapter.Diff(ctx, request.Target, manifests)
	if diffErr != nil {
		return ReconcileResult{}, operator.recordFailure(ctx, request, document, OperatorActionReconcile, diffErr)
	}
	canonicalizeChanges(difference.Changes)
	result := ReconcileResult{Changes: append([]Change(nil), difference.Changes...)}
	auditResult := "unchanged"
	affected := changeResources(difference.Changes)
	if len(difference.Changes) > 0 {
		if _, applyErr := operator.adapter.Apply(ctx, request.Target, manifests, request.BootstrapAuthority); applyErr != nil {
			return ReconcileResult{}, operator.recordFailure(ctx, request, document, OperatorActionReconcile, applyErr)
		}
		if migrationErr := operator.upgradeMigrations(ctx, request.Target, rendered, document, request.BootstrapAuthority); migrationErr != nil {
			return ReconcileResult{}, operator.recordFailure(ctx, request, document, OperatorActionReconcile, migrationErr)
		}
		if operator.orchestration != nil {
			if _, orchestrationErr := operator.orchestration.ReconcileOrchestration(ctx, request.Target, rendered, request.BootstrapAuthority); orchestrationErr != nil {
				return ReconcileResult{}, operator.recordFailure(ctx, request, document, OperatorActionReconcile, orchestrationErr)
			}
		}
		result.Applied = true
		auditResult = "applied"
	}
	if operator.providers != nil {
		providerIDs, providerErr := operator.providers.ReconcileDeclared(ctx, request.Target, rendered, request.BootstrapAuthority)
		if providerErr != nil {
			return ReconcileResult{}, operator.recordFailure(ctx, request, document, OperatorActionReconcile, providerErr)
		}
		if providerErr := validateDeclaredProviderIDs(document.Resources, providerIDs); providerErr != nil {
			return ReconcileResult{}, operator.recordFailure(ctx, request, document, OperatorActionReconcile, providerErr)
		}
		affected = append(affected, providerIDs...)
		if auditResult == "unchanged" {
			auditResult = "reconciled"
		}
	}
	if err := operator.record(ctx, request, document, OperatorActionReconcile, auditResult, affected); err != nil {
		return ReconcileResult{}, err
	}
	return result, nil
}

// Rollback applies a separately rendered previous Stack state through the same explicit operator boundary.
func (operator KubernetesOperator) Rollback(ctx context.Context, request OperatorRequest, current, previous Rendered) (KubernetesObservation, error) {
	_, currentDocument, err := operator.prepare(ctx, request, current)
	if err != nil {
		return KubernetesObservation{}, err
	}
	if err := validateBootstrapAuthority(request.BootstrapAuthority, currentDocument); err != nil {
		return KubernetesObservation{}, operator.recordFailure(ctx, request, currentDocument, OperatorActionRollback, err)
	}
	manifests, document, err := operator.prepare(ctx, request, previous)
	if err != nil {
		return KubernetesObservation{}, err
	}
	if currentDocument.Stack != document.Stack || currentDocument.Profile != document.Profile || currentDocument.Namespace != document.Namespace {
		return KubernetesObservation{}, operator.recordFailure(ctx, request, currentDocument, OperatorActionRollback, errors.New("rollback rendered Stack identity must match current rendering"))
	}
	transitionAuthority, transitionErr := reviewedRollbackTransition(request.BootstrapAuthority, currentDocument, document)
	if transitionErr != nil {
		return KubernetesObservation{}, operator.recordFailure(ctx, request, currentDocument, OperatorActionRollback, transitionErr)
	}
	if migrationErr := operator.rollbackMigrations(ctx, request.Target, current, previous, document, transitionAuthority); migrationErr != nil {
		return KubernetesObservation{}, operator.recordFailure(ctx, request, document, OperatorActionRollback, migrationErr)
	}
	observation, rollbackErr := operator.adapter.Apply(ctx, request.Target, manifests, transitionAuthority)
	if rollbackErr != nil {
		return KubernetesObservation{}, operator.recordFailure(ctx, request, document, OperatorActionRollback, rollbackErr)
	}
	if err := operator.recordTransition(ctx, request, document, currentDocument.Digest, observation.ObjectIDs); err != nil {
		return KubernetesObservation{}, err
	}
	return observation, nil
}

// reviewedRollbackTransition derives the only permitted revision transition:
// the caller must hold authority for the exact current rendering, and the
// explicit rollback target must have the same contained Stack identity.
func reviewedRollbackTransition(authority BootstrapAuthority, current, previous renderedDocument) (BootstrapAuthority, error) {
	if err := validateBootstrapAuthority(authority, current); err != nil {
		return BootstrapAuthority{}, err
	}
	if current.Stack != previous.Stack || current.Profile != previous.Profile || current.Namespace != previous.Namespace {
		return BootstrapAuthority{}, errors.New("validate rollback transition: reviewed Stack identity must match")
	}
	transition := authority
	transition.RenderDigest = previous.Digest
	return transition, nil
}

// Teardown delegates only containment-safe, re-observed deletion to the explicit operator adapter.
func (operator KubernetesOperator) Teardown(ctx context.Context, request OperatorRequest, rendered Rendered) error {
	manifests, document, err := operator.prepare(ctx, request, rendered)
	if err != nil {
		return err
	}
	if err := validateBootstrapAuthority(request.BootstrapAuthority, document); err != nil {
		return operator.recordFailure(ctx, request, document, OperatorActionTeardown, err)
	}
	affected := []ResourceID{}
	if operator.providers != nil {
		providerIDs, providerErr := operator.providers.TeardownDeclared(ctx, request.Target, rendered, request.BootstrapAuthority)
		if providerErr != nil {
			return operator.recordFailure(ctx, request, document, OperatorActionTeardown, providerErr)
		}
		if providerErr := validateDeclaredProviderIDs(document.Resources, providerIDs); providerErr != nil {
			return operator.recordFailure(ctx, request, document, OperatorActionTeardown, providerErr)
		}
		affected = append(affected, providerIDs...)
	}
	if teardownErr := operator.adapter.Teardown(ctx, request.Target, rendered, manifests, request.BootstrapAuthority); teardownErr != nil {
		return operator.recordFailure(ctx, request, document, OperatorActionTeardown, teardownErr)
	}
	affected = append(affected, manifestResources(manifests)...)
	return operator.record(ctx, request, document, OperatorActionTeardown, "torn_down", affected)
}

func validateDeclaredProviderIDs(resources []Resource, actual []ResourceID) error {
	expected := make([]ResourceID, 0, len(resources))
	for _, resource := range resources {
		if resource.Kind != ResourceKubernetes {
			expected = append(expected, resource.ID)
		}
	}
	actual = append([]ResourceID(nil), actual...)
	sort.Slice(expected, func(left, right int) bool { return expected[left] < expected[right] })
	sort.Slice(actual, func(left, right int) bool { return actual[left] < actual[right] })
	if len(expected) != len(actual) {
		return errors.New("validate declared provider reconciliation: declared provider resource set differs from desired state")
	}
	for index := range expected {
		if expected[index] != actual[index] || (index > 0 && actual[index] == actual[index-1]) {
			return errors.New("validate declared provider reconciliation: declared provider resource set differs from desired state")
		}
	}
	return nil
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

func (operator KubernetesOperator) upgradeMigrations(ctx context.Context, target OperatorTarget, rendered Rendered, document renderedDocument, authority BootstrapAuthority) error {
	if !containsDatabaseResource(document.Resources) {
		return nil
	}
	migrator, ok := operator.adapter.(KubernetesMigrationAdapter)
	if !ok {
		return errors.New("run Kubernetes operator migration: adapter does not implement declared migration execution")
	}
	if err := migrator.Upgrade(ctx, target, rendered, authority); err != nil {
		return errors.Wrap(err, "run Kubernetes operator migration upgrade")
	}
	return nil
}

func (operator KubernetesOperator) rollbackMigrations(ctx context.Context, target OperatorTarget, current, previous Rendered, previousDocument renderedDocument, authority BootstrapAuthority) error {
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
	if err := migrator.Rollback(ctx, target, current, previous, authority); err != nil {
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
	return validateOperatorTarget(request.Target)
}

func validateBootstrapAuthority(authority BootstrapAuthority, document renderedDocument) error {
	if authority.NamespaceUID == "" || authority.Nonce == "" {
		return errors.New("validate bootstrap authority: bootstrap authority is required")
	}
	if authority.Stack != document.Stack || authority.Profile != document.Profile || authority.Namespace != document.Namespace || authority.RenderDigest != document.Digest {
		return errors.New("validate bootstrap authority: Stack identity or render digest does not match reviewed rendered state")
	}
	return nil
}

func validateBootstrapIntent(authority BootstrapAuthority, document renderedDocument) error {
	if authority.NamespaceUID != "" || authority.Nonce == "" || authority.Stack != document.Stack || authority.Profile != document.Profile || authority.Namespace != document.Namespace || authority.RenderDigest != document.Digest {
		return errors.New("validate bootstrap authority: a new capability bound to reviewed rendered state is required")
	}
	return nil
}

func validateOperatorTarget(target OperatorTarget) error {
	if target.Kubeconfig == "" || !filepath.IsAbs(target.Kubeconfig) || target.Context == "" || len(target.Context) > 253 {
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
	return operator.appendRecord(ctx, record)
}

func (operator KubernetesOperator) recordTransition(ctx context.Context, request OperatorRequest, document renderedDocument, fromDigest string, resources []ResourceID) error {
	record := OperatorAuditRecord{Action: OperatorActionRollback, Actor: request.Actor, Context: request.Target.Context, Stack: document.Stack, Profile: document.Profile, Digest: document.Digest, TransitionFromDigest: fromDigest, Result: "rolled_back", Resources: append([]ResourceID(nil), resources...)}
	return operator.appendRecord(ctx, record)
}

func (operator KubernetesOperator) appendRecord(ctx context.Context, record OperatorAuditRecord) error {
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
