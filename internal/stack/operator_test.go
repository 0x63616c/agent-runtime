package stack_test

import (
	"context"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/stack"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type recordedAudit struct{ records []stack.OperatorAuditRecord }

func (audit *recordedAudit) Append(_ context.Context, record stack.OperatorAuditRecord) error {
	audit.records = append(audit.records, record)
	return nil
}

type fakeKubernetesOperator struct {
	changes    []stack.Change
	applies    int
	diffs      int
	observes   int
	teardowns  int
	upgrades   int
	rollbacks  int
	verifies   int
	verifyErr  error
	upgradeErr error
	postErr    error
	postPhase  bool
	events     []string
}

func (*fakeKubernetesOperator) BootstrapNamespace(_ context.Context, _ stack.OperatorTarget, _ stack.KubernetesManifests, _ string) (stack.KubernetesNamespaceObservation, error) {
	return stack.KubernetesNamespaceObservation{}, nil
}

func (operator *fakeKubernetesOperator) VerifyBootstrapAuthority(_ context.Context, _ stack.OperatorTarget, _ stack.KubernetesManifests, _ stack.BootstrapAuthority) error {
	operator.verifies++
	return operator.verifyErr
}

type fakeDeclaredProvider struct {
	reconciled []stack.ResourceID
	tornDown   []stack.ResourceID
	reconciles int
	teardowns  int
}

func (provider *fakeDeclaredProvider) ReconcileDeclared(_ context.Context, _ stack.OperatorTarget, _ stack.Rendered, _ stack.BootstrapAuthority) ([]stack.ResourceID, error) {
	provider.reconciles++
	return append([]stack.ResourceID(nil), provider.reconciled...), nil
}

func (provider *fakeDeclaredProvider) TeardownDeclared(_ context.Context, _ stack.OperatorTarget, _ stack.Rendered, _ stack.BootstrapAuthority) ([]stack.ResourceID, error) {
	provider.teardowns++
	return append([]stack.ResourceID(nil), provider.tornDown...), nil
}

func (operator *fakeKubernetesOperator) Apply(_ context.Context, _ stack.OperatorTarget, _ stack.KubernetesManifests, _ stack.BootstrapAuthority) (stack.KubernetesObservation, error) {
	operator.applies++
	operator.events = append(operator.events, "apply")
	return stack.KubernetesObservation{ObjectIDs: []stack.ResourceID{"api"}}, nil
}

func (operator *fakeKubernetesOperator) ApplyPostMigration(_ context.Context, _ stack.OperatorTarget, _ stack.KubernetesManifests, _ stack.BootstrapAuthority) (stack.KubernetesObservation, error) {
	if !operator.postPhase {
		return stack.KubernetesObservation{}, nil
	}
	operator.events = append(operator.events, "post")
	return stack.KubernetesObservation{ObjectIDs: []stack.ResourceID{"sandbox-host-bootstrap"}}, operator.postErr
}

func (operator *fakeKubernetesOperator) Observe(_ context.Context, _ stack.OperatorTarget, _ stack.KubernetesManifests) (stack.KubernetesObservation, error) {
	operator.observes++
	return stack.KubernetesObservation{ObjectIDs: []stack.ResourceID{"api"}}, nil
}

func (operator *fakeKubernetesOperator) Diff(_ context.Context, _ stack.OperatorTarget, _ stack.KubernetesManifests) (stack.KubernetesDifference, error) {
	operator.diffs++
	return stack.KubernetesDifference{Changes: operator.changes}, nil
}

func (operator *fakeKubernetesOperator) Teardown(_ context.Context, _ stack.OperatorTarget, _ stack.Rendered, _ stack.KubernetesManifests, _ stack.BootstrapAuthority) error {
	operator.teardowns++
	return nil
}

func (operator *fakeKubernetesOperator) Upgrade(_ context.Context, _ stack.OperatorTarget, _ stack.Rendered, _ stack.BootstrapAuthority) error {
	operator.upgrades++
	operator.events = append(operator.events, "upgrade")
	return operator.upgradeErr
}

func (operator *fakeKubernetesOperator) Rollback(_ context.Context, _ stack.OperatorTarget, _ stack.Rendered, _ stack.Rendered, _ stack.BootstrapAuthority) error {
	operator.rollbacks++
	return nil
}

func operatorRequest(rendered stack.Rendered) stack.OperatorRequest {
	authority, err := stack.NewBootstrapAuthority(rendered, "uid-bootstrap")
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return stack.OperatorRequest{
		Actor:              "platform-operator",
		Target:             stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "disposable-ci"},
		BootstrapAuthority: authority,
	}
}

var _ = Describe("Audited Kubernetes operator", func() {
	It("applies post-migration Jobs only after a successful migration upgrade", func() {
		spec, err := stack.Parse(strings.NewReader(databaseStack(`{"database":"agent_runtime","schema":"runtime","connection_reference":"database-secret","migration_target":"postgres","migrations":[{"version":1,"upgrade_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rollback_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","upgrade_artifact":"migrations/v1.up.sql","rollback_artifact":"migrations/v1.down.sql"}]}`)))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		adapter := &fakeKubernetesOperator{postPhase: true}
		operator, err := stack.NewKubernetesOperator(adapter, &recordedAudit{})
		Expect(err).NotTo(HaveOccurred())
		request := operatorRequest(rendered)
		request.Target.MigrationRoot = "/reviewed-migrations"
		_, err = operator.Apply(context.Background(), request, rendered)
		Expect(err).NotTo(HaveOccurred())
		Expect(adapter.events).To(Equal([]string{"apply", "upgrade", "post"}))

		adapter = &fakeKubernetesOperator{postPhase: true, upgradeErr: context.DeadlineExceeded}
		operator, err = stack.NewKubernetesOperator(adapter, &recordedAudit{})
		Expect(err).NotTo(HaveOccurred())
		_, err = operator.Apply(context.Background(), request, rendered)
		Expect(err).To(MatchError(ContainSubstring("deadline exceeded")))
		Expect(adapter.events).To(Equal([]string{"apply", "upgrade"}))
	})

	It("transitions verified authority only to a later render of the same Stack", func() {
		currentSpec, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		nextSpec, err := stack.Parse(strings.NewReader(strings.Replace(validIdentityStack, "ntfy-token", "ntfy-token-v2", 1)))
		Expect(err).NotTo(HaveOccurred())
		current, err := stack.Render(currentSpec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		next, err := stack.Render(nextSpec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		adapter := &fakeKubernetesOperator{}
		audit := &recordedAudit{}
		operator, err := stack.NewKubernetesOperator(adapter, audit)
		Expect(err).NotTo(HaveOccurred())
		request := operatorRequest(current)
		var bound stack.BootstrapAuthority
		Expect(operator.Transition(context.Background(), request, current, next, func(authority stack.BootstrapAuthority) error {
			bound = authority
			return nil
		})).To(Succeed())
		Expect(adapter.verifies).To(Equal(1))
		Expect(bound.RenderDigest).To(Equal(next.Digest()))
		Expect(bound.Nonce).To(Equal(request.BootstrapAuthority.Nonce))
		Expect(audit.records).To(ConsistOf(stack.OperatorAuditRecord{Action: stack.OperatorActionTransition, Actor: request.Actor, Context: request.Target.Context, Stack: "feature-a", Profile: stack.ProfileLocal, Digest: next.Digest(), TransitionFromDigest: current.Digest(), Result: "transitioned", Resources: []stack.ResourceID{"namespace"}}))
	})

	It("refuses stale authority and a cross-profile transition before binding", func() {
		spec, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		current, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		next, err := stack.Render(spec, stack.ProfileProduction)
		Expect(err).NotTo(HaveOccurred())
		adapter := &fakeKubernetesOperator{}
		operator, err := stack.NewKubernetesOperator(adapter, &recordedAudit{})
		Expect(err).NotTo(HaveOccurred())
		request := operatorRequest(current)
		called := false
		Expect(operator.Transition(context.Background(), request, current, next, func(stack.BootstrapAuthority) error { called = true; return nil })).To(MatchError(ContainSubstring("same Stack identity")))
		request.BootstrapAuthority.RenderDigest = "sha256:" + strings.Repeat("0", 64)
		Expect(operator.Transition(context.Background(), request, current, current, func(stack.BootstrapAuthority) error { called = true; return nil })).To(MatchError(ContainSubstring("render digest")))
		Expect(called).To(BeFalse())
		Expect(adapter.verifies).To(BeZero())
	})

	It("refuses standalone apply before any adapter can mutate an unproven namespace", func() {
		spec, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		adapter := &fakeKubernetesOperator{}
		operator, err := stack.NewKubernetesOperator(adapter, &recordedAudit{})
		Expect(err).NotTo(HaveOccurred())

		_, err = operator.Apply(context.Background(), stack.OperatorRequest{
			Actor: "platform-operator", Target: stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "disposable-ci"},
		}, rendered)

		Expect(err).To(MatchError(ContainSubstring("bootstrap authority is required")))
		Expect(adapter.applies).To(Equal(0))
	})

	It("refuses standalone reconcile and teardown without bootstrap authority", func() {
		spec, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		adapter := &fakeKubernetesOperator{}
		operator, err := stack.NewKubernetesOperator(adapter, &recordedAudit{})
		Expect(err).NotTo(HaveOccurred())
		request := stack.OperatorRequest{Actor: "platform-operator", Target: stack.OperatorTarget{Kubeconfig: "/explicit/kubeconfig", Context: "disposable-ci"}}

		_, reconcileErr := operator.Reconcile(context.Background(), request, rendered)
		teardownErr := operator.Teardown(context.Background(), request, rendered)

		Expect(reconcileErr).To(MatchError(ContainSubstring("bootstrap authority is required")))
		Expect(teardownErr).To(MatchError(ContainSubstring("bootstrap authority is required")))
		Expect(adapter.applies).To(Equal(0))
		Expect(adapter.teardowns).To(Equal(0))
	})

	It("refuses apply, reconcile, and teardown when authority was bootstrapped for another rendering", func() {
		spec, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		adapter := &fakeKubernetesOperator{changes: []stack.Change{{Resource: "api"}}}
		operator, err := stack.NewKubernetesOperator(adapter, &recordedAudit{})
		Expect(err).NotTo(HaveOccurred())
		request := operatorRequest(rendered)
		request.BootstrapAuthority.RenderDigest = "sha256:" + strings.Repeat("0", 64)

		_, applyErr := operator.Apply(context.Background(), request, rendered)
		_, reconcileErr := operator.Reconcile(context.Background(), request, rendered)
		teardownErr := operator.Teardown(context.Background(), request, rendered)

		Expect(applyErr).To(MatchError(ContainSubstring("render digest")))
		Expect(reconcileErr).To(MatchError(ContainSubstring("render digest")))
		Expect(teardownErr).To(MatchError(ContainSubstring("render digest")))
		Expect(adapter.applies).To(BeZero())
		Expect(adapter.teardowns).To(BeZero())
	})

	It("refuses every migration-capable lifecycle action when the render-digest authority is stale", func() {
		spec, err := stack.Parse(strings.NewReader(databaseStack(`{"database":"agent_runtime","schema":"runtime","connection_reference":"database-secret","migration_target":"postgres","migrations":[{"version":1,"upgrade_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rollback_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","upgrade_artifact":"migrations/v1.up.sql","rollback_artifact":"migrations/v1.down.sql"}]}`)))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		adapter := &fakeKubernetesOperator{changes: []stack.Change{{Resource: "postgres"}}}
		operator, err := stack.NewKubernetesOperator(adapter, &recordedAudit{})
		Expect(err).NotTo(HaveOccurred())
		request := operatorRequest(rendered)
		request.Target.MigrationRoot = "/reviewed-migrations"
		request.BootstrapAuthority.RenderDigest = "sha256:" + strings.Repeat("0", 64)

		_, applyErr := operator.Apply(context.Background(), request, rendered)
		_, reconcileErr := operator.Reconcile(context.Background(), request, rendered)
		_, rollbackErr := operator.Rollback(context.Background(), request, rendered, rendered)
		teardownErr := operator.Teardown(context.Background(), request, rendered)

		Expect(applyErr).To(MatchError(ContainSubstring("render digest")))
		Expect(reconcileErr).To(MatchError(ContainSubstring("render digest")))
		Expect(rollbackErr).To(MatchError(ContainSubstring("render digest")))
		Expect(teardownErr).To(MatchError(ContainSubstring("render digest")))
		Expect(adapter.applies).To(BeZero())
		Expect(adapter.upgrades).To(BeZero())
		Expect(adapter.rollbacks).To(BeZero())
		Expect(adapter.teardowns).To(BeZero())
	})

	It("reconciles and accounts for every declared non-Kubernetes resource", func() {
		spec, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		adapter := &fakeKubernetesOperator{}
		provider := &fakeDeclaredProvider{reconciled: []stack.ResourceID{"notifier-secret"}}
		audit := &recordedAudit{}
		operator, err := stack.NewKubernetesOperatorWithProviders(adapter, provider, audit)
		Expect(err).NotTo(HaveOccurred())

		_, err = operator.Apply(context.Background(), operatorRequest(rendered), rendered)
		Expect(err).NotTo(HaveOccurred())
		Expect(provider.reconciles).To(Equal(1))
		Expect(audit.records).To(HaveLen(1))
		Expect(audit.records[0].Resources).To(Equal([]stack.ResourceID{"api", "notifier-secret"}))
	})

	It("fails closed when a provider omits or invents a declared resource", func() {
		spec, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		request := operatorRequest(rendered)

		for _, returned := range [][]stack.ResourceID{nil, {"foreign"}} {
			provider := &fakeDeclaredProvider{reconciled: returned}
			operator, constructErr := stack.NewKubernetesOperatorWithProviders(&fakeKubernetesOperator{}, provider, &recordedAudit{})
			Expect(constructErr).NotTo(HaveOccurred())
			_, applyErr := operator.Apply(context.Background(), request, rendered)
			Expect(applyErr).To(MatchError(ContainSubstring("declared provider resource set differs")))
		}
	})

	It("rolls back a changed reviewed rendering while retaining current bootstrap authority", func() {
		rendered := renderIdentityStack()
		previousSpec, err := stack.Parse(strings.NewReader(strings.Replace(validIdentityStack, `"version":"v1"`, `"version":"v2"`, 1)))
		Expect(err).NotTo(HaveOccurred())
		previous, err := stack.Render(previousSpec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		Expect(previous.Digest()).NotTo(Equal(rendered.Digest()))
		adapter := &fakeKubernetesOperator{}
		audit := &recordedAudit{}
		operator, err := stack.NewKubernetesOperator(adapter, audit)
		Expect(err).NotTo(HaveOccurred())

		_, err = operator.Rollback(context.Background(), operatorRequest(rendered), rendered, previous)

		Expect(err).NotTo(HaveOccurred())
		Expect(adapter.applies).To(Equal(1))
		Expect(audit.records).To(HaveLen(1))
		Expect(audit.records[0].TransitionFromDigest).To(Equal(rendered.Digest()))
		Expect(audit.records[0].Digest).To(Equal(previous.Digest()))
	})

	It("tears provider resources down before Kubernetes dependencies", func() {
		spec, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		adapter := &fakeKubernetesOperator{}
		provider := &fakeDeclaredProvider{tornDown: []stack.ResourceID{"notifier-secret"}}
		audit := &recordedAudit{}
		operator, err := stack.NewKubernetesOperatorWithProviders(adapter, provider, audit)
		Expect(err).NotTo(HaveOccurred())

		err = operator.Teardown(context.Background(), operatorRequest(rendered), rendered)
		Expect(err).NotTo(HaveOccurred())
		Expect(provider.teardowns).To(Equal(1))
		Expect(adapter.teardowns).To(Equal(1))
		Expect(audit.records[0].Resources).To(Equal([]stack.ResourceID{"notifier-secret"}))
	})
	It("reconciles only declared drift and retains the actor, target, digest, and bounded affected resources", func() {
		spec, err := stack.Parse(strings.NewReader(stackDocument(kubernetesManifestResources, kubernetesManifestResources, kubernetesManifestResources)))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileCI)
		Expect(err).NotTo(HaveOccurred())
		adapter := &fakeKubernetesOperator{changes: []stack.Change{{Resource: "api", Kind: stack.ChangeModified}}}
		audit := &recordedAudit{}
		operator, err := stack.NewKubernetesOperator(adapter, audit)
		Expect(err).NotTo(HaveOccurred())

		result, err := operator.Reconcile(context.Background(), operatorRequest(rendered), rendered)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Applied).To(BeTrue())
		Expect(adapter.applies).To(Equal(1))
		Expect(audit.records).To(HaveLen(1))
		Expect(audit.records[0].Action).To(Equal(stack.OperatorActionReconcile))
		Expect(audit.records[0].Actor).To(Equal("platform-operator"))
		Expect(audit.records[0].Context).To(Equal("disposable-ci"))
		Expect(audit.records[0].Digest).To(Equal(rendered.Digest()))
		Expect(audit.records[0].Result).To(Equal("applied"))
		Expect(audit.records[0].Resources).To(Equal([]stack.ResourceID{"api"}))
	})

	It("reconciles declared providers even when Kubernetes manifests are unchanged", func() {
		spec, err := stack.Parse(strings.NewReader(validIdentityStack))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		adapter := &fakeKubernetesOperator{}
		provider := &fakeDeclaredProvider{reconciled: []stack.ResourceID{"notifier-secret"}}
		audit := &recordedAudit{}
		operator, err := stack.NewKubernetesOperatorWithProviders(adapter, provider, audit)
		Expect(err).NotTo(HaveOccurred())

		result, err := operator.Reconcile(context.Background(), operatorRequest(rendered), rendered)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Applied).To(BeFalse())
		Expect(adapter.diffs).To(Equal(1))
		Expect(provider.reconciles).To(Equal(1))
		Expect(audit.records).To(HaveLen(1))
		Expect(audit.records[0].Result).To(Equal("reconciled"))
		Expect(audit.records[0].Resources).To(Equal([]stack.ResourceID{"notifier-secret"}))
	})

	It("reconciles declared providers without reading Kubernetes fields owned by Tilt", func() {
		database := `{"database":"agent_runtime","schema":"runtime","connection_reference":"database-secret","migration_target":"postgres","migrations":[{"version":1,"upgrade_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rollback_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","upgrade_artifact":"migrations/v1.up.sql","rollback_artifact":"migrations/v1.down.sql"}]}`
		spec, err := stack.Parse(strings.NewReader(databaseStack(database)))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileLocal)
		Expect(err).NotTo(HaveOccurred())
		adapter := &fakeKubernetesOperator{changes: []stack.Change{{Resource: "api", Kind: stack.ChangeModified}}}
		provider := &fakeDeclaredProvider{reconciled: []stack.ResourceID{"database", "database-secret"}}
		audit := &recordedAudit{}
		operator, err := stack.NewKubernetesOperatorWithProviders(adapter, provider, audit)
		Expect(err).NotTo(HaveOccurred())

		request := operatorRequest(rendered)
		request.Target.MigrationRoot = "/reviewed-migrations"
		result, err := operator.ReconcileProviders(context.Background(), request, rendered)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Applied).To(BeFalse())
		Expect(adapter.applies).To(BeZero())
		Expect(adapter.diffs).To(BeZero())
		Expect(adapter.upgrades).To(Equal(1))
		Expect(provider.reconciles).To(Equal(1))
		Expect(audit.records).To(HaveLen(1))
		Expect(audit.records[0].Action).To(Equal(stack.OperatorActionReconcile))
		Expect(audit.records[0].Result).To(Equal("reconciled"))
		Expect(audit.records[0].Resources).To(Equal([]stack.ResourceID{"database", "database-secret"}))
	})

	It("does not mutate when observed state already matches the rendered manifests", func() {
		spec, err := stack.Parse(strings.NewReader(stackDocument(kubernetesManifestResources, kubernetesManifestResources, kubernetesManifestResources)))
		Expect(err).NotTo(HaveOccurred())
		rendered, err := stack.Render(spec, stack.ProfileCI)
		Expect(err).NotTo(HaveOccurred())
		adapter := &fakeKubernetesOperator{}
		audit := &recordedAudit{}
		operator, err := stack.NewKubernetesOperator(adapter, audit)
		Expect(err).NotTo(HaveOccurred())

		result, err := operator.Reconcile(context.Background(), operatorRequest(rendered), rendered)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Applied).To(BeFalse())
		Expect(adapter.applies).To(Equal(0))
		Expect(audit.records[0].Result).To(Equal("unchanged"))
	})
})
