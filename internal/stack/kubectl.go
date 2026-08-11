package stack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cockroachdb/errors"
)

// KubectlCommandResult is bounded process output and its exact exit status.
type KubectlCommandResult struct {
	// Output is bounded combined command output. It is not retained in audit records.
	Output []byte
	// ExitCode is the child process status; zero means success.
	ExitCode int
}

// KubectlCommandRunner is the sole process boundary used by KubectlAdapter.
type KubectlCommandRunner interface {
	// Run executes an argv-only command with bounded captured output.
	Run(context.Context, string, []string, []byte) (KubectlCommandResult, error)
}

// KubectlAdapter applies and observes only an explicit kubeconfig/context target.
type KubectlAdapter struct {
	runner KubectlCommandRunner
}

const databaseReadinessAttempts = 120

// NewKubectlAdapter constructs a Kubernetes provider adapter over an injected process seam.
func NewKubectlAdapter(runner KubectlCommandRunner) (KubectlAdapter, error) {
	if runner == nil {
		return KubectlAdapter{}, errors.New("construct kubectl adapter: command runner is required")
	}
	return KubectlAdapter{runner: runner}, nil
}

// SystemKubectlRunner is the argv-only production command runner for stackctl.
type SystemKubectlRunner struct{}

// Run executes one bounded kubectl child process.
func (SystemKubectlRunner) Run(ctx context.Context, program string, arguments []string, input []byte) (KubectlCommandResult, error) {
	command := exec.CommandContext(ctx, program, arguments...)
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	result := KubectlCommandResult{Output: boundedOutput(output), ExitCode: 0}
	if err == nil {
		return result, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result, nil
	}
	return result, errors.Wrap(err, "run kubectl")
}

// Apply applies canonical manifests then re-observes provider object identities.
func (adapter KubectlAdapter) Apply(ctx context.Context, target OperatorTarget, manifests KubernetesManifests, authority BootstrapAuthority) (KubernetesObservation, error) {
	if err := adapter.verifyBootstrapAuthority(ctx, target, manifests, authority); err != nil {
		return KubernetesObservation{}, err
	}
	if err := adapter.runSuccess(ctx, target, []string{"apply", "--server-side", "--field-manager=agent-runtime-stackctl", "-f", "-"}, manifests.JSON()); err != nil {
		return KubernetesObservation{}, errors.Wrap(err, "apply rendered Kubernetes manifests")
	}
	return adapter.Observe(ctx, target, manifests)
}

// BootstrapNamespace atomically creates only an absent rendered Namespace and then re-observes its identity.
func (adapter KubectlAdapter) BootstrapNamespace(ctx context.Context, target OperatorTarget, manifests KubernetesManifests, nonceDigest string) (KubernetesNamespaceObservation, error) {
	if nonceDigest == "" {
		return KubernetesNamespaceObservation{}, errors.New("bootstrap rendered Kubernetes Namespace: nonce digest is required")
	}
	result, err := adapter.run(ctx, target, []string{"get", "Namespace/" + manifests.namespace.Metadata.Name, "--ignore-not-found=true", "-o", "json"}, nil)
	if err != nil {
		return KubernetesNamespaceObservation{}, err
	}
	if result.ExitCode != 0 {
		return KubernetesNamespaceObservation{}, kubectlExitError("get Namespace for bootstrap", result.ExitCode)
	}
	if len(bytes.TrimSpace(result.Output)) != 0 {
		return KubernetesNamespaceObservation{}, errors.New("bootstrap rendered Kubernetes Namespace: refuse pre-existing Namespace")
	}
	namespace := manifests.namespace
	namespace.Metadata.Annotations = map[string]string{bootstrapNonceDigestAnnotation: nonceDigest}
	encoded, err := json.Marshal(namespace)
	if err != nil {
		return KubernetesNamespaceObservation{}, errors.Wrap(err, "encode rendered Kubernetes Namespace")
	}
	if err := adapter.runSuccess(ctx, target, []string{"create", "--field-manager=agent-runtime-stackctl", "-f", "-"}, append(encoded, '\n')); err != nil {
		return KubernetesNamespaceObservation{}, errors.Wrap(err, "bootstrap rendered Kubernetes Namespace")
	}
	observed, err := adapter.observeManifest(ctx, target, manifests.namespace)
	if err != nil {
		return KubernetesNamespaceObservation{}, errors.Wrap(err, "observe bootstrapped Kubernetes Namespace")
	}
	expected := OwnershipLabels{PartOf: "agent-runtime", Stack: manifests.stack, Profile: manifests.profile}
	if observed.UID() == "" || observed.labels() != expected || observed.Metadata.Annotations[bootstrapNonceDigestAnnotation] != nonceDigest {
		return KubernetesNamespaceObservation{}, errors.New("observe bootstrapped Kubernetes Namespace: containment labels or UID do not match")
	}
	return KubernetesNamespaceObservation{Namespace: manifests.namespace.Metadata.Name, UID: observed.UID(), Labels: observed.labels(), RenderDigest: manifests.digest}, nil
}

// Observe reads every expected object UID and containment label without mutation.
func (adapter KubectlAdapter) Observe(ctx context.Context, target OperatorTarget, manifests KubernetesManifests) (KubernetesObservation, error) {
	state, err := adapter.observeState(ctx, target, manifests)
	if err != nil {
		return KubernetesObservation{}, err
	}
	identities := make([]ResourceID, 0, len(state.Resources))
	for _, resource := range state.Resources {
		identities = append(identities, resource.ID)
	}
	sort.Slice(identities, func(left, right int) bool { return identities[left] < identities[right] })
	return KubernetesObservation{ObjectIDs: identities}, nil
}

// Diff invokes kubectl's live diff operation and returns only bounded declared resource identities.
func (adapter KubectlAdapter) Diff(ctx context.Context, target OperatorTarget, manifests KubernetesManifests) (KubernetesDifference, error) {
	result, err := adapter.run(ctx, target, []string{"diff", "--server-side", "--field-manager=agent-runtime-stackctl", "-f", "-"}, manifests.JSON())
	if err != nil {
		return KubernetesDifference{}, err
	}
	switch result.ExitCode {
	case 0:
		return KubernetesDifference{}, nil
	case 1:
		resources := append([]ResourceID{"namespace"}, manifestResources(manifests)...)
		sort.Slice(resources, func(left, right int) bool { return resources[left] < resources[right] })
		changes := make([]Change, 0, len(resources))
		for _, resource := range resources {
			changes = append(changes, Change{Resource: resource, Kind: ChangeModified})
		}
		return KubernetesDifference{Changes: changes}, nil
	default:
		return KubernetesDifference{}, kubectlExitError("diff", result.ExitCode)
	}
}

// Teardown performs a complete identity preflight and rechecks each UID and label immediately before deletion.
func (adapter KubectlAdapter) Teardown(ctx context.Context, target OperatorTarget, rendered Rendered, manifests KubernetesManifests, authority BootstrapAuthority) error {
	if err := adapter.verifyBootstrapAuthority(ctx, target, manifests, authority); err != nil {
		return err
	}
	state, err := adapter.observeState(ctx, target, manifests)
	if err != nil {
		return err
	}
	plan, err := PlanKubernetesTeardown(rendered, state)
	if err != nil {
		return err
	}
	objects := make(map[ResourceID]KubernetesManifest, len(manifests.objects))
	for _, object := range manifests.objects {
		objects[object.Resource] = object
	}
	for _, action := range plan.Actions {
		if action.Behavior == DeleteTombstone {
			return errors.Newf("teardown rendered Kubernetes manifests: resource %s requires a tombstone adapter", action.Resource)
		}
	}
	containsRetainedObject := false
	for _, action := range plan.Actions {
		if action.Behavior == DeleteRetain {
			containsRetainedObject = true
			continue
		}
		object := objects[action.Resource]
		current, observeErr := adapter.observeManifest(ctx, target, object)
		if observeErr != nil {
			return observeErr
		}
		if current.UID() != action.UID || current.labels() != state.Labels {
			return errors.Newf("teardown rendered Kubernetes manifests: resource %s changed identity before deletion", action.Resource)
		}
		if err := adapter.deleteObserved(ctx, target, object, current); err != nil {
			return errors.Wrapf(err, "teardown rendered Kubernetes manifest %s", action.Resource)
		}
	}
	if containsRetainedObject {
		return nil
	}
	currentNamespace, err := adapter.observeManifest(ctx, target, manifests.namespace)
	if err != nil {
		return err
	}
	if currentNamespace.UID() != plan.NamespaceUID || currentNamespace.labels() != state.Labels {
		return errors.New("teardown rendered Kubernetes manifests: Namespace changed identity before deletion")
	}
	if err := adapter.verifyNamespaceEmpty(ctx, target, manifests.namespace.Metadata.Name); err != nil {
		return err
	}
	if err := adapter.deleteObserved(ctx, target, manifests.namespace, currentNamespace); err != nil {
		return errors.Wrap(err, "teardown rendered Kubernetes Namespace")
	}
	if err := adapter.runSuccess(ctx, target, []string{"wait", "--for=delete", "Namespace/" + manifests.namespace.Metadata.Name, "--timeout=120s"}, nil); err != nil {
		return errors.Wrap(err, "wait for rendered Kubernetes Namespace deletion")
	}
	return nil
}

func (adapter KubectlAdapter) verifyBootstrapAuthority(ctx context.Context, target OperatorTarget, manifests KubernetesManifests, authority BootstrapAuthority) error {
	if authority.Stack != manifests.stack || authority.Profile != manifests.profile || authority.Namespace != manifests.namespace.Metadata.Name || authority.NamespaceUID == "" {
		return errors.New("verify bootstrap authority: authority does not match rendered Kubernetes manifests")
	}
	observed, err := adapter.observeManifest(ctx, target, manifests.namespace)
	if err != nil {
		return errors.Wrap(err, "verify bootstrap authority Namespace")
	}
	expected := OwnershipLabels{PartOf: "agent-runtime", Stack: manifests.stack, Profile: manifests.profile}
	if observed.UID() != authority.NamespaceUID || observed.labels() != expected || observed.Metadata.Annotations[bootstrapNonceDigestAnnotation] != authority.NonceDigest() {
		return errors.New("verify bootstrap authority: Namespace is absent, replaced, or not owned by the reviewed Stack")
	}
	return nil
}

func (adapter KubectlAdapter) verifyNamespaceEmpty(ctx context.Context, target OperatorTarget, namespace string) error {
	resources := "deployments,statefulsets,jobs,services,ingresses,serviceaccounts,roles,rolebindings,networkpolicies,persistentvolumeclaims,configmaps,resourcequotas,secrets"
	result, err := adapter.run(ctx, target, []string{"get", resources, "--namespace", namespace, "-o", "json"}, nil)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return kubectlExitError("inventory Namespace before deletion", result.ExitCode)
	}
	return verifyNamespaceEmptyForDeletion(result.Output)
}

func verifyNamespaceEmptyForDeletion(encoded []byte) error {
	var inventory struct {
		Items []struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(encoded, &inventory); err != nil {
		return errors.Wrap(err, "decode Namespace inventory before deletion")
	}
	for _, item := range inventory.Items {
		if item.Kind == "" || item.Metadata.Name == "" {
			return errors.New("verify Namespace inventory before deletion: object is missing identity")
		}
		if (item.Kind == "ServiceAccount" && item.Metadata.Name == "default") || (item.Kind == "ConfigMap" && item.Metadata.Name == "kube-root-ca.crt") {
			continue
		}
		return errors.Newf("verify Namespace inventory before deletion: undeclared object %s/%s remains", item.Kind, item.Metadata.Name)
	}
	return nil
}

// Upgrade executes digest-verified declared SQL artifacts through the declared database workload.
func (adapter KubectlAdapter) Upgrade(ctx context.Context, target OperatorTarget, rendered Rendered, authority BootstrapAuthority) error {
	manifests, err := RenderKubernetes(rendered)
	if err != nil {
		return err
	}
	if err := adapter.verifyBootstrapAuthority(ctx, target, manifests, authority); err != nil {
		return err
	}
	document, err := parseRenderedBytes(rendered.JSON())
	if err != nil {
		return errors.Wrap(err, "upgrade rendered database migrations")
	}
	resources := resourcesByID(document.Resources)
	for _, resource := range document.Resources {
		if resource.Kind != ResourceDatabase {
			continue
		}
		if err := adapter.runMigrations(ctx, target, rendered, authority, document.Namespace, resource, resources, false, nil); err != nil {
			return err
		}
	}
	return nil
}

// Rollback executes only declared current migration artifacts newer than the previous rendered state.
func (adapter KubectlAdapter) Rollback(ctx context.Context, target OperatorTarget, current Rendered, previous Rendered, authority BootstrapAuthority) error {
	manifests, err := RenderKubernetes(previous)
	if err != nil {
		return err
	}
	if err := adapter.verifyBootstrapAuthority(ctx, target, manifests, authority); err != nil {
		return err
	}
	currentDocument, err := parseRenderedBytes(current.JSON())
	if err != nil {
		return errors.Wrap(err, "rollback current rendered database migrations")
	}
	previousDocument, err := parseRenderedBytes(previous.JSON())
	if err != nil {
		return errors.Wrap(err, "rollback previous rendered database migrations")
	}
	if currentDocument.Stack != previousDocument.Stack || currentDocument.Profile != previousDocument.Profile || currentDocument.Namespace != previousDocument.Namespace {
		return errors.New("rollback rendered database migrations: current and previous Stack identity must match")
	}
	previousDatabases := make(map[ResourceID]DatabaseResource)
	for _, resource := range previousDocument.Resources {
		if resource.Kind == ResourceDatabase {
			previousDatabases[resource.ID] = *resource.Database
		}
	}
	resources := resourcesByID(currentDocument.Resources)
	for _, resource := range currentDocument.Resources {
		if resource.Kind != ResourceDatabase {
			continue
		}
		previousDatabase, exists := previousDatabases[resource.ID]
		if !exists {
			previousDatabase = DatabaseResource{}
		}
		if err := adapter.runMigrations(ctx, target, previous, authority, currentDocument.Namespace, resource, resources, true, &previousDatabase); err != nil {
			return err
		}
	}
	return nil
}

func (adapter KubectlAdapter) runMigrations(ctx context.Context, target OperatorTarget, authorityRendered Rendered, authority BootstrapAuthority, namespace string, resource Resource, resources map[ResourceID]Resource, rollback bool, previous *DatabaseResource) error {
	database := resource.Database
	targetResource, exists := resources[database.MigrationTarget]
	if !exists || !isKubernetesWorkload(targetResource) {
		return errors.Newf("run database migrations: resource %s has no declared Kubernetes workload target", resource.ID)
	}
	if err := adapter.waitForWorkload(ctx, target, namespace, targetResource.Kubernetes); err != nil {
		return errors.Wrapf(err, "run database migrations for %s", resource.ID)
	}
	user := declaredPostgresUser(targetResource.Kubernetes)
	if err := adapter.waitForDatabase(ctx, target, namespace, targetResource.Kubernetes, database.Database, user); err != nil {
		return errors.Wrapf(err, "run database migrations for %s", resource.ID)
	}
	migrations := append([]Migration(nil), database.Migrations...)
	if rollback {
		sort.Slice(migrations, func(left, right int) bool { return migrations[left].Version > migrations[right].Version })
	} else {
		sort.Slice(migrations, func(left, right int) bool { return migrations[left].Version < migrations[right].Version })
	}
	for _, migration := range migrations {
		if rollback && previousMigrationMatches(*previous, migration) {
			continue
		}
		if !rollback && migration.Version > 1 {
			recorded, recordedErr := adapter.migrationRecorded(ctx, target, namespace, targetResource.Kubernetes, database.Database, user, migration.Version)
			if recordedErr != nil {
				return errors.Wrapf(recordedErr, "observe declared database migration %s version %d", resource.ID, migration.Version)
			}
			if recorded {
				continue
			}
		}
		artifact := migration.UpgradeArtifact
		expectedDigest := migration.UpgradeDigest
		if rollback {
			artifact = migration.RollbackArtifact
			expectedDigest = migration.RollbackDigest
		}
		sql, err := readMigrationArtifact(target.MigrationRoot, artifact, expectedDigest)
		if err != nil {
			return errors.Wrapf(err, "run database migration %s version %d", resource.ID, migration.Version)
		}
		arguments := []string{"exec", targetResource.Kubernetes.Kind + "/" + targetResource.Kubernetes.Name, "--namespace", namespace, "-i", "--", "psql", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", database.Database, "-f", "-"}
		manifests, manifestErr := RenderKubernetes(authorityRendered)
		if manifestErr != nil {
			return manifestErr
		}
		if verifyErr := adapter.verifyBootstrapAuthority(ctx, target, manifests, authority); verifyErr != nil {
			return verifyErr
		}
		if err := adapter.runSuccess(ctx, target, arguments, sql); err != nil {
			return errors.Wrapf(err, "execute declared database migration %s version %d", resource.ID, migration.Version)
		}
	}
	return nil
}

// migrationRecorded checks the durable migration journal before replaying a
// historical migration. Version one creates the schema that owns this journal,
// so it remains safely repeatable. Later migration artifacts can contain a
// point-in-time schema assertion which a newer reviewed migration deliberately
// changes; replaying such an artifact would turn a healthy upgraded database
// into a false failure.
func (adapter KubectlAdapter) migrationRecorded(ctx context.Context, target OperatorTarget, namespace string, workload *KubernetesResource, database, user string, version int) (bool, error) {
	if workload == nil || version < 2 {
		return false, errors.New("observe declared database migration: workload and version two or later are required")
	}
	existsQuery := "SELECT to_regclass('runtime.schema_migrations') IS NOT NULL"
	arguments := []string{"exec", workload.Kind + "/" + workload.Name, "--namespace", namespace, "--", "psql", "-At", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", database, "-c", existsQuery}
	result, err := adapter.run(ctx, target, arguments, nil)
	if err != nil {
		return false, err
	}
	if result.ExitCode != 0 {
		return false, kubectlExitError("observe database migration", result.ExitCode)
	}
	switch strings.TrimSpace(string(result.Output)) {
	case "f":
		return false, nil
	case "t":
		// PostgreSQL resolves relation names while planning a query. Querying the
		// migration table in the same statement as a to_regclass guard therefore
		// still fails before migration v2 creates that table. Only address the
		// relation after this independent existence probe succeeds.
		query := fmt.Sprintf("SELECT EXISTS (SELECT 1 FROM runtime.schema_migrations WHERE migration_version = %d)", version)
		arguments[len(arguments)-1] = query
		result, err = adapter.run(ctx, target, arguments, nil)
		if err != nil {
			return false, err
		}
		if result.ExitCode != 0 {
			return false, kubectlExitError("observe database migration", result.ExitCode)
		}
		switch strings.TrimSpace(string(result.Output)) {
		case "t":
			return true, nil
		case "f":
			return false, nil
		default:
			return false, errors.New("observe declared database migration: journal returned an invalid state")
		}
	default:
		return false, errors.New("observe declared database migration: relation probe returned an invalid state")
	}
}

// waitForDatabase closes the brief initdb gap after a workload becomes ready.
// It deliberately uses bounded command retries rather than a wall-clock sleep.
func (adapter KubectlAdapter) waitForDatabase(ctx context.Context, target OperatorTarget, namespace string, workload *KubernetesResource, database, user string) error {
	arguments := []string{"exec", workload.Kind + "/" + workload.Name, "--namespace", namespace, "--", "psql", "-At", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", database, "-c", "SELECT 1"}
	var lastErr error
	for attempt := 0; attempt < databaseReadinessAttempts; attempt++ {
		if err := adapter.runSuccess(ctx, target, arguments, nil); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if err := ctx.Err(); err != nil {
			return errors.Wrap(err, "await database readiness")
		}
	}
	return errors.Wrap(lastErr, "await database readiness after bounded attempts")
}

func declaredPostgresUser(workload *KubernetesResource) string {
	for _, variable := range workload.Environment {
		if variable.Name == "POSTGRES_USER" && variable.Value != "" {
			return variable.Value
		}
	}
	return "postgres"
}

func (adapter KubectlAdapter) waitForWorkload(ctx context.Context, target OperatorTarget, namespace string, workload *KubernetesResource) error {
	arguments := []string{"rollout", "status", workload.Kind + "/" + workload.Name, "--namespace", namespace, "--timeout=120s"}
	if workload.Kind == "Job" {
		arguments = []string{"wait", "--for=condition=complete", "Job/" + workload.Name, "--namespace", namespace, "--timeout=120s"}
	}
	return adapter.runSuccess(ctx, target, arguments, nil)
}

func previousMigrationMatches(previous DatabaseResource, current Migration) bool {
	for _, migration := range previous.Migrations {
		if migration.Version == current.Version && migration.UpgradeDigest == current.UpgradeDigest && migration.RollbackDigest == current.RollbackDigest {
			return true
		}
	}
	return false
}

func readMigrationArtifact(root, artifact, expectedDigest string) ([]byte, error) {
	if root == "" || !filepath.IsAbs(root) || !validArtifactPath(artifact) {
		return nil, errors.New("read declared migration artifact: explicit absolute root and safe relative path are required")
	}
	path := filepath.Join(root, filepath.Clean(artifact))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "read declared migration artifact")
	}
	sum := sha256.Sum256(data)
	actualDigest := fmt.Sprintf("sha256:%x", sum)
	if actualDigest != expectedDigest {
		return nil, errors.New("read declared migration artifact: digest does not match reviewed migration declaration")
	}
	return data, nil
}

func resourcesByID(resources []Resource) map[ResourceID]Resource {
	indexed := make(map[ResourceID]Resource, len(resources))
	for _, resource := range resources {
		indexed[resource.ID] = resource
	}
	return indexed
}

func (adapter KubectlAdapter) observeState(ctx context.Context, target OperatorTarget, manifests KubernetesManifests) (ObservedState, error) {
	namespace, err := adapter.observeManifest(ctx, target, manifests.namespace)
	if err != nil {
		return ObservedState{}, errors.Wrap(err, "observe rendered Kubernetes Namespace")
	}
	expected := OwnershipLabels{PartOf: "agent-runtime", Stack: manifests.stack, Profile: manifests.profile}
	if namespace.UID() == "" || namespace.labels() != expected {
		return ObservedState{}, errors.New("observe rendered Kubernetes Namespace: containment labels or UID do not match")
	}
	resources := make([]ObservedResource, 0, len(manifests.objects))
	for _, object := range manifests.objects {
		observed, observeErr := adapter.observeManifest(ctx, target, object)
		if observeErr != nil {
			return ObservedState{}, errors.Wrapf(observeErr, "observe rendered Kubernetes resource %s", object.Resource)
		}
		if observed.UID() == "" || observed.labels() != expected {
			return ObservedState{}, errors.Newf("observe rendered Kubernetes resource %s: containment labels or UID do not match", object.Resource)
		}
		resources = append(resources, ObservedResource{ID: object.Resource, UID: observed.UID(), Labels: observed.labels()})
	}
	return ObservedState{Stack: manifests.stack, Profile: manifests.profile, Namespace: manifests.namespace.Metadata.Name, NamespaceUID: namespace.UID(), RenderDigest: manifests.digest, Labels: expected, Resources: resources}, nil
}

func (adapter KubectlAdapter) observeManifest(ctx context.Context, target OperatorTarget, manifest KubernetesManifest) (observedObject, error) {
	arguments := []string{"get", manifest.Kind + "/" + manifest.Metadata.Name}
	if manifest.Kind != "Namespace" {
		arguments = append(arguments, "--namespace", manifest.Metadata.Namespace)
	}
	arguments = append(arguments, "-o", "json")
	result, err := adapter.run(ctx, target, arguments, nil)
	if err != nil {
		return observedObject{}, err
	}
	if result.ExitCode != 0 {
		return observedObject{}, kubectlExitError("get", result.ExitCode)
	}
	var object observedObject
	if err := json.Unmarshal(result.Output, &object); err != nil {
		return observedObject{}, errors.Wrap(err, "decode Kubernetes object identity")
	}
	return object, nil
}

type observedObject struct {
	Metadata struct {
		UID             ObservedUID       `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Labels          map[string]string `json:"labels"`
		Annotations     map[string]string `json:"annotations"`
	} `json:"metadata"`
}

func (object observedObject) labels() OwnershipLabels {
	return OwnershipLabels{PartOf: object.Metadata.Labels[partOfLabel], Stack: object.Metadata.Labels[stackLabel], Profile: Profile(object.Metadata.Labels[profileLabel])}
}

func (object observedObject) UID() ObservedUID { return object.Metadata.UID }

func (adapter KubectlAdapter) run(ctx context.Context, target OperatorTarget, action []string, input []byte) (KubectlCommandResult, error) {
	if err := validateOperatorRequest(OperatorRequest{Actor: "adapter", Target: target}); err != nil {
		return KubectlCommandResult{}, err
	}
	arguments := []string{"--kubeconfig", target.Kubeconfig, "--context", target.Context}
	arguments = append(arguments, action...)
	result, err := adapter.runner.Run(ctx, "kubectl", arguments, input)
	if err != nil {
		return KubectlCommandResult{}, errors.Wrap(err, "run explicit kubectl operator command")
	}
	return result, nil
}

func (adapter KubectlAdapter) runSuccess(ctx context.Context, target OperatorTarget, action []string, input []byte) error {
	result, err := adapter.run(ctx, target, action, input)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return kubectlExitError(action[0], result.ExitCode)
	}
	return nil
}

func (adapter KubectlAdapter) deleteObserved(ctx context.Context, target OperatorTarget, manifest KubernetesManifest, observed observedObject) error {
	if observed.UID() == "" || observed.Metadata.ResourceVersion == "" {
		return errors.New("delete observed Kubernetes object: UID and resource version are required")
	}
	path := "/api/" + manifest.APIVersion + "/"
	if strings.Contains(manifest.APIVersion, "/") {
		parts := strings.Split(manifest.APIVersion, "/")
		path = "/apis/" + parts[0] + "/" + parts[1] + "/"
	}
	if manifest.Kind != "Namespace" {
		path += "namespaces/" + url.PathEscape(manifest.Metadata.Namespace) + "/"
	}
	resource, ok := kubernetesResourcePath(manifest.Kind)
	if !ok {
		return errors.Newf("delete observed Kubernetes object: unsupported kind %s", manifest.Kind)
	}
	path += resource + "/" + url.PathEscape(manifest.Metadata.Name)
	payload := fmt.Sprintf(`{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":%q,"resourceVersion":%q}}`, observed.UID(), observed.Metadata.ResourceVersion)
	return adapter.runSuccess(ctx, target, []string{"delete", "--raw", path, "-f", "-"}, []byte(payload+"\n"))
}

func kubernetesResourcePath(kind string) (string, bool) {
	resources := map[string]string{"Namespace": "namespaces", "Deployment": "deployments", "StatefulSet": "statefulsets", "Job": "jobs", "Service": "services", "Ingress": "ingresses", "ServiceAccount": "serviceaccounts", "Role": "roles", "RoleBinding": "rolebindings", "NetworkPolicy": "networkpolicies", "PersistentVolumeClaim": "persistentvolumeclaims", "ConfigMap": "configmaps", "ResourceQuota": "resourcequotas", "Secret": "secrets"}
	resource, ok := resources[kind]
	return resource, ok
}

func kubectlExitError(action string, code int) error {
	return errors.Newf("run kubectl %s: exit status %d", action, code)
}

func boundedOutput(output []byte) []byte {
	const maximumOutputBytes = 16 << 10
	if len(output) <= maximumOutputBytes {
		return append([]byte(nil), output...)
	}
	return append([]byte(nil), output[:maximumOutputBytes]...)
}

// JSONLineAuditLog retains secret-safe operator evidence in an explicit append-only file.
type JSONLineAuditLog struct {
	// Path is the caller-supplied audit destination.
	Path string
}

// Append writes and syncs exactly one JSON operator audit record.
func (log JSONLineAuditLog) Append(ctx context.Context, record OperatorAuditRecord) error {
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, "append Kubernetes operator audit record")
	}
	if log.Path == "" {
		return errors.New("append Kubernetes operator audit record: path is required")
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return errors.Wrap(err, "encode Kubernetes operator audit record")
	}
	file, err := os.OpenFile(log.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.Wrap(err, "open Kubernetes operator audit log")
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return errors.Wrap(err, "write Kubernetes operator audit record")
	}
	if err := file.Sync(); err != nil {
		return errors.Wrap(err, "sync Kubernetes operator audit record")
	}
	return nil
}
