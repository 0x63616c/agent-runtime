// Package stack defines the typed desired-state input for operator-owned infrastructure.
package stack

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"slices"
	"sort"

	"github.com/cockroachdb/errors"
)

const schemaVersion = 1

var stackNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$`)

// Name is the sole validated identity shared by render, apply, and teardown.
type Name struct{ value string }

// String returns the DNS-label-safe stack identity.
func (name Name) String() string { return name.value }

// Profile selects one reviewed rendering policy.
type Profile string

const (
	// ProfileLocal selects the isolated disposable developer topology.
	ProfileLocal Profile = "local"
	// ProfileCI selects the isolated disposable continuous-integration topology.
	ProfileCI Profile = "ci"
	// ProfileProduction selects the persistent self-hosted production topology.
	ProfileProduction Profile = "production"
)

// Spec is validated versioned desired state and has no usable zero value.
type Spec struct {
	Version  int
	Name     Name
	profiles Profiles
}

type specInput struct {
	Version  int          `json:"version"`
	Name     string       `json:"name"`
	Profiles profileInput `json:"profiles"`
}

type profileInput struct {
	Local      profileDocument `json:"local"`
	CI         profileDocument `json:"ci"`
	Production profileDocument `json:"production"`
}

type profileDocument struct {
	Namespace          string             `json:"namespace"`
	Prerequisites      []Prerequisite     `json:"prerequisites"`
	SandboxQuotaPolicy SandboxQuotaPolicy `json:"sandbox_quota_policy"`
	Resources          json.RawMessage    `json:"resources"`
}

// Profiles is the closed set of reviewed topology profiles in one Stack.
type Profiles struct {
	Local      ProfileSpec
	CI         ProfileSpec
	Production ProfileSpec
}

// ProfileSpec is one explicitly namespaced resource topology.
type ProfileSpec struct {
	Namespace          string
	Prerequisites      []Prerequisite
	SandboxQuotaPolicy SandboxQuotaPolicy
	Resources          []Resource
}

// Parse decodes exactly one strict Stack document and validates its identity.
func Parse(input io.Reader) (Spec, error) {
	if input == nil {
		return Spec{}, errors.New("parse stack specification: input is required")
	}
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	var document specInput
	if err := decoder.Decode(&document); err != nil {
		return Spec{}, errors.Wrap(err, "parse stack specification")
	}
	if err := requireEnd(decoder); err != nil {
		return Spec{}, err
	}
	if document.Version != schemaVersion {
		return Spec{}, errors.Newf("validate stack specification: version must be %d", schemaVersion)
	}
	name, err := parseName(document.Name)
	if err != nil {
		return Spec{}, err
	}
	profiles, err := parseProfiles(document.Profiles)
	if err != nil {
		return Spec{}, err
	}
	if profiles.Local.Namespace != "ar-"+name.String() || profiles.CI.Namespace != "ar-ci-"+name.String() || profiles.Production.Namespace != name.String() {
		return Spec{}, errors.New("validate stack specification: profile namespaces must be explicitly bound to the sole stack identity")
	}
	return Spec{Version: document.Version, Name: name, profiles: profiles}, nil
}

// Namespace returns the explicit namespace for a reviewed profile.
func (spec Spec) Namespace(profile Profile) string {
	selected, ok := spec.profile(profile)
	if !ok {
		return ""
	}
	return selected.Namespace
}

// SandboxQuotaPolicy returns the explicit finite sandbox defaults and ceilings for a profile.
func (spec Spec) SandboxQuotaPolicy(profile Profile) (SandboxQuotaPolicy, error) {
	selected, ok := spec.profile(profile)
	if !ok {
		return SandboxQuotaPolicy{}, errors.New("select sandbox quota policy: profile must be local, ci, or production")
	}
	return selected.SandboxQuotaPolicy, nil
}

func parseProfiles(input profileInput) (Profiles, error) {
	local, err := parseProfile(ProfileLocal, input.Local)
	if err != nil {
		return Profiles{}, err
	}
	ci, err := parseProfile(ProfileCI, input.CI)
	if err != nil {
		return Profiles{}, err
	}
	production, err := parseProfile(ProfileProduction, input.Production)
	if err != nil {
		return Profiles{}, err
	}
	profiles := Profiles{Local: local, CI: ci, Production: production}
	if err := validateProfileTopology(profiles); err != nil {
		return Profiles{}, err
	}
	return profiles, nil
}

func parseProfile(profile Profile, input profileDocument) (ProfileSpec, error) {
	if !stackNamePattern.MatchString(input.Namespace) || input.Namespace == "default" {
		return ProfileSpec{}, errors.Newf("validate %s stack profile: namespace must be an explicit non-default DNS label", profile)
	}
	if input.Resources == nil {
		return ProfileSpec{}, errors.Newf("validate %s stack profile: resources must be declared", profile)
	}
	if input.Prerequisites == nil {
		return ProfileSpec{}, errors.Newf("validate %s stack profile: prerequisites must be explicitly declared", profile)
	}
	for _, prerequisite := range input.Prerequisites {
		if err := validatePrerequisite(prerequisite); err != nil {
			return ProfileSpec{}, errors.Wrapf(err, "validate %s stack profile", profile)
		}
	}
	prerequisiteNames := map[string]struct{}{}
	for _, prerequisite := range input.Prerequisites {
		if _, duplicate := prerequisiteNames[prerequisite.Name]; duplicate {
			return ProfileSpec{}, errors.Newf("validate %s stack profile: prerequisite %s is declared more than once", profile, prerequisite.Name)
		}
		prerequisiteNames[prerequisite.Name] = struct{}{}
	}
	if err := validateSandboxQuotaPolicy(input.SandboxQuotaPolicy); err != nil {
		return ProfileSpec{}, errors.Wrapf(err, "validate %s stack profile", profile)
	}
	var resources []Resource
	resourceDecoder := json.NewDecoder(bytes.NewReader(input.Resources))
	resourceDecoder.DisallowUnknownFields()
	if err := resourceDecoder.Decode(&resources); err != nil {
		return ProfileSpec{}, errors.Wrapf(err, "parse %s stack resources", profile)
	}
	if len(resources) == 0 {
		return ProfileSpec{}, errors.Newf("validate %s stack profile: resources must not be empty", profile)
	}
	for _, resource := range resources {
		if err := validateResource(resource, input.Namespace); err != nil {
			return ProfileSpec{}, errors.Wrapf(err, "validate %s stack profile", profile)
		}
	}
	if err := validateDependencyGraph(resources); err != nil {
		return ProfileSpec{}, errors.Wrapf(err, "validate %s stack profile", profile)
	}
	return ProfileSpec{Namespace: input.Namespace, Prerequisites: append([]Prerequisite(nil), input.Prerequisites...), SandboxQuotaPolicy: input.SandboxQuotaPolicy, Resources: resources}, nil
}

func validateDependencyGraph(resources []Resource) error {
	byID := make(map[ResourceID]Resource, len(resources))
	for _, resource := range resources {
		if _, duplicate := byID[resource.ID]; duplicate {
			return errors.Newf("resource %s is declared more than once", resource.ID)
		}
		byID[resource.ID] = resource
	}
	for _, resource := range resources {
		for _, dependency := range resource.Dependencies {
			if _, exists := byID[dependency]; !exists {
				return errors.Newf("resource %s depends on undeclared resource %s", resource.ID, dependency)
			}
		}
		if err := validateTypedReferences(resource, byID); err != nil {
			return err
		}
	}
	visiting := map[ResourceID]bool{}
	visited := map[ResourceID]bool{}
	var visit func(ResourceID) error
	visit = func(id ResourceID) error {
		if visiting[id] {
			return errors.Newf("resource dependency cycle contains %s", id)
		}
		if visited[id] {
			return nil
		}
		visiting[id] = true
		for _, dependency := range byID[id].Dependencies {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		delete(visiting, id)
		visited[id] = true
		return nil
	}
	for id := range byID {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

func validateTypedReferences(resource Resource, resources map[ResourceID]Resource) error {
	required := map[ResourceID]ResourceKind{}
	switch resource.Kind {
	case ResourceBlob:
		required[resource.Blob.EndpointReference] = ResourceKubernetes
		required[resource.Blob.CredentialReference] = ResourceSecretReference
	case ResourceDatabase:
		required[resource.Database.ConnectionReference] = ResourceSecretReference
		required[resource.Database.MigrationTarget] = ResourceKubernetes
	case ResourceTelemetry:
		required[resource.Telemetry.CollectorService] = ResourceKubernetes
	case ResourceKubernetes:
		if resource.Kubernetes.Selector != "" {
			required[resource.Kubernetes.Selector] = ResourceKubernetes
		}
		if resource.Kubernetes.Network != nil {
			if resource.Kubernetes.Network.Subject != "" {
				required[resource.Kubernetes.Network.Subject] = ResourceKubernetes
			}
			for _, reference := range resource.Kubernetes.Network.AllowedEgress {
				required[reference] = ResourceKubernetes
			}
		}
	}
	declaredDependency := make(map[ResourceID]struct{}, len(resource.Dependencies))
	for _, dependency := range resource.Dependencies {
		declaredDependency[dependency] = struct{}{}
	}
	for reference, expectedKind := range required {
		if reference == "" {
			return errors.Newf("resource %s contains an empty typed reference", resource.ID)
		}
		target, exists := resources[reference]
		if !exists {
			return errors.Newf("resource %s references undeclared resource %s", resource.ID, reference)
		}
		if _, declared := declaredDependency[reference]; !declared {
			return errors.Newf("resource %s reference %s must be an explicit dependency", resource.ID, reference)
		}
		if expectedKind != "" && target.Kind != expectedKind {
			return errors.Newf("resource %s reference %s must have kind %s", resource.ID, reference, expectedKind)
		}
	}
	if resource.Kind == ResourceKubernetes {
		object := resource.Kubernetes
		if object.Selector != "" && !isKubernetesWorkload(resources[object.Selector]) {
			return errors.Newf("resource %s selector %s must name a declared workload", resource.ID, object.Selector)
		}
		if object.Network != nil {
			if object.Network.Subject != "" && !isKubernetesWorkload(resources[object.Network.Subject]) {
				return errors.Newf("resource %s NetworkPolicy subject %s must name a declared workload", resource.ID, object.Network.Subject)
			}
			for _, reference := range object.Network.AllowedEgress {
				if !isKubernetesWorkload(resources[reference]) {
					return errors.Newf("resource %s NetworkPolicy egress target %s must name a declared workload", resource.ID, reference)
				}
			}
		}
		if object.Kind == "RoleBinding" {
			var roleFound, accountFound bool
			for _, dependency := range resource.Dependencies {
				target := resources[dependency]
				if target.Kind != ResourceKubernetes {
					continue
				}
				if target.Kubernetes.Kind == "Role" && target.Kubernetes.Name == object.Role {
					roleFound = true
				}
				if target.Kubernetes.Kind == "ServiceAccount" && target.Kubernetes.Name == object.ServiceAccount {
					accountFound = true
				}
			}
			if !roleFound || !accountFound {
				return errors.Newf("resource %s RoleBinding must depend on its declared Role and ServiceAccount", resource.ID)
			}
		}
	}
	if resource.Kind == ResourceDatabase {
		target := resources[resource.Database.MigrationTarget]
		if !isKubernetesWorkload(target) || target.Kubernetes.Readiness == nil {
			return errors.Newf("resource %s migration target %s must name a declared workload with an explicit readiness probe", resource.ID, resource.Database.MigrationTarget)
		}
	}
	return nil
}

func isKubernetesWorkload(resource Resource) bool {
	return resource.Kind == ResourceKubernetes && resource.Kubernetes != nil && (resource.Kubernetes.Kind == "Deployment" || resource.Kubernetes.Kind == "StatefulSet" || resource.Kubernetes.Kind == "Job")
}

func validateProfileTopology(profiles Profiles) error {
	reference := profileResources(profiles.Local.Resources)
	for _, candidate := range []struct {
		name      Profile
		resources []Resource
	}{{ProfileCI, profiles.CI.Resources}, {ProfileProduction, profiles.Production.Resources}} {
		resources := profileResources(candidate.resources)
		if len(resources) != len(reference) {
			return errors.Newf("validate %s stack profile: resource topology differs from local", candidate.name)
		}
		for id, resource := range reference {
			candidateResource, exists := resources[id]
			if !exists || !sameResourceTopology(resource, candidateResource) {
				return errors.Newf("validate %s stack profile: resource %s topology differs from local", candidate.name, id)
			}
		}
	}
	return nil
}

func profileResources(resources []Resource) map[ResourceID]Resource {
	indexed := make(map[ResourceID]Resource, len(resources))
	for _, resource := range resources {
		indexed[resource.ID] = resource
	}
	return indexed
}

func sameResourceTopology(left, right Resource) bool {
	if left.Kind != right.Kind || left.Owner != right.Owner || left.Scope != right.Scope || left.BackupRestoreOwner != right.BackupRestoreOwner || left.DeleteBehavior != right.DeleteBehavior || left.ExternalController != right.ExternalController {
		return false
	}
	leftDependencies := append([]ResourceID(nil), left.Dependencies...)
	rightDependencies := append([]ResourceID(nil), right.Dependencies...)
	sort.Slice(leftDependencies, func(i, j int) bool { return leftDependencies[i] < leftDependencies[j] })
	sort.Slice(rightDependencies, func(i, j int) bool { return rightDependencies[i] < rightDependencies[j] })
	if !slices.Equal(leftDependencies, rightDependencies) {
		return false
	}
	if left.Kubernetes != nil && right.Kubernetes != nil {
		return left.Kubernetes.APIVersion == right.Kubernetes.APIVersion && left.Kubernetes.Kind == right.Kubernetes.Kind
	}
	return (left.Kubernetes == nil) == (right.Kubernetes == nil)
}

func (spec Spec) profile(profile Profile) (ProfileSpec, bool) {
	switch profile {
	case ProfileLocal:
		return spec.profiles.Local, true
	case ProfileCI:
		return spec.profiles.CI, true
	case ProfileProduction:
		return spec.profiles.Production, true
	default:
		return ProfileSpec{}, false
	}
}

func parseName(value string) (Name, error) {
	if !stackNamePattern.MatchString(value) {
		return Name{}, errors.New("validate stack specification: name must be a lowercase DNS label of at most 40 characters")
	}
	return Name{value: value}, nil
}

func requireEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("parse stack specification: multiple JSON values are not allowed")
		}
		return errors.Wrap(err, "parse stack specification trailing data")
	}
	return nil
}
