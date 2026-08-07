package stack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/cockroachdb/errors"
)

// Rendered is immutable canonical desired state for one reviewed profile.
type Rendered struct {
	digest    string
	data      []byte
	resources []Resource
}

type renderedDocument struct {
	SchemaVersion      int                `json:"schema_version"`
	Stack              string             `json:"stack"`
	Profile            Profile            `json:"profile"`
	Namespace          string             `json:"namespace"`
	Labels             renderedLabels     `json:"labels"`
	Prerequisites      []Prerequisite     `json:"prerequisites"`
	SandboxQuotaPolicy SandboxQuotaPolicy `json:"sandbox_quota_policy"`
	Catalog            []CatalogEntry     `json:"catalog"`
	Resources          []Resource         `json:"resources"`
	Digest             string             `json:"digest,omitempty"`
}

type renderedLabels struct {
	PartOf  string  `json:"app.kubernetes.io/part-of"`
	Stack   string  `json:"agent-runtime.dev/stack"`
	Profile Profile `json:"agent-runtime.dev/profile"`
}

// CatalogEntry is canonical ownership and provenance metadata for one resource.
type CatalogEntry struct {
	// ID is the stable stack-local resource identity.
	ID ResourceID `json:"id"`
	// Kind is the closed typed resource kind.
	Kind ResourceKind `json:"kind"`
	// Owner names the responsible operator role.
	Owner string `json:"owner"`
	// Scope is the declared authority boundary.
	Scope Scope `json:"scope"`
	// Dependencies is canonical dependency order.
	Dependencies []ResourceID `json:"dependencies"`
	// Retention is the explicit lifecycle policy.
	Retention Retention `json:"retention"`
	// BackupRestoreOwner names the responsible recovery role.
	BackupRestoreOwner string `json:"backup_restore_owner"`
	// DeleteBehavior is the containment-safe removal policy.
	DeleteBehavior DeleteBehavior `json:"delete_behavior"`
	// ExternalController states whether another declared controller creates it.
	ExternalController bool `json:"external_controller"`
	// Digest binds this entry to its complete canonical resource declaration.
	Digest string `json:"digest"`
}

// Render produces deterministic desired state without reading environment or infrastructure.
func Render(spec Spec, profile Profile) (Rendered, error) {
	selected, ok := spec.profile(profile)
	if !ok {
		return Rendered{}, errors.New("render stack: profile must be local, ci, or production")
	}
	resources, err := cloneResources(selected.Resources)
	if err != nil {
		return Rendered{}, err
	}
	canonicalizeResources(resources)
	catalog := make([]CatalogEntry, 0, len(resources))
	for _, resource := range resources {
		encoded, marshalErr := json.Marshal(resource)
		if marshalErr != nil {
			return Rendered{}, errors.Wrapf(marshalErr, "render stack resource %s", resource.ID)
		}
		catalog = append(catalog, CatalogEntry{
			ID: resource.ID, Kind: resource.Kind, Owner: resource.Owner, Scope: resource.Scope,
			Dependencies: append(make([]ResourceID, 0, len(resource.Dependencies)), resource.Dependencies...), Retention: resource.Retention,
			BackupRestoreOwner: resource.BackupRestoreOwner, DeleteBehavior: resource.DeleteBehavior,
			ExternalController: resource.ExternalController, Digest: digest(encoded),
		})
	}
	document := renderedDocument{
		SchemaVersion: schemaVersion,
		Stack:         spec.Name.String(),
		Profile:       profile,
		Namespace:     selected.Namespace,
		Labels: renderedLabels{
			PartOf:  "agent-runtime",
			Stack:   spec.Name.String(),
			Profile: profile,
		},
		Prerequisites:      canonicalPrerequisites(selected.Prerequisites),
		SandboxQuotaPolicy: selected.SandboxQuotaPolicy,
		Catalog:            catalog,
		Resources:          resources,
	}
	unsigned, err := json.Marshal(document)
	if err != nil {
		return Rendered{}, errors.Wrap(err, "render stack canonical document")
	}
	document.Digest = digest(unsigned)
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return Rendered{}, errors.Wrap(err, "render stack output")
	}
	encoded = append(encoded, '\n')
	return Rendered{digest: document.Digest, data: encoded, resources: resources}, nil
}

func canonicalPrerequisites(prerequisites []Prerequisite) []Prerequisite {
	canonical := append(make([]Prerequisite, 0, len(prerequisites)), prerequisites...)
	sort.Slice(canonical, func(left, right int) bool { return canonical[left].Name < canonical[right].Name })
	return canonical
}

// Digest returns the canonical SHA-256 desired-state identity.
func (rendered Rendered) Digest() string { return rendered.digest }

// JSON returns a copy of canonical rendered desired state.
func (rendered Rendered) JSON() []byte { return append([]byte(nil), rendered.data...) }

// Resources returns a deep copy in canonical ResourceID order.
func (rendered Rendered) Resources() []Resource {
	resources, err := cloneResources(rendered.resources)
	if err != nil {
		return nil
	}
	return resources
}

func cloneResources(resources []Resource) ([]Resource, error) {
	encoded, err := json.Marshal(resources)
	if err != nil {
		return nil, errors.Wrap(err, "clone rendered stack resources")
	}
	var clone []Resource
	if err := json.Unmarshal(encoded, &clone); err != nil {
		return nil, errors.Wrap(err, "clone rendered stack resources")
	}
	return clone, nil
}

func canonicalizeResources(resources []Resource) {
	for index := range resources {
		resource := &resources[index]
		sort.Slice(resource.Dependencies, func(left, right int) bool { return resource.Dependencies[left] < resource.Dependencies[right] })
		if resource.Kubernetes != nil {
			sort.Slice(resource.Kubernetes.Ports, func(left, right int) bool {
				return resource.Kubernetes.Ports[left].Name < resource.Kubernetes.Ports[right].Name
			})
			sort.Slice(resource.Kubernetes.Storage, func(left, right int) bool {
				return resource.Kubernetes.Storage[left].Name < resource.Kubernetes.Storage[right].Name
			})
			sort.Slice(resource.Kubernetes.Permissions, func(left, right int) bool {
				return resource.Kubernetes.Permissions[left].Resource < resource.Kubernetes.Permissions[right].Resource
			})
			for permissionIndex := range resource.Kubernetes.Permissions {
				sort.Strings(resource.Kubernetes.Permissions[permissionIndex].Verbs)
			}
			if resource.Kubernetes.Network != nil {
				sort.Slice(resource.Kubernetes.Network.AllowedEgress, func(left, right int) bool {
					return resource.Kubernetes.Network.AllowedEgress[left] < resource.Kubernetes.Network.AllowedEgress[right]
				})
			}
		}
		if resource.Orchestration != nil {
			sort.Slice(resource.Orchestration.SearchAttributes, func(left, right int) bool {
				return resource.Orchestration.SearchAttributes[left].Name < resource.Orchestration.SearchAttributes[right].Name
			})
			sort.Slice(resource.Orchestration.Schedules, func(left, right int) bool {
				return resource.Orchestration.Schedules[left].Name < resource.Orchestration.Schedules[right].Name
			})
		}
	}
	sort.Slice(resources, func(left, right int) bool { return resources[left].ID < resources[right].ID })
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
