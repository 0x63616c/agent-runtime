package stack

import (
	"regexp"
	"strings"

	"github.com/cockroachdb/errors"
)

var resourceIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var sha256Pattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var imageDigestPattern = regexp.MustCompile(`^[^@[:space:]]+@sha256:[a-f0-9]{64}$`)
var environmentNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
var blobBucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
var blobPrefixPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,510}[a-zA-Z0-9]$`)
var databaseNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
var temporalSearchAttributeNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,62}$`)

// ResourceID is a stable stack-local desired-resource identity.
type ResourceID string

// ResourceKind selects exactly one closed typed resource payload.
type ResourceKind string

const (
	// ResourceKubernetes is a namespaced Kubernetes desired object.
	ResourceKubernetes ResourceKind = "kubernetes"
	// ResourceOrchestration is a durable orchestration namespace declaration.
	ResourceOrchestration ResourceKind = "orchestration"
	// ResourceBlob is an object-storage bucket and prefix declaration.
	ResourceBlob ResourceKind = "blob"
	// ResourceDatabase is a database schema and migration declaration.
	ResourceDatabase ResourceKind = "database"
	// ResourceSecretReference is an external secret reference, never secret material.
	ResourceSecretReference ResourceKind = "secret_reference"
	// ResourceTelemetry is a telemetry collector and retention declaration.
	ResourceTelemetry ResourceKind = "telemetry"
)

// Scope identifies the declared authority boundary of a resource.
type Scope string

const (
	// ScopeNamespace is owned inside the profile's explicit namespace.
	ScopeNamespace Scope = "namespace"
	// ScopeCluster is cluster-scoped and requires an explicit operator owner.
	ScopeCluster Scope = "cluster"
	// ScopeProvider is owned through a declared external provider boundary.
	ScopeProvider Scope = "provider"
)

// RetentionPolicy classifies resource retention without an implicit default.
type RetentionPolicy string

const (
	// RetentionEphemeral deletes content with the owned stack.
	RetentionEphemeral RetentionPolicy = "ephemeral"
	// RetentionPersistent retains content for a finite declared number of days.
	RetentionPersistent RetentionPolicy = "persistent"
	// RetentionExternal delegates retention to the named external controller.
	RetentionExternal RetentionPolicy = "external"
)

// DeleteBehavior describes containment-safe removal semantics.
type DeleteBehavior string

const (
	// DeleteOwned permits deletion after identity, labels, and observed UID agree.
	DeleteOwned DeleteBehavior = "delete"
	// DeleteTombstone retains a tombstone after content cleanup.
	DeleteTombstone DeleteBehavior = "tombstone"
	// DeleteRetain leaves the resource under its declared owner.
	DeleteRetain DeleteBehavior = "retain"
)

// Retention is an explicit finite lifecycle declaration.
type Retention struct {
	// Policy selects who retains the resource.
	Policy RetentionPolicy `json:"policy"`
	// Days is zero only for ephemeral or externally governed retention.
	Days int `json:"days"`
}

// Resource is a closed tagged union with common ownership and lifecycle metadata.
type Resource struct {
	// ID is stable within every profile of one Stack.
	ID ResourceID `json:"id"`
	// Kind selects exactly one typed payload below.
	Kind ResourceKind `json:"kind"`
	// Owner names the operator role accountable for the resource.
	Owner string `json:"owner"`
	// Scope declares the resource authority boundary.
	Scope Scope `json:"scope"`
	// Dependencies names resources that must be reconciled first.
	Dependencies []ResourceID `json:"dependencies"`
	// Retention declares finite or externally governed retention.
	Retention Retention `json:"retention"`
	// BackupRestoreOwner names the role responsible for backup and restore, or "none".
	BackupRestoreOwner string `json:"backup_restore_owner"`
	// DeleteBehavior declares safe delete, tombstone, or retain behavior.
	DeleteBehavior DeleteBehavior `json:"delete_behavior"`
	// ExternalController states whether a separately declared controller creates it.
	ExternalController bool `json:"external_controller"`
	// Kubernetes contains a Kubernetes object declaration when Kind is kubernetes.
	Kubernetes *KubernetesResource `json:"kubernetes,omitempty"`
	// Orchestration contains durable orchestration declarations when Kind is orchestration.
	Orchestration *OrchestrationResource `json:"orchestration,omitempty"`
	// Blob contains object-storage declarations when Kind is blob.
	Blob *BlobResource `json:"blob,omitempty"`
	// Database contains schema and migration declarations when Kind is database.
	Database *DatabaseResource `json:"database,omitempty"`
	// SecretReference contains provider-owned secret identity when Kind is secret_reference.
	SecretReference *SecretReferenceResource `json:"secret_reference,omitempty"`
	// Telemetry contains collector and retention declarations when Kind is telemetry.
	Telemetry *TelemetryResource `json:"telemetry,omitempty"`
}

// KubernetesResource is a typed namespaced Kubernetes desired object.
type KubernetesResource struct {
	// APIVersion is the pinned Kubernetes API version.
	APIVersion string `json:"api_version"`
	// Kind is the allowlisted Kubernetes kind.
	Kind string `json:"kind"`
	// Name is the DNS-label-safe object name.
	Name string `json:"name"`
	// Replicas is the finite desired count for a Deployment or StatefulSet.
	// Omission in Stack schema v1 resolves to one replica for compatibility.
	Replicas int `json:"replicas,omitempty"`
	// Image is an immutable digest-qualified reference for workloads.
	Image string `json:"image,omitempty"`
	// ServiceAccount names the least-privilege account used by a workload or binding.
	ServiceAccount string `json:"service_account,omitempty"`
	// Role names the Role selected by a RoleBinding.
	Role string `json:"role,omitempty"`
	// Selector names the workload selected by a Service or Ingress backend.
	Selector ResourceID `json:"selector,omitempty"`
	// Command replaces a workload image entrypoint with reviewed argv.
	Command []string `json:"command,omitempty"`
	// Arguments are reviewed argv values passed to Command or the image entrypoint.
	Arguments []string `json:"arguments,omitempty"`
	// Environment contains reviewed non-secret workload environment values.
	Environment []EnvironmentVariable `json:"environment,omitempty"`
	// SecretEnvironment binds named environment values to declared Secret references.
	// It contains references only; secret material never appears in Stack desired state.
	SecretEnvironment []SecretEnvironmentVariable `json:"secret_environment,omitempty"`
	// VolumeMounts binds a workload to explicitly declared PersistentVolumeClaims.
	VolumeMounts []PersistentVolumeMount `json:"volume_mounts,omitempty"`
	// ConfigMapMounts binds reviewed ConfigMap keys read-only into a workload.
	ConfigMapMounts []ConfigMapMount `json:"config_map_mounts,omitempty"`
	// SecretMounts binds reviewed Secret keys read-only into a workload.
	SecretMounts []SecretMount `json:"secret_mounts,omitempty"`
	// Readiness is the explicit workload health probe when an operator must await service readiness.
	Readiness *ReadinessProbe `json:"readiness,omitempty"`
	// PostMigration defers a one-shot Job until every declared database migration
	// has completed. It is only valid for local/CI bootstrap Jobs.
	PostMigration bool `json:"post_migration,omitempty"`
	// Ports is explicit, including an empty array for workloads with no ports.
	Ports []Port `json:"ports,omitempty"`
	// Compute contains finite requests and limits for workloads.
	Compute *ComputeResources `json:"compute,omitempty"`
	// Storage is explicit, including an empty array when no storage is used.
	Storage []Storage `json:"storage,omitempty"`
	// Network contains the NetworkPolicy rule set.
	Network *NetworkRules `json:"network,omitempty"`
	// Permissions contains allowlisted Role permissions.
	Permissions []Permission `json:"permissions,omitempty"`
	// Data contains reviewed non-secret ConfigMap values.
	Data map[string]string `json:"data,omitempty"`
	// IngressRules are explicit HTTP routes owned by a networking.k8s.io/v1 Ingress.
	IngressRules []IngressRule `json:"ingress_rules,omitempty"`
}

// IngressRule is one bounded route to a declared namespaced Service port.
type IngressRule struct {
	// Host is the reviewed DNS host, or localhost for local development only.
	Host string `json:"host"`
	// Path is the absolute HTTP path.
	Path string `json:"path"`
	// PathType is Exact or Prefix.
	PathType string `json:"path_type"`
	// Service names the Stack Service resource.
	Service ResourceID `json:"service"`
	// ServicePort is the named Service port.
	ServicePort string `json:"service_port"`
}

// EnvironmentVariable is one reviewed non-secret workload environment value.
type EnvironmentVariable struct {
	// Name is the environment key.
	Name string `json:"name"`
	// Value is the bounded non-secret literal value.
	Value string `json:"value"`
}

// SecretEnvironmentVariable binds one process environment variable to one key
// in a declared Secret reference.
type SecretEnvironmentVariable struct {
	// Name is the process environment variable name.
	Name string `json:"name"`
	// Secret names the Stack SecretReference resource.
	Secret ResourceID `json:"secret"`
	// Key is the declared non-secret key name within Secret.
	Key string `json:"key"`
}

// PersistentVolumeMount binds a workload mount path to a declared PVC resource.
type PersistentVolumeMount struct {
	// Claim names the Stack PersistentVolumeClaim resource.
	Claim ResourceID `json:"claim"`
	// Path is the absolute in-container mount path.
	Path string `json:"path"`
	// ReadOnly controls write authority inside the workload.
	ReadOnly bool `json:"read_only"`
}

// ConfigMapMount binds one reviewed ConfigMap key read-only at an absolute path.
type ConfigMapMount struct {
	// ConfigMap names the Stack ConfigMap resource.
	ConfigMap ResourceID `json:"config_map"`
	// Key names the reviewed ConfigMap key to project.
	Key string `json:"key"`
	// Path is the absolute in-container file path for the projected key.
	Path string `json:"path"`
}

// SecretMount binds one reviewed Secret key read-only at an absolute path.
type SecretMount struct {
	Secret ResourceID `json:"secret"`
	Key    string     `json:"key"`
	Path   string     `json:"path"`
}

// ReadinessProbe is a bounded exec health check declared with a workload.
type ReadinessProbe struct {
	// Command is reviewed argv executed in the workload container.
	Command []string `json:"command"`
	// InitialDelaySeconds is the finite wait before the first probe.
	InitialDelaySeconds int `json:"initial_delay_seconds"`
	// PeriodSeconds is the finite interval between probes.
	PeriodSeconds int `json:"period_seconds"`
	// FailureThreshold is the finite number of failures before the pod is not ready.
	FailureThreshold int `json:"failure_threshold"`
}

// Port is one explicitly declared service or container port.
type Port struct {
	// Name is stable within the resource.
	Name string `json:"name"`
	// Number is a valid TCP/UDP port.
	Number int `json:"number"`
	// Protocol is TCP or UDP.
	Protocol string `json:"protocol"`
}

// ComputeResources declares finite requests and limits.
type ComputeResources struct {
	// RequestMilliCPU is the requested CPU in millicores.
	RequestMilliCPU int `json:"request_milli_cpu"`
	// LimitMilliCPU is the finite CPU limit in millicores.
	LimitMilliCPU int `json:"limit_milli_cpu"`
	// RequestMemoryBytes is requested memory in bytes.
	RequestMemoryBytes int64 `json:"request_memory_bytes"`
	// LimitMemoryBytes is the finite memory limit in bytes.
	LimitMemoryBytes int64 `json:"limit_memory_bytes"`
}

// Storage declares one finite named storage allocation.
type Storage struct {
	// Name is stable within the resource.
	Name string `json:"name"`
	// SizeBytes is the finite requested size.
	SizeBytes int64 `json:"size_bytes"`
	// Class is the explicitly selected storage class or "ephemeral".
	Class string `json:"class"`
}

// NetworkRules declares default-deny policy and bounded exceptions.
type NetworkRules struct {
	// DefaultDeny must be true for an admitted profile.
	DefaultDeny bool `json:"default_deny"`
	// Subject selects the declared workload restricted by this policy; empty selects the namespace.
	Subject ResourceID `json:"subject,omitempty"`
	// AllowDNS permits only UDP and TCP port 53 to kube-system CoreDNS pods.
	AllowDNS bool `json:"allow_dns,omitempty"`
	// AllowedEgress names explicit service resource dependencies.
	AllowedEgress []ResourceID `json:"allowed_egress"`
	// AllowedIngress names the declared workloads permitted to initiate traffic to Subject.
	// An explicitly empty list applies an ingress default-deny policy.
	AllowedIngress []ResourceID `json:"allowed_ingress,omitempty"`
}

// Permission is one non-wildcard Kubernetes Role rule.
type Permission struct {
	// APIGroup is explicit; core is represented by an empty string.
	APIGroup string `json:"api_group"`
	// Resource is one non-wildcard Kubernetes resource name.
	Resource string `json:"resource"`
	// Verbs contains non-wildcard allowed actions.
	Verbs []string `json:"verbs"`
}

// OrchestrationResource declares namespace, search attributes, schedules, and retention.
type OrchestrationResource struct {
	// Namespace is the explicit durable orchestration namespace.
	Namespace string `json:"namespace"`
	// TaskQueuePrefix confines durable worker routing to this Stack profile.
	TaskQueuePrefix string `json:"task_queue_prefix"`
	// RetentionDays is finite namespace history retention.
	RetentionDays int `json:"retention_days"`
	// SearchAttributes is the complete typed search-attribute set.
	SearchAttributes []SearchAttribute `json:"search_attributes"`
	// Schedules is the complete declared schedule set.
	Schedules []Schedule `json:"schedules"`
}

// SearchAttribute is one durable indexed field declaration.
type SearchAttribute struct {
	// Name is the stable field name.
	Name string `json:"name"`
	// Type is the provider-supported scalar type.
	Type string `json:"type"`
}

const (
	// SearchAttributeTypeText is a full-text indexed Temporal field.
	SearchAttributeTypeText = "Text"
	// SearchAttributeTypeKeyword is an exact-match indexed Temporal field.
	SearchAttributeTypeKeyword = "Keyword"
	// SearchAttributeTypeInt is an integer indexed Temporal field.
	SearchAttributeTypeInt = "Int"
	// SearchAttributeTypeDouble is a floating-point indexed Temporal field.
	SearchAttributeTypeDouble = "Double"
	// SearchAttributeTypeBool is a boolean indexed Temporal field.
	SearchAttributeTypeBool = "Bool"
	// SearchAttributeTypeDatetime is a timestamp indexed Temporal field.
	SearchAttributeTypeDatetime = "Datetime"
	// SearchAttributeTypeKeywordList is a list-of-keywords indexed Temporal field.
	SearchAttributeTypeKeywordList = "KeywordList"
)

// Schedule is one explicit operator-owned schedule declaration.
type Schedule struct {
	// Name is the stable schedule name.
	Name string `json:"name"`
	// Cron is the reviewed schedule expression.
	Cron string `json:"cron"`
}

// BlobResource declares bucket/prefix ownership and finite retention.
type BlobResource struct {
	// Bucket is the explicit bucket name.
	Bucket string `json:"bucket"`
	// Prefix is the stack-owned key prefix.
	Prefix string `json:"prefix"`
	// EndpointReference names a declared service dependency rather than a storage URL.
	EndpointReference ResourceID `json:"endpoint_reference"`
	// EndpointPortName selects one declared Service port without inferring provider conventions.
	EndpointPortName string `json:"endpoint_port_name"`
	// CredentialReference names a SecretReference resource.
	CredentialReference ResourceID `json:"credential_reference"`
	// ReconcilerReference names the declared operator workload containing the pinned storage client.
	ReconcilerReference ResourceID `json:"reconciler_reference"`
}

// DatabaseResource declares schema ownership and reversible migrations.
type DatabaseResource struct {
	// Database is the explicit database name.
	Database string `json:"database"`
	// Schema is the explicit schema name.
	Schema string `json:"schema"`
	// ConnectionReference names a SecretReference resource.
	ConnectionReference ResourceID `json:"connection_reference"`
	// MigrationTarget names the declared Kubernetes workload that executes reviewed migration artifacts.
	MigrationTarget    ResourceID `json:"migration_target"`
	MigrationAuthority string     `json:"migration_authority,omitempty"`
	// Migrations is an ordered reversible migration set.
	Migrations []Migration `json:"migrations"`
}

// Migration is a reviewed upgrade and rollback artifact pair.
type Migration struct {
	// Version is a positive monotonically increasing schema version.
	Version int `json:"version"`
	// UpgradeDigest is the immutable upgrade artifact SHA-256.
	UpgradeDigest string `json:"upgrade_digest"`
	// RollbackDigest is the immutable rollback artifact SHA-256.
	RollbackDigest string `json:"rollback_digest"`
	// UpgradeArtifact is the reviewed relative path beneath the explicit operator migration root.
	UpgradeArtifact string `json:"upgrade_artifact"`
	// RollbackArtifact is the reviewed relative path beneath the explicit operator migration root.
	RollbackArtifact string `json:"rollback_artifact"`
}

// SecretReferenceResource declares only external secret identity and version.
type SecretReferenceResource struct {
	// Provider is the declared external secret authority.
	Provider string `json:"provider"`
	// Reference is the provider-owned secret name, never its value.
	Reference string `json:"reference"`
	// Version pins the reviewed secret schema/version selector.
	Version string `json:"version"`
	// Keys is the reviewed non-secret key-name inventory. It never contains values.
	Keys []string `json:"keys,omitempty"`
}

// TelemetryResource declares a collector service and finite retention.
type TelemetryResource struct {
	// CollectorService names a declared Kubernetes Service dependency.
	CollectorService ResourceID `json:"collector_service"`
	// PortName selects one declared service port by name.
	PortName string `json:"port_name"`
	// RetentionDays is finite telemetry retention.
	RetentionDays int `json:"retention_days"`
}

func validateResource(resource Resource, namespace string, profile Profile) error {
	if !resourceIDPattern.MatchString(string(resource.ID)) {
		return errors.New("resource id must be a lowercase stack-local identifier")
	}
	if !resourceIDPattern.MatchString(resource.Owner) || !resourceIDPattern.MatchString(resource.BackupRestoreOwner) {
		return errors.Newf("resource %s must declare valid owner and backup_restore_owner", resource.ID)
	}
	if resource.Dependencies == nil {
		return errors.Newf("resource %s must explicitly declare dependencies", resource.ID)
	}
	if resource.Retention.Days < 0 || (resource.Retention.Policy == RetentionPersistent && resource.Retention.Days == 0) {
		return errors.Newf("resource %s has invalid finite retention", resource.ID)
	}
	if resource.Retention.Policy != RetentionEphemeral && resource.Retention.Policy != RetentionPersistent && resource.Retention.Policy != RetentionExternal {
		return errors.Newf("resource %s has invalid retention policy", resource.ID)
	}
	if resource.Scope != ScopeNamespace && resource.Scope != ScopeCluster && resource.Scope != ScopeProvider {
		return errors.Newf("resource %s has invalid scope", resource.ID)
	}
	if resource.DeleteBehavior != DeleteOwned && resource.DeleteBehavior != DeleteTombstone && resource.DeleteBehavior != DeleteRetain {
		return errors.Newf("resource %s has invalid delete behavior", resource.ID)
	}
	payloads := 0
	for _, present := range []bool{resource.Kubernetes != nil, resource.Orchestration != nil, resource.Blob != nil, resource.Database != nil, resource.SecretReference != nil, resource.Telemetry != nil} {
		if present {
			payloads++
		}
	}
	if payloads != 1 {
		return errors.Newf("resource %s must contain exactly one typed payload", resource.ID)
	}
	if !resourcePayloadMatchesKind(resource) {
		return errors.Newf("resource %s payload does not match kind %s", resource.ID, resource.Kind)
	}
	switch resource.Kind {
	case ResourceKubernetes:
		if err := validateKubernetes(resource, namespace, profile); err != nil {
			return err
		}
	case ResourceOrchestration:
		if err := validateOrchestration(resource); err != nil {
			return err
		}
	case ResourceBlob:
		if err := validateBlob(resource); err != nil {
			return err
		}
	case ResourceDatabase:
		if err := validateDatabase(resource); err != nil {
			return err
		}
	case ResourceSecretReference:
		secret := resource.SecretReference
		if secret.Provider == "" || secret.Reference == "" || secret.Version == "" {
			return errors.Newf("resource %s secret reference is incomplete", resource.ID)
		}
		if !resource.ExternalController {
			return errors.Newf("resource %s secret reference must name external controller ownership", resource.ID)
		}
	case ResourceTelemetry:
		telemetry := resource.Telemetry
		if telemetry.CollectorService == "" || telemetry.PortName == "" || telemetry.RetentionDays <= 0 {
			return errors.Newf("resource %s telemetry declaration is incomplete or unbounded", resource.ID)
		}
	}
	return nil
}

func validateKubernetes(resource Resource, namespace string, profile Profile) error {
	object := resource.Kubernetes
	if object.APIVersion == "" || !resourceIDPattern.MatchString(object.Name) {
		return errors.Newf("resource %s Kubernetes api_version and name are required", resource.ID)
	}
	allowed := map[string]bool{
		"Namespace": true, "Deployment": true, "StatefulSet": true, "Job": true,
		"Service": true, "Ingress": true, "ServiceAccount": true, "Role": true,
		"RoleBinding": true, "NetworkPolicy": true, "PersistentVolumeClaim": true,
		"ConfigMap": true, "ResourceQuota": true,
	}
	if !allowed[object.Kind] {
		return errors.Newf("resource %s Kubernetes kind is not allowlisted", resource.ID)
	}
	if object.Kind == "Namespace" {
		if object.Name != namespace || resource.Scope != ScopeCluster {
			return errors.Newf("resource %s Namespace must equal the explicit profile namespace and use cluster scope", resource.ID)
		}
		return nil
	}
	if resource.Scope != ScopeNamespace {
		return errors.Newf("resource %s namespaced Kubernetes object must use namespace scope", resource.ID)
	}
	switch object.Kind {
	case "Deployment", "StatefulSet", "Job":
		if object.Replicas < 0 || object.Replicas > 100 || (object.Replicas > 0 && object.Kind == "Job") {
			return errors.Newf("resource %s replicas must be between 1 and 100 for Deployment or StatefulSet", resource.ID)
		}
		if !imageDigestPattern.MatchString(object.Image) {
			return errors.Newf("resource %s workload image must use an immutable sha256 digest", resource.ID)
		}
		if object.PostMigration && object.Kind != "Job" {
			return errors.Newf("resource %s post_migration is valid only for a Job", resource.ID)
		}
		if object.ServiceAccount == "" || object.Ports == nil || object.Storage == nil {
			return errors.Newf("resource %s workload must explicitly declare service account, ports, and storage", resource.ID)
		}
		if err := validateCompute(resource.ID, object.Compute); err != nil {
			return err
		}
		for _, value := range append(append([]string(nil), object.Command...), object.Arguments...) {
			if value == "" || len(value) > 1024 {
				return errors.Newf("resource %s workload command arguments must be bounded and non-empty", resource.ID)
			}
		}
		for _, variable := range object.Environment {
			if !environmentNamePattern.MatchString(variable.Name) || variable.Value == "" || len(variable.Value) > 4096 || looksLikeSecretEnvironment(variable.Name) {
				return errors.Newf("resource %s workload environment must be bounded and non-secret", resource.ID)
			}
		}
		names := make(map[string]struct{}, len(object.Environment)+len(object.SecretEnvironment))
		for _, variable := range object.Environment {
			names[variable.Name] = struct{}{}
		}
		claims := make(map[ResourceID]struct{}, len(object.VolumeMounts))
		paths := make(map[string]struct{}, len(object.VolumeMounts)+len(object.ConfigMapMounts)+len(object.SecretMounts))
		for _, variable := range object.SecretEnvironment {
			if !environmentNamePattern.MatchString(variable.Name) || variable.Secret == "" || !environmentNamePattern.MatchString(variable.Key) || len(variable.Key) > 253 {
				return errors.Newf("resource %s secret environment must name a declared key and Secret reference", resource.ID)
			}
			if _, duplicate := names[variable.Name]; duplicate {
				return errors.Newf("resource %s environment variable %s is declared more than once", resource.ID, variable.Name)
			}
			names[variable.Name] = struct{}{}
		}
		for _, mount := range object.VolumeMounts {
			if mount.Claim == "" || !strings.HasPrefix(mount.Path, "/") || strings.Contains(mount.Path, "..") || len(mount.Path) > 1024 {
				return errors.Newf("resource %s volume mount must use a declared claim and bounded absolute path", resource.ID)
			}
			if _, duplicate := claims[mount.Claim]; duplicate {
				return errors.Newf("resource %s volume claim %s is mounted more than once", resource.ID, mount.Claim)
			}
			if _, duplicate := paths[mount.Path]; duplicate {
				return errors.Newf("resource %s mount path %s is declared more than once", resource.ID, mount.Path)
			}
			claims[mount.Claim], paths[mount.Path] = struct{}{}, struct{}{}
		}
		configMaps := make(map[ResourceID]struct{}, len(object.ConfigMapMounts))
		for _, mount := range object.ConfigMapMounts {
			if mount.ConfigMap == "" || mount.Key == "" || strings.Contains(mount.Key, "/") || len(mount.Key) > 253 || !strings.HasPrefix(mount.Path, "/") || strings.Contains(mount.Path, "..") || len(mount.Path) > 1024 {
				return errors.Newf("resource %s ConfigMap mount must use a declared key and bounded absolute path", resource.ID)
			}
			if _, duplicate := configMaps[mount.ConfigMap]; duplicate {
				return errors.Newf("resource %s ConfigMap %s is mounted more than once", resource.ID, mount.ConfigMap)
			}
			if _, duplicate := paths[mount.Path]; duplicate {
				return errors.Newf("resource %s mount path %s is declared more than once", resource.ID, mount.Path)
			}
			configMaps[mount.ConfigMap], paths[mount.Path] = struct{}{}, struct{}{}
		}
		for _, mount := range object.SecretMounts {
			if mount.Secret == "" || !environmentNamePattern.MatchString(mount.Key) || !strings.HasPrefix(mount.Path, "/") || strings.Contains(mount.Path, "..") || len(mount.Path) > 1024 {
				return errors.Newf("resource %s Secret mount must use a declared key and bounded absolute path", resource.ID)
			}
			if _, duplicate := paths[mount.Path]; duplicate {
				return errors.Newf("resource %s mount path %s is declared more than once", resource.ID, mount.Path)
			}
			paths[mount.Path] = struct{}{}
		}
		if object.Readiness != nil {
			if object.Readiness.InitialDelaySeconds < 0 || object.Readiness.PeriodSeconds <= 0 || object.Readiness.FailureThreshold <= 0 || len(object.Readiness.Command) == 0 {
				return errors.Newf("resource %s workload readiness probe must be complete and finite", resource.ID)
			}
			for _, value := range object.Readiness.Command {
				if value == "" || len(value) > 1024 {
					return errors.Newf("resource %s workload readiness probe command must be bounded", resource.ID)
				}
			}
		}
	case "Service":
		if len(object.Ports) == 0 || object.Selector == "" {
			return errors.Newf("resource %s service or ingress must declare ports and a workload selector", resource.ID)
		}
	case "Ingress":
		if object.APIVersion != "networking.k8s.io/v1" || len(object.IngressRules) == 0 {
			return errors.Newf("resource %s Ingress must declare networking.k8s.io/v1 rules", resource.ID)
		}
		for _, rule := range object.IngressRules {
			if !validIngressHost(rule.Host, profile) || !strings.HasPrefix(rule.Path, "/") || strings.Contains(rule.Path, "..") || (rule.PathType != "Exact" && rule.PathType != "Prefix") || rule.Service == "" || !resourceIDPattern.MatchString(rule.ServicePort) {
				return errors.Newf("resource %s Ingress contains an invalid explicit route", resource.ID)
			}
		}
	case "NetworkPolicy":
		if object.Network == nil || !object.Network.DefaultDeny || object.Network.AllowedEgress == nil {
			return errors.Newf("resource %s NetworkPolicy must explicitly default deny", resource.ID)
		}
		if (len(object.Network.AllowedEgress) > 0 || object.Network.AllowDNS || object.Network.AllowedIngress != nil) && object.Network.Subject == "" {
			return errors.Newf("resource %s NetworkPolicy egress exceptions must select one declared workload", resource.ID)
		}
	case "Role":
		if len(object.Permissions) == 0 {
			return errors.Newf("resource %s Role must declare bounded permissions", resource.ID)
		}
		for _, permission := range object.Permissions {
			if permission.APIGroup == "*" || permission.Resource == "" || permission.Resource == "*" || len(permission.Verbs) == 0 {
				return errors.Newf("resource %s Role permission must not use wildcards", resource.ID)
			}
			for _, verb := range permission.Verbs {
				if verb == "" || verb == "*" {
					return errors.Newf("resource %s Role permission must not use wildcard verbs", resource.ID)
				}
			}
		}
	case "RoleBinding":
		if object.ServiceAccount == "" || object.Role == "" {
			return errors.Newf("resource %s RoleBinding must declare role and service account", resource.ID)
		}
	case "PersistentVolumeClaim":
		if len(object.Storage) != 1 || object.Storage[0].SizeBytes <= 0 || object.Storage[0].Class == "" {
			return errors.Newf("resource %s persistent storage must be finite and explicitly classed", resource.ID)
		}
	case "ResourceQuota":
		if err := validateCompute(resource.ID, object.Compute); err != nil {
			return err
		}
	}
	if object.Kind == "ConfigMap" {
		if object.Data == nil {
			return errors.Newf("resource %s ConfigMap must explicitly declare data", resource.ID)
		}
		for key, value := range object.Data {
			if key == "" || len(key) > 253 || len(value) > 1<<20 || looksLikeSecretEnvironment(key) {
				return errors.Newf("resource %s ConfigMap data must be bounded and non-secret", resource.ID)
			}
		}
	}
	for _, port := range object.Ports {
		if !resourceIDPattern.MatchString(port.Name) || port.Number < 1 || port.Number > 65535 || (port.Protocol != "TCP" && port.Protocol != "UDP") {
			return errors.Newf("resource %s contains an invalid declared port", resource.ID)
		}
	}
	for _, storage := range object.Storage {
		if !resourceIDPattern.MatchString(storage.Name) || storage.SizeBytes <= 0 || storage.Class == "" {
			return errors.Newf("resource %s contains invalid or unbounded storage", resource.ID)
		}
	}
	return nil
}

func validIngressHost(host string, profile Profile) bool {
	if host == "localhost" {
		return profile == ProfileLocal || profile == ProfileCI
	}
	if len(host) == 0 || len(host) > 253 || strings.Contains(host, "..") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !resourceIDPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func looksLikeSecretEnvironment(name string) bool {
	upper := strings.ToUpper(name)
	return strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "SECRET") || strings.Contains(upper, "TOKEN") || strings.HasSuffix(upper, "_KEY")
}

func validateCompute(id ResourceID, compute *ComputeResources) error {
	if compute == nil || compute.RequestMilliCPU <= 0 || compute.LimitMilliCPU <= 0 || compute.RequestMilliCPU > compute.LimitMilliCPU || compute.RequestMemoryBytes <= 0 || compute.LimitMemoryBytes <= 0 || compute.RequestMemoryBytes > compute.LimitMemoryBytes {
		return errors.Newf("resource %s compute requests and finite limits are required", id)
	}
	return nil
}

func validateOrchestration(resource Resource) error {
	declaration := resource.Orchestration
	if declaration.Namespace == "" || declaration.TaskQueuePrefix == "" || len(declaration.TaskQueuePrefix) > 128 || declaration.RetentionDays <= 0 || declaration.SearchAttributes == nil || declaration.Schedules == nil {
		return errors.Newf("resource %s orchestration declaration is incomplete or unbounded", resource.ID)
	}
	attributes := make(map[string]struct{}, len(declaration.SearchAttributes))
	for _, attribute := range declaration.SearchAttributes {
		if !temporalSearchAttributeNamePattern.MatchString(attribute.Name) || !validSearchAttributeType(attribute.Type) {
			return errors.Newf("resource %s has an invalid Temporal search attribute", resource.ID)
		}
		if _, duplicate := attributes[attribute.Name]; duplicate {
			return errors.Newf("resource %s declares Temporal search attribute %s more than once", resource.ID, attribute.Name)
		}
		attributes[attribute.Name] = struct{}{}
	}
	schedules := make(map[string]struct{}, len(declaration.Schedules))
	for _, schedule := range declaration.Schedules {
		if !resourceIDPattern.MatchString(schedule.Name) || strings.TrimSpace(schedule.Cron) == "" || len(schedule.Cron) > 512 {
			return errors.Newf("resource %s has an invalid schedule declaration", resource.ID)
		}
		if _, duplicate := schedules[schedule.Name]; duplicate {
			return errors.Newf("resource %s declares schedule %s more than once", resource.ID, schedule.Name)
		}
		schedules[schedule.Name] = struct{}{}
	}
	return nil
}

func validSearchAttributeType(value string) bool {
	switch value {
	case SearchAttributeTypeText, SearchAttributeTypeKeyword, SearchAttributeTypeInt, SearchAttributeTypeDouble, SearchAttributeTypeBool, SearchAttributeTypeDatetime, SearchAttributeTypeKeywordList:
		return true
	default:
		return false
	}
}

func validateBlob(resource Resource) error {
	declaration := resource.Blob
	if !blobBucketPattern.MatchString(declaration.Bucket) || !blobPrefixPattern.MatchString(declaration.Prefix) || declaration.EndpointReference == "" || !resourceIDPattern.MatchString(declaration.EndpointPortName) || declaration.CredentialReference == "" || declaration.ReconcilerReference == "" {
		return errors.Newf("resource %s blob declaration is incomplete", resource.ID)
	}
	return nil
}

func validateDatabase(resource Resource) error {
	declaration := resource.Database
	if !databaseNamePattern.MatchString(declaration.Database) || !databaseNamePattern.MatchString(declaration.Schema) || declaration.ConnectionReference == "" || declaration.MigrationTarget == "" || (len(declaration.Migrations) == 0 && !resource.ExternalController) {
		return errors.Newf("resource %s database declaration is incomplete", resource.ID)
	}
	lastVersion := 0
	for _, migration := range declaration.Migrations {
		if migration.Version <= lastVersion || !sha256Pattern.MatchString(migration.UpgradeDigest) || !sha256Pattern.MatchString(migration.RollbackDigest) || !validArtifactPath(migration.UpgradeArtifact) || !validArtifactPath(migration.RollbackArtifact) {
			return errors.Newf("resource %s migrations must be ordered with immutable upgrade and rollback digests", resource.ID)
		}
		lastVersion = migration.Version
	}
	return nil
}

func validArtifactPath(path string) bool {
	return path != "" && len(path) <= 256 && !strings.HasPrefix(path, "/") && !strings.Contains(path, "\\") && !strings.Contains(path, "..")
}

func resourcePayloadMatchesKind(resource Resource) bool {
	switch resource.Kind {
	case ResourceKubernetes:
		return resource.Kubernetes != nil
	case ResourceOrchestration:
		return resource.Orchestration != nil
	case ResourceBlob:
		return resource.Blob != nil
	case ResourceDatabase:
		return resource.Database != nil
	case ResourceSecretReference:
		return resource.SecretReference != nil
	case ResourceTelemetry:
		return resource.Telemetry != nil
	default:
		return false
	}
}
