// Package agentspecbackfillcrd renders and validates the structural AgentSpecBackfill Kubernetes CRD.
package agentspecbackfillcrd

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfillcr"
	"github.com/cockroachdb/errors"
)

const (
	crdAPIVersion = "apiextensions.k8s.io/v1"
	crdKind       = "CustomResourceDefinition"
	maximumCount  = int64(9223372036854775807)
)

type document struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   metadata `json:"metadata"`
	Spec       spec     `json:"spec"`
}

type metadata struct {
	Name string `json:"name"`
}

type spec struct {
	Group                 string    `json:"group"`
	Names                 names     `json:"names"`
	Scope                 string    `json:"scope"`
	Versions              []version `json:"versions"`
	PreserveUnknownFields bool      `json:"preserveUnknownFields"`
}

type names struct {
	Kind     string `json:"kind"`
	ListKind string `json:"listKind"`
	Plural   string `json:"plural"`
	Singular string `json:"singular"`
}

type version struct {
	Name         string       `json:"name"`
	Served       bool         `json:"served"`
	Storage      bool         `json:"storage"`
	Schema       schemaBlock  `json:"schema"`
	Subresources subresources `json:"subresources"`
}

type schemaBlock struct {
	OpenAPIV3Schema schema `json:"openAPIV3Schema"`
}

type subresources struct {
	Status map[string]any `json:"status"`
}

type validation struct {
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

type schema struct {
	Type                  string            `json:"type,omitempty"`
	Format                string            `json:"format,omitempty"`
	Pattern               string            `json:"pattern,omitempty"`
	Minimum               *int64            `json:"minimum,omitempty"`
	Maximum               *int64            `json:"maximum,omitempty"`
	MinLength             *int64            `json:"minLength,omitempty"`
	MaxLength             *int64            `json:"maxLength,omitempty"`
	Enum                  []string          `json:"enum,omitempty"`
	Properties            map[string]schema `json:"properties,omitempty"`
	Required              []string          `json:"required,omitempty"`
	KubernetesValidations []validation      `json:"x-kubernetes-validations,omitempty"`
}

// Render returns the sole canonical AgentSpecBackfill v1 CRD JSON manifest.
func Render() ([]byte, error) {
	encoded, err := json.MarshalIndent(renderedDocument(), "", "  ")
	if err != nil {
		return nil, errors.Wrap(err, "render AgentSpecBackfill CRD")
	}
	return append(encoded, '\n'), nil
}

// Validate refuses any CRD manifest that is not the exact structural AgentSpecBackfill v1 declaration.
func Validate(input []byte) error {
	if len(input) == 0 || len(input) > 32<<10 {
		return errors.New("validate AgentSpecBackfill CRD: bounded input is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var decoded document
	if err := decoder.Decode(&decoded); err != nil {
		return errors.Wrap(err, "validate AgentSpecBackfill CRD")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("validate AgentSpecBackfill CRD: exactly one document is required")
	}
	if !reflect.DeepEqual(decoded, renderedDocument()) {
		return errors.New("validate AgentSpecBackfill CRD: exact generated declaration is required")
	}
	return nil
}

func renderedDocument() document {
	group, versionName, _ := strings.Cut(agentspecbackfillcr.APIVersion, "/")
	return document{APIVersion: crdAPIVersion, Kind: crdKind, Metadata: metadata{Name: "agentspecbackfills." + group}, Spec: spec{
		Group: group,
		Names: names{Kind: agentspecbackfillcr.Kind, ListKind: agentspecbackfillcr.Kind + "List", Plural: "agentspecbackfills", Singular: "agentspecbackfill"},
		Scope: "Namespaced", PreserveUnknownFields: false,
		Versions: []version{{Name: versionName, Served: true, Storage: true, Schema: schemaBlock{OpenAPIV3Schema: rootSchema()}, Subresources: subresources{Status: map[string]any{}}}},
	}}
}

func rootSchema() schema {
	result := object(map[string]schema{"spec": requestSchema(), "status": statusSchema()}, []string{"spec"})
	result.KubernetesValidations = []validation{
		{Rule: "!has(self.status) || (self.status.controllerImageDigest == self.spec.controllerImageDigest && self.status.snapshotFingerprint == self.spec.snapshotFingerprint && self.status.snapshotCount == self.spec.snapshotCount && self.status.manifestDigest == self.spec.manifestDigest && self.status.staticReadinessDigest == self.spec.staticReadinessDigest && self.status.verifiedCount <= self.spec.snapshotCount)", Message: "status must bind the immutable request"},
		{Rule: "!has(self.status) || self.status.phase != 'Refused' || self.status.reason != 'not_admitted' || self.status.completedAt < self.spec.createdAt", Message: "not-admitted refusal must precede request creation"},
		{Rule: "!has(self.status) || self.status.phase != 'Refused' || self.status.reason != 'expired' || self.status.completedAt >= self.spec.requestExpiresAt", Message: "expired refusal must follow request expiry"},
		{Rule: "!has(self.status) || !(self.status.phase == 'Verified' || (self.status.phase == 'Refused' && (self.status.reason == 'snapshot' || self.status.reason == 'content'))) || (self.status.completedAt >= self.spec.createdAt && self.status.completedAt < self.spec.requestExpiresAt)", Message: "verified and integrity refusals must be inside the request interval"},
	}
	return result
}

func requestSchema() schema {
	fields := map[string]schema{
		"stackDigest": digestSchema(), "migrationVersion": fixedInteger(4), "migrationArtifactDigest": digestSchema(),
		"manifestDigest": digestSchema(), "controllerImageDigest": digestSchema(), "snapshotFingerprint": digestSchema(),
		"snapshotCount": positiveInteger(), "fenceNonce": stringSchema("^[A-Za-z0-9_-]{43}$", 43, 43),
		"createdAt": timestampSchema(), "staticReadinessDigest": digestSchema(), "databaseAuthorityDigest": digestSchema(),
		"blobReadCapabilityDigest": digestSchema(), "requestExpiresAt": timestampSchema(),
	}
	result := object(fields, sortedKeys(fields))
	result.KubernetesValidations = []validation{
		{Rule: "self == oldSelf", Message: "AgentSpecBackfill spec is immutable"},
		{Rule: "self.requestExpiresAt > self.createdAt", Message: "request expiry must follow creation"},
		{Rule: "self.requestExpiresAt <= self.createdAt + duration('600s')", Message: "request expiry may be at most ten minutes after creation"},
	}
	return result
}

func statusSchema() schema {
	fields := map[string]schema{
		"phase": stringEnum("Pending", "Verifying", "Verified", "Refused"), "requestUID": stringSchema("^[a-z0-9][a-z0-9-]{0,127}$", 1, 128),
		"observedGeneration": positiveInteger(), "controllerImageDigest": digestSchema(), "requestDigest": digestSchema(),
		"snapshotFingerprint": digestSchema(), "snapshotCount": positiveInteger(), "manifestDigest": digestSchema(),
		"staticReadinessDigest": digestSchema(), "verifiedCount": unsignedInteger(), "reason": stringEnum("snapshot", "content", "expired", "not_admitted"),
		"completedAt": timestampSchema(),
	}
	result := object(fields, []string{"phase", "requestUID", "observedGeneration", "controllerImageDigest", "requestDigest", "snapshotFingerprint", "snapshotCount", "manifestDigest", "staticReadinessDigest", "verifiedCount", "completedAt"})
	result.KubernetesValidations = []validation{
		{Rule: "!(has(oldSelf.phase) && (oldSelf.phase == 'Verified' || oldSelf.phase == 'Refused')) || self == oldSelf", Message: "terminal AgentSpecBackfill status is immutable"},
		{Rule: "self.phase != 'Verified' || (!has(self.reason) && self.verifiedCount == self.snapshotCount)", Message: "verified status has no reason and verifies every snapshot"},
		{Rule: "self.phase != 'Refused' || has(self.reason)", Message: "refused status has a bounded reason"},
		{Rule: "(self.phase != 'Pending' && self.phase != 'Verifying') || (!has(self.reason) && self.completedAt == timestamp('0001-01-01T00:00:00Z'))", Message: "nonterminal status has no refusal reason or completion time"},
	}
	return result
}

func object(properties map[string]schema, required []string) schema {
	return schema{Type: "object", Properties: properties, Required: required}
}

func digestSchema() schema { return stringSchema("^sha256:[0-9a-f]{64}$", 71, 71) }

func timestampSchema() schema {
	return schema{Type: "string", Format: "date-time", MaxLength: pointer(int64(35))}
}

func stringSchema(pattern string, minimum, maximum int64) schema {
	return schema{Type: "string", Pattern: pattern, MinLength: pointer(minimum), MaxLength: pointer(maximum)}
}

func fixedInteger(value int64) schema {
	return schema{Type: "integer", Format: "int32", Minimum: pointer(value), Maximum: pointer(value)}
}

func positiveInteger() schema {
	return schema{Type: "integer", Format: "int64", Minimum: pointer(1), Maximum: pointer(maximumCount)}
}

func unsignedInteger() schema {
	return schema{Type: "integer", Format: "int64", Minimum: pointer(0), Maximum: pointer(maximumCount)}
}

func stringEnum(values ...string) schema {
	return schema{Type: "string", Enum: append([]string(nil), values...)}
}

func pointer(value int64) *int64 { return &value }

func sortedKeys(values map[string]schema) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	for index := 1; index < len(keys); index++ {
		for previous := index; previous > 0 && keys[previous] < keys[previous-1]; previous-- {
			keys[previous], keys[previous-1] = keys[previous-1], keys[previous]
		}
	}
	return keys
}
