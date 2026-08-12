// Package roles validates trust-scoped runtime process composition.
package roles

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/cockroachdb/errors"
)

const configurationVersion = 1

var (
	environmentNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	namespacePattern       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Role identifies one independently deployed, trust-scoped runtime process.
type Role string

const (
	// RoleAPI serves the public runtime contract without direct infrastructure credentials.
	RoleAPI Role = "api"
	// RoleOrchestration coordinates state and Temporal work without model or tool credentials.
	RoleOrchestration Role = "orchestration"
	// RoleModel invokes a configured model with only model and conversation authority.
	RoleModel Role = "model"
	// RoleTool executes policy-authorized tools with narrow tool and sandbox authority.
	RoleTool Role = "tool"
	// RoleBlob serves the immutable blob plane with storage authority.
	RoleBlob Role = "blob"
	// RoleCodec provides the inspection-only Temporal UI codec endpoint.
	RoleCodec Role = "codec"
	// RoleSandboxControl coordinates enrolled sandbox hosts.
	RoleSandboxControl Role = "sandbox-control"
	// RoleSandboxHost runs an enrolled sandbox host agent.
	RoleSandboxHost Role = "sandbox-host"
)

// SecretSource resolves an environment name only at the process composition boundary.
// Implementations must never return secret material through diagnostics.
type SecretSource interface {
	// Lookup returns the value and its presence for one environment variable.
	Lookup(context.Context, string) (string, bool, error)
}

// CredentialInventory enumerates the known credential environment names that
// are present at the process boundary. It never returns credential values.
// Prepare requires this seam so a role cannot silently inherit another role's
// mounted credential.
type CredentialInventory interface {
	// KnownCredentialEnvironmentNames returns present names from the reviewed credential inventory.
	KnownCredentialEnvironmentNames(context.Context) ([]string, error)
}

// Config is a validated operator-owned configuration for one runtime role.
// It contains endpoints and environment-key references, never secret values.
type Config struct {
	role          Role
	namespace     string
	listenAddress string
	dependencies  []dependency
}

// Role returns the one trust boundary selected by this Config.
func (config Config) Role() Role { return config.role }

// Namespace returns the explicit Temporal and infrastructure namespace identity.
func (config Config) Namespace() string { return config.namespace }

// ListenAddress returns the explicit health endpoint bind address.
func (config Config) ListenAddress() string { return config.listenAddress }

// Dependency describes one role-visible operator endpoint and optional secret environment reference.
type Dependency struct {
	// Name identifies a reviewed dependency kind.
	Name string `json:"name"`
	// Endpoint is a non-secret target endpoint.
	Endpoint string `json:"endpoint"`
	// SecretEnvironment is an environment key holding an authorization value, never that value itself.
	SecretEnvironment string `json:"secret_environment,omitempty"`
}

type document struct {
	Version       int          `json:"version"`
	Role          Role         `json:"role"`
	Namespace     string       `json:"namespace"`
	ListenAddress string       `json:"listen_address"`
	Dependencies  []Dependency `json:"dependencies"`
}

type dependency struct {
	name              string
	endpoint          string
	secretEnvironment string
}

type requirement struct {
	name              string
	secretEnvironment string
}

var roleRequirements = map[Role][]requirement{
	RoleAPI: {
		{name: "state"}, {name: "telemetry"},
	},
	RoleOrchestration: {
		{name: "state", secretEnvironment: "STATE_DATABASE_DSN"}, {name: "telemetry"}, {name: "temporal", secretEnvironment: "TEMPORAL_AUTH_TOKEN"},
	},
	RoleModel: {
		{name: "conversation", secretEnvironment: "CONVERSATION_ACCESS_TOKEN"}, {name: "egress-proxy"}, {name: "model", secretEnvironment: "MODEL_API_KEY"}, {name: "telemetry"},
	},
	RoleTool: {
		{name: "sandbox-control", secretEnvironment: "SANDBOX_CONTROL_TOKEN"}, {name: "telemetry"}, {name: "tool-broker", secretEnvironment: "TOOL_BROKER_TOKEN"},
	},
	RoleBlob: {
		{name: "storage", secretEnvironment: "BLOB_STORAGE_CREDENTIAL"}, {name: "telemetry"},
	},
	RoleCodec: {
		{name: "blob", secretEnvironment: "CODEC_BLOB_CREDENTIAL"}, {name: "telemetry"},
	},
	RoleSandboxControl: {
		{name: "host-ca", secretEnvironment: "SANDBOX_HOST_CA"}, {name: "sandbox-state", secretEnvironment: "SANDBOX_STATE_DSN"}, {name: "telemetry"},
	},
	RoleSandboxHost: {
		{name: "host-identity", secretEnvironment: "SANDBOX_HOST_IDENTITY"}, {name: "sandbox-control", secretEnvironment: "SANDBOX_CONTROL_TOKEN"}, {name: "telemetry"},
	},
}

// KnownCredentialEnvironmentNames returns the reviewed, complete credential
// key inventory. It contains names only and is safe to use in diagnostics.
func KnownCredentialEnvironmentNames() []string {
	known := make([]string, 0)
	seen := make(map[string]struct{})
	for _, requirements := range roleRequirements {
		for _, requirement := range requirements {
			if requirement.secretEnvironment == "" {
				continue
			}
			if _, exists := seen[requirement.secretEnvironment]; exists {
				continue
			}
			seen[requirement.secretEnvironment] = struct{}{}
			known = append(known, requirement.secretEnvironment)
		}
	}
	sort.Strings(known)
	return known
}

// Parse decodes one strict operator role document. Application configuration
// such as agents, sessions, tools, or policies is deliberately not accepted here.
func Parse(input io.Reader) (Config, error) {
	if input == nil {
		return Config{}, errors.New("parse runtime role configuration: input is required")
	}
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	var decoded document
	if err := decoder.Decode(&decoded); err != nil {
		return Config{}, errors.Wrap(err, "parse runtime role configuration")
	}
	if err := requireEnd(decoder); err != nil {
		return Config{}, err
	}
	if decoded.Version != configurationVersion {
		return Config{}, errors.Newf("validate runtime role configuration: version must be %d", configurationVersion)
	}
	requirements, exists := roleRequirements[decoded.Role]
	if !exists {
		if decoded.Role == "all" {
			return Config{}, errors.New("validate runtime role configuration: role all is not a deployable trust boundary; deploy each declared role separately")
		}
		return Config{}, errors.New("validate runtime role configuration: role is not supported")
	}
	if !namespacePattern.MatchString(decoded.Namespace) || decoded.Namespace == "default" {
		return Config{}, errors.New("validate runtime role configuration: namespace must be an explicit non-default DNS label")
	}
	if err := validateListenAddress(decoded.ListenAddress); err != nil {
		return Config{}, err
	}
	dependencies, err := validateDependencies(decoded.Dependencies, requirements)
	if err != nil {
		return Config{}, err
	}
	return Config{role: decoded.Role, namespace: decoded.Namespace, listenAddress: decoded.ListenAddress, dependencies: dependencies}, nil
}

func requireEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("parse runtime role configuration: only one document is allowed")
		}
		return errors.Wrap(err, "parse runtime role configuration")
	}
	return nil
}

func validateListenAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return errors.New("validate runtime role configuration: listen_address must be an explicit host:port")
	}
	if host != "127.0.0.1" && host != "0.0.0.0" && host != "::1" && host != "::" {
		return errors.New("validate runtime role configuration: listen_address host must be an explicit local bind address")
	}
	return nil
}

func validateDependencies(input []Dependency, requirements []requirement) ([]dependency, error) {
	if input == nil {
		return nil, errors.New("validate runtime role configuration: dependencies must be explicitly declared")
	}
	required := make(map[string]requirement, len(requirements))
	for _, item := range requirements {
		required[item.name] = item
	}
	seen := make(map[string]struct{}, len(input))
	dependencies := make([]dependency, 0, len(input))
	for _, item := range input {
		requirement, allowed := required[item.Name]
		if !allowed {
			return nil, errors.Newf("validate runtime role configuration: role does not allow dependency %s", item.Name)
		}
		if _, duplicate := seen[item.Name]; duplicate {
			return nil, errors.Newf("validate runtime role configuration: dependency %s is declared more than once", item.Name)
		}
		seen[item.Name] = struct{}{}
		if !validEndpoint(item.Endpoint) {
			return nil, errors.Newf("validate runtime role configuration: dependency %s endpoint must be an explicit non-secret URL or host:port", item.Name)
		}
		if requirement.secretEnvironment != "" {
			if item.SecretEnvironment != requirement.secretEnvironment {
				return nil, errors.Newf("validate runtime role configuration: dependency %s requires credential environment %s", item.Name, requirement.secretEnvironment)
			}
		} else if item.SecretEnvironment != "" {
			return nil, errors.Newf("validate runtime role configuration: dependency %s must not receive a secret_environment", item.Name)
		}
		dependencies = append(dependencies, dependency{name: item.Name, endpoint: item.Endpoint, secretEnvironment: item.SecretEnvironment})
	}
	for _, requirement := range requirements {
		if _, found := seen[requirement.name]; !found {
			return nil, errors.Newf("validate runtime role configuration: role requires dependency %s", requirement.name)
		}
	}
	sort.Slice(dependencies, func(left, right int) bool { return dependencies[left].name < dependencies[right].name })
	return dependencies, nil
}

func validEndpoint(endpoint string) bool {
	if endpoint == "" || len(endpoint) > 1024 || strings.ContainsAny(endpoint, "\n\r\t ") {
		return false
	}
	if strings.Contains(endpoint, "://") {
		return strings.HasPrefix(endpoint, "https://") || strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "postgres://")
	}
	_, port, err := net.SplitHostPort(endpoint)
	return err == nil && port != ""
}

// Plan is a secret-safe prepared process composition. Secret values remain private.
type Plan struct {
	role               Role
	namespace          string
	listenAddress      string
	secretEnvironments []string
}

// Role returns the prepared process trust boundary.
func (plan Plan) Role() Role { return plan.role }

// SecretEnvironmentNames returns the reviewed secret environment names, never values.
func (plan Plan) SecretEnvironmentNames() []string { return slices.Clone(plan.secretEnvironments) }

// String returns a safe diagnostic summary that intentionally excludes endpoints and secrets.
func (plan Plan) String() string {
	return fmt.Sprintf("RolePlan{Role:%s Namespace:%s SecretEnvironmentCount:%d}", plan.role, plan.namespace, len(plan.secretEnvironments))
}

// Prepare verifies only the credentials the selected role is entitled to use.
func Prepare(ctx context.Context, config Config, source SecretSource) (Plan, error) {
	if source == nil {
		return Plan{}, errors.New("prepare runtime role: secret source is required")
	}
	inventory, ok := source.(CredentialInventory)
	if !ok {
		return Plan{}, errors.New("prepare runtime role: secret source must enumerate known credentials")
	}
	present, err := inventory.KnownCredentialEnvironmentNames(ctx)
	if err != nil {
		return Plan{}, errors.Wrap(err, "prepare runtime role: enumerate known credentials")
	}
	allowed := make(map[string]struct{}, len(config.dependencies))
	for _, dependency := range config.dependencies {
		if dependency.secretEnvironment != "" {
			allowed[dependency.secretEnvironment] = struct{}{}
		}
	}
	known := make(map[string]struct{}, len(KnownCredentialEnvironmentNames()))
	for _, environment := range KnownCredentialEnvironmentNames() {
		known[environment] = struct{}{}
	}
	seen := make(map[string]struct{}, len(present))
	for _, environment := range present {
		if !environmentNamePattern.MatchString(environment) {
			return Plan{}, errors.New("prepare runtime role: credential inventory returned an invalid environment name")
		}
		if _, duplicate := seen[environment]; duplicate {
			return Plan{}, errors.Newf("prepare runtime role: credential inventory lists %s more than once", environment)
		}
		seen[environment] = struct{}{}
		if _, recognized := known[environment]; !recognized {
			return Plan{}, errors.Newf("prepare runtime role: credential inventory lists unknown credential %s", environment)
		}
		if _, entitled := allowed[environment]; !entitled {
			return Plan{}, errors.Newf("prepare runtime role: known credential %s is not entitled to role %s", environment, config.role)
		}
	}
	secretEnvironments := make([]string, 0, len(config.dependencies))
	for _, dependency := range config.dependencies {
		if dependency.secretEnvironment == "" {
			continue
		}
		value, found, err := source.Lookup(ctx, dependency.secretEnvironment)
		if err != nil {
			return Plan{}, errors.Wrapf(err, "prepare runtime role: read credential %s", dependency.secretEnvironment)
		}
		if !found || value == "" {
			return Plan{}, errors.Newf("prepare runtime role: required credential %s is unavailable", dependency.secretEnvironment)
		}
		secretEnvironments = append(secretEnvironments, dependency.secretEnvironment)
	}
	sort.Strings(secretEnvironments)
	return Plan{role: config.role, namespace: config.namespace, listenAddress: config.listenAddress, secretEnvironments: secretEnvironments}, nil
}
