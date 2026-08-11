// Command dev owns the explicit local-only Stack materialization lifecycle.
// It never mutates the user's kubeconfig or emits secret material into a
// checked-in Stack document.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/0x63616c/agent-runtime/internal/roles"
	"github.com/0x63616c/agent-runtime/internal/stack"
)

const quotaPolicy = `{"defaults":{"milli_cpu":500,"memory_bytes":536870912,"root_disk_bytes":4294967296,"tmpfs_bytes":268435456,"pids":128,"process_count":64,"open_files":1024,"inodes":100000,"files":50000,"lifetime_seconds":3600,"produced_output_bytes":67108864,"retained_output_bytes":16777216,"transfer_bytes":1073741824,"network_connections":64,"volume_bytes":10737418240,"snapshot_bytes":10737418240},"maximums":{"milli_cpu":4000,"memory_bytes":4294967296,"root_disk_bytes":34359738368,"tmpfs_bytes":2147483648,"pids":1024,"process_count":512,"open_files":8192,"inodes":1000000,"files":500000,"lifetime_seconds":86400,"produced_output_bytes":1073741824,"retained_output_bytes":268435456,"transfer_bytes":10737418240,"network_connections":1024,"volume_bytes":107374182400,"snapshot_bytes":107374182400}}`

type localFixtureScenario = roles.LocalDemoFixtureScenario

const (
	localFixtureScenarioWorkspaceApprovalReset  = roles.LocalDemoFixtureScenarioWorkspaceApprovalReset
	localFixtureScenarioWorkspaceApprovalExpiry = roles.LocalDemoFixtureScenarioWorkspaceApprovalExpiry
)

var (
	stackPattern         = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$`)
	operatorActorPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9@._-]{0,127}$`)
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, output io.Writer) error {
	if len(arguments) == 0 {
		return fmt.Errorf("run local development command: render, secrets, preflight, up, reconcile, status, api, reset, or down is required")
	}
	switch arguments[0] {
	case "render":
		stack, profile, scenario, destination, err := parseRenderArguments(arguments[1:])
		if err != nil {
			return err
		}
		document, err := renderStack(stack, profile, scenario)
		if err != nil {
			return err
		}
		if destination != "" {
			if err := writePrivate(destination, document); err != nil {
				return err
			}
		}
		_, err = output.Write(document)
		return err
	case "secrets":
		stack, profile, root, err := parseSecretsArguments(arguments[1:])
		if err != nil {
			return err
		}
		manifest, err := materializeSecretsForProfile(stack, profile, root, rand.Reader)
		if err != nil {
			return err
		}
		_, err = output.Write(manifest)
		return err
	case "preflight":
		_, root, kubeconfig, err := parsePreflightArguments(arguments[1:])
		if err != nil {
			return err
		}
		return preflight(ctx, root, kubeconfig, output)
	case "up":
		stack, root, kubeconfig, actor, scenario, err := parseUpArguments(arguments[1:])
		if err != nil {
			return err
		}
		return up(ctx, stack, root, kubeconfig, actor, scenario, output)
	case "reconcile":
		stack, root, err := parseStackAndRoot("reconcile", arguments[1:])
		if err != nil {
			return err
		}
		return reconcile(ctx, stack, root, output)
	case "status":
		stack, root, err := parseStackAndRoot("status", arguments[1:])
		if err != nil {
			return err
		}
		return status(stack, root, output)
	case "reset":
		stack, root, err := parseStackAndRoot("reset", arguments[1:])
		if err != nil {
			return err
		}
		return reset(ctx, stack, root, output)
	case "api":
		stack, root, err := parseStackAndRoot("api", arguments[1:])
		if err != nil {
			return err
		}
		return api(ctx, stack, root, output)
	case "down":
		stack, root, err := parseStackAndRoot("down", arguments[1:])
		if err != nil {
			return err
		}
		return down(ctx, stack, root, output)
	default:
		return fmt.Errorf("run local development command: unknown command %q", arguments[0])
	}
}

func parseSecretsArguments(arguments []string) (string, string, string, error) {
	flags := flag.NewFlagSet("secrets", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stackName := flags.String("stack", "", "sole validated Stack identity")
	profile := flags.String("profile", "local", "local or ci")
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return "", "", "", fmt.Errorf("parse local development secrets arguments: --stack is required")
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve local development root: %w", err)
	}
	if *stackName == "" {
		*stackName, err = derivedStack(absRoot)
		if err != nil {
			return "", "", "", err
		}
	}
	if err := validateStack(*stackName); err != nil {
		return "", "", "", err
	}
	if *profile != "local" && *profile != "ci" {
		return "", "", "", fmt.Errorf("parse local development secrets arguments: --profile must be local or ci")
	}
	return *stackName, *profile, absRoot, nil
}

func parseRenderArguments(arguments []string) (string, string, localFixtureScenario, string, error) {
	flags := flag.NewFlagSet("render", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stack := flags.String("stack", "", "sole validated Stack identity")
	profile := flags.String("profile", "local", "local, ci, or production")
	fixtureScenario := flags.String("fixture-scenario", string(localFixtureScenarioWorkspaceApprovalReset), "declared local fixture scenario")
	destination := flags.String("output", "", "private local output path")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return "", "", localFixtureScenarioWorkspaceApprovalReset, "", fmt.Errorf("parse local Stack render arguments: --stack is required")
	}
	if err := validateStack(*stack); err != nil {
		return "", "", localFixtureScenarioWorkspaceApprovalReset, "", err
	}
	if *profile != "local" && *profile != "ci" && *profile != "production" {
		return "", "", localFixtureScenarioWorkspaceApprovalReset, "", fmt.Errorf("parse local Stack render arguments: --profile must be local, ci, or production")
	}
	scenario, err := parseLocalFixtureScenario(*fixtureScenario)
	if err != nil {
		return "", "", localFixtureScenarioWorkspaceApprovalReset, "", err
	}
	fixtureScenarioProvided := false
	flags.Visit(func(item *flag.Flag) {
		if item.Name == "fixture-scenario" {
			fixtureScenarioProvided = true
		}
	})
	if *profile != "local" && fixtureScenarioProvided {
		return "", "", localFixtureScenarioWorkspaceApprovalReset, "", fmt.Errorf("parse local Stack render arguments: --fixture-scenario is local-only")
	}
	return *stack, *profile, scenario, *destination, nil
}

func parseStackAndRoot(command string, arguments []string) (string, string, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stack := flags.String("stack", "", "sole validated Stack identity")
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return "", "", fmt.Errorf("parse local development %s arguments: --stack is required", command)
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		return "", "", fmt.Errorf("resolve local development root: %w", err)
	}
	if *stack == "" {
		*stack, err = derivedStack(absRoot)
		if err != nil {
			return "", "", err
		}
	}
	if err := validateStack(*stack); err != nil {
		return "", "", err
	}
	return *stack, absRoot, nil
}

func parseUpArguments(arguments []string) (string, string, string, string, localFixtureScenario, error) {
	flags := flag.NewFlagSet("up", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stackName := flags.String("stack", "", "sole validated Stack identity")
	root := flags.String("root", ".", "repository root")
	kubeconfig := flags.String("kubeconfig", "", "absolute kubeconfig used only with the explicit orbstack context")
	actor := flags.String("actor", "", "bounded audited local operator identity")
	fixtureScenario := flags.String("fixture-scenario", string(localFixtureScenarioWorkspaceApprovalReset), "declared local fixture scenario")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return "", "", "", "", localFixtureScenarioWorkspaceApprovalReset, fmt.Errorf("parse local development up arguments: --stack, absolute --kubeconfig, and --actor are required")
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		return "", "", "", "", localFixtureScenarioWorkspaceApprovalReset, fmt.Errorf("resolve local development root: %w", err)
	}
	if *stackName == "" {
		*stackName, err = derivedStack(absRoot)
		if err != nil {
			return "", "", "", "", localFixtureScenarioWorkspaceApprovalReset, err
		}
	}
	if err := validateStack(*stackName); err != nil {
		return "", "", "", "", localFixtureScenarioWorkspaceApprovalReset, err
	}
	if !filepath.IsAbs(*kubeconfig) {
		return "", "", "", "", localFixtureScenarioWorkspaceApprovalReset, fmt.Errorf("parse local development up arguments: absolute --kubeconfig is required")
	}
	if !operatorActorPattern.MatchString(*actor) {
		return "", "", "", "", localFixtureScenarioWorkspaceApprovalReset, fmt.Errorf("parse local development up arguments: --actor must be a bounded operator identity")
	}
	scenario, err := parseLocalFixtureScenario(*fixtureScenario)
	if err != nil {
		return "", "", "", "", localFixtureScenarioWorkspaceApprovalReset, err
	}
	return *stackName, absRoot, *kubeconfig, *actor, scenario, nil
}

func parseLocalFixtureScenario(value string) (localFixtureScenario, error) {
	scenario, err := roles.ParseLocalDemoFixtureScenario(value)
	if err != nil {
		return "", fmt.Errorf("parse local fixture scenario: --fixture-scenario must name one declared local scenario")
	}
	return scenario, nil
}

func parsePreflightArguments(arguments []string) (string, string, string, error) {
	flags := flag.NewFlagSet("preflight", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stackName := flags.String("stack", "", "sole validated Stack identity")
	root := flags.String("root", ".", "repository root")
	kubeconfig := flags.String("kubeconfig", "", "absolute kubeconfig used only with the explicit orbstack context")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return "", "", "", fmt.Errorf("parse local development preflight arguments: --stack and absolute --kubeconfig are required")
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve local development root: %w", err)
	}
	if *stackName == "" {
		*stackName, err = derivedStack(absRoot)
		if err != nil {
			return "", "", "", err
		}
	}
	if err := validateStack(*stackName); err != nil {
		return "", "", "", err
	}
	if !filepath.IsAbs(*kubeconfig) {
		return "", "", "", fmt.Errorf("parse local development preflight arguments: absolute --kubeconfig is required")
	}
	return *stackName, absRoot, *kubeconfig, nil
}

func validateStack(stack string) error {
	if !stackPattern.MatchString(stack) {
		return fmt.Errorf("validate local Stack identity: --stack must be a lowercase DNS label up to 40 characters")
	}
	return nil
}

func renderStack(stack, profile string, scenario localFixtureScenario) ([]byte, error) {
	if err := validateStack(stack); err != nil {
		return nil, err
	}
	if profile != "local" && profile != "ci" && profile != "production" {
		return nil, fmt.Errorf("render local Stack document: profile must be local, ci, or production")
	}
	if profile != "local" && scenario != localFixtureScenarioWorkspaceApprovalReset {
		return nil, fmt.Errorf("render local Stack document: fixture scenario is local-only")
	}
	profiles := make(map[string]any, 3)
	for _, candidate := range []string{"local", "ci", "production"} {
		resources, err := reviewedProfileResources(stack, candidate)
		if err != nil {
			return nil, err
		}
		if candidate == "local" {
			if err := attachLocalFixtureScenario(resources, scenario); err != nil {
				return nil, err
			}
		}
		namespace := profileNamespace(stack, candidate)
		reviewedNamespace := profileNamespace("agent-runtime", candidate)
		resolved := make([]json.RawMessage, len(resources))
		for index, resource := range resources {
			value := strings.ReplaceAll(string(resource), reviewedNamespace, namespace)
			resolved[index] = json.RawMessage(value)
		}
		prerequisites := []any{}
		if candidate == "local" {
			prerequisites = []any{
				map[string]any{"name": "tilt", "kind": "executable", "expected": "present", "minimum_bytes": 0, "repair": "Install Tilt; local development does not install it automatically."},
				map[string]any{"name": "kubectl", "kind": "executable", "expected": "present", "minimum_bytes": 0, "repair": "Install kubectl; do not change your Kubernetes context."},
				map[string]any{"name": "kubernetes-context", "kind": "kubernetes_context", "expected": "orbstack", "minimum_bytes": 0, "repair": "Start OrbStack Kubernetes; the local command never changes current-context."},
			}
		}
		profiles[candidate] = map[string]any{"namespace": namespace, "prerequisites": prerequisites, "sandbox_quota_policy": json.RawMessage(quotaPolicy), "resources": resolved}
	}
	document := map[string]any{"version": 1, "name": stack, "profiles": profiles}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode local Stack document: %w", err)
	}
	return append(encoded, '\n'), nil
}

func reviewedProfileResources(stackName, profile string) ([]json.RawMessage, error) {
	directory, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("locate reviewed local Stack profile: %w", err)
	}
	for {
		path := filepath.Join(directory, "deploy", "production", "stack.json")
		if data, readErr := os.ReadFile(path); readErr == nil {
			reviewed, parseErr := stack.Parse(bytes.NewReader(data))
			if parseErr != nil {
				return nil, fmt.Errorf("parse reviewed local Stack profile: %w", parseErr)
			}
			_ = reviewed
			var document struct {
				Profiles map[string]struct {
					Resources []json.RawMessage `json:"resources"`
				} `json:"profiles"`
			}
			if err := json.Unmarshal(data, &document); err != nil {
				return nil, fmt.Errorf("decode reviewed Stack profile: %w", err)
			}
			reviewedProfile, exists := document.Profiles[profile]
			if !exists {
				return nil, fmt.Errorf("decode reviewed Stack profile: %s is missing", profile)
			}
			resources := append([]json.RawMessage(nil), reviewedProfile.Resources...)
			for index, resource := range resources {
				var object map[string]json.RawMessage
				if err := json.Unmarshal(resource, &object); err != nil {
					return nil, fmt.Errorf("decode reviewed Stack resource: %w", err)
				}
				var id stack.ResourceID
				if err := json.Unmarshal(object["id"], &id); err != nil {
					return nil, fmt.Errorf("read reviewed Stack resource identity: %w", err)
				}
				if profile != "local" || !tiltBuiltResource(id) {
					continue
				}
				var kubernetes map[string]json.RawMessage
				if err := json.Unmarshal(object["kubernetes"], &kubernetes); err != nil {
					return nil, fmt.Errorf("decode reviewed Stack workload: %w", err)
				}
				image, err := json.Marshal(devImage(stackName, id))
				if err != nil {
					return nil, fmt.Errorf("encode local Tilt image reference: %w", err)
				}
				kubernetes["image"] = image
				encodedKubernetes, err := json.Marshal(kubernetes)
				if err != nil {
					return nil, fmt.Errorf("encode reviewed Stack workload: %w", err)
				}
				object["kubernetes"] = encodedKubernetes
				encodedResource, err := json.Marshal(object)
				if err != nil {
					return nil, fmt.Errorf("encode reviewed Stack resource: %w", err)
				}
				resources[index] = encodedResource
			}
			return resources, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return nil, fmt.Errorf("locate reviewed local Stack profile: deploy/production/stack.json was not found")
		}
		directory = parent
	}
}

func attachLocalFixtureScenario(resources []json.RawMessage, scenario localFixtureScenario) error {
	if scenario != localFixtureScenarioWorkspaceApprovalReset && scenario != localFixtureScenarioWorkspaceApprovalExpiry {
		return fmt.Errorf("attach local fixture scenario: scenario is not declared")
	}
	attached := 0
	for index, resource := range resources {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(resource, &object); err != nil {
			return fmt.Errorf("attach local fixture scenario: decode resource: %w", err)
		}
		var id stack.ResourceID
		if err := json.Unmarshal(object["id"], &id); err != nil {
			return fmt.Errorf("attach local fixture scenario: read resource identity: %w", err)
		}
		if id != "model" && id != "tool" {
			continue
		}
		var kubernetes map[string]json.RawMessage
		if err := json.Unmarshal(object["kubernetes"], &kubernetes); err != nil {
			return fmt.Errorf("attach local fixture scenario: decode %s workload: %w", id, err)
		}
		var environments []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		if err := json.Unmarshal(kubernetes["environment"], &environments); err != nil {
			return fmt.Errorf("attach local fixture scenario: decode %s environment: %w", id, err)
		}
		found := false
		for environmentIndex := range environments {
			environment := &environments[environmentIndex]
			if environment.Name != "RUNTIME_ROLE_CONFIG" {
				continue
			}
			encoded, err := roles.WithLocalDemoFixtureScenario(environment.Value, scenario)
			if err != nil {
				return fmt.Errorf("attach local fixture scenario: set %s role configuration: %w", id, err)
			}
			environment.Value = encoded
			found = true
			attached++
		}
		if !found {
			return fmt.Errorf("attach local fixture scenario: %s has no runtime role configuration", id)
		}
		encodedEnvironment, err := json.Marshal(environments)
		if err != nil {
			return fmt.Errorf("attach local fixture scenario: encode %s environment: %w", id, err)
		}
		kubernetes["environment"] = encodedEnvironment
		encodedKubernetes, err := json.Marshal(kubernetes)
		if err != nil {
			return fmt.Errorf("attach local fixture scenario: encode %s workload: %w", id, err)
		}
		object["kubernetes"] = encodedKubernetes
		encodedResource, err := json.Marshal(object)
		if err != nil {
			return fmt.Errorf("attach local fixture scenario: encode %s resource: %w", id, err)
		}
		resources[index] = encodedResource
	}
	if attached != 2 {
		return fmt.Errorf("attach local fixture scenario: exactly model and tool must be attached")
	}
	return nil
}

func tiltBuiltResource(id stack.ResourceID) bool {
	switch id {
	case "api", "runtime-api", "orchestration", "model", "tool", "blob-role", "codec", "sandbox-control", "sandbox-host", "egress-proxy":
		return true
	default:
		return false
	}
}

func devImage(stack string, id stack.ResourceID) string {
	return "agent-runtime-dev/" + stack + "/" + string(id) + "@sha256:" + strings.Repeat("d", 64)
}

func profileNamespace(stack, profile string) string {
	switch profile {
	case "local":
		return "ar-" + stack
	case "ci":
		return "ar-ci-" + stack
	default:
		return stack
	}
}

func derivedStack(root string) (string, error) {
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("derive local Stack identity: canonicalize worktree: %w", err)
	}
	sum := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("dev-%x", sum[:4]), nil
}

type localSecrets struct {
	Stack  string                       `json:"stack"`
	Values map[string]map[string]string `json:"values"`
}

type localState struct {
	Stack               string `json:"stack"`
	Namespace           string `json:"namespace"`
	DashboardPort       int    `json:"dashboard_port"`
	WorktreeFingerprint string `json:"worktree_fingerprint"`
	Kubeconfig          string `json:"kubeconfig"`
	OperatorActor       string `json:"operator_actor"`
	FixtureScenario     string `json:"fixture_scenario,omitempty"`
}

func materializeSecrets(stack, root string, reader io.Reader) ([]byte, error) {
	return materializeSecretsForProfile(stack, "local", root, reader)
}

func materializeSecretsForProfile(stackName, profile, root string, reader io.Reader) ([]byte, error) {
	references, err := localSecretReferences(stackName, profile)
	if err != nil {
		return nil, err
	}
	path := secretStatePath(root, stackName, profile)
	state := localSecrets{}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &state); err != nil || state.Stack != stackName || !matchesSecretReferences(state.Values, references) {
			return nil, fmt.Errorf("read local development secret state: refuse malformed or foreign Stack state")
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read local development secret state: %w", err)
	}
	if state.Values == nil {
		state = localSecrets{Stack: stackName, Values: make(map[string]map[string]string, len(references))}
		for _, reference := range references {
			values := make(map[string]string, len(reference.keys))
			for _, key := range reference.keys {
				values[key] = randomValue(reader)
			}
			state.Values[reference.name] = values
		}
		stateReference, stateFound := secretReferenceByID(references, "state-db-secret")
		sandboxReference, sandboxFound := secretReferenceByID(references, "sandbox-state-secret")
		blobReference, blobFound := secretReferenceByID(references, "blob-storage-secret")
		orchestrationReference, orchestrationFound := secretReferenceByID(references, "orchestration-payload-blob-secret")
		runtimeAPIReference, runtimeAPIFound := secretReferenceByID(references, "runtime-api-secret")
		modelReference, modelFound := secretReferenceByID(references, "model-secret")
		toolReference, toolFound := secretReferenceByID(references, "tool-broker-secret")
		if !stateFound || !sandboxFound || !blobFound || !orchestrationFound || !runtimeAPIFound || !modelFound || !toolFound {
			return nil, fmt.Errorf("materialize local development secrets: reviewed Stack is missing required state credential references")
		}
		statePassword := state.Values[stateReference.name]["POSTGRES_PASSWORD"]
		stateDSN := "postgres://postgres:" + statePassword + "@state:5432/agent_runtime?sslmode=disable"
		state.Values[stateReference.name]["STATE_DATABASE_DSN"] = stateDSN
		state.Values[sandboxReference.name]["SANDBOX_STATE_DSN"] = stateDSN
		state.Values[orchestrationReference.name]["ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY"] = state.Values[blobReference.name]["MINIO_ROOT_USER"]
		state.Values[orchestrationReference.name]["ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY"] = state.Values[blobReference.name]["MINIO_ROOT_PASSWORD"]
		state.Values[runtimeAPIReference.name]["AR_RUNTIME_MINIO_ACCESS_KEY"] = state.Values[blobReference.name]["MINIO_ROOT_USER"]
		state.Values[runtimeAPIReference.name]["AR_RUNTIME_MINIO_SECRET_KEY"] = state.Values[blobReference.name]["MINIO_ROOT_PASSWORD"]
		if profile == "local" {
			for _, reference := range []localSecretReference{modelReference, toolReference} {
				state.Values[reference.name]["LOCAL_DEMO_STATE_DSN"] = state.Values[stateReference.name]["STATE_DATABASE_DSN"]
				state.Values[reference.name]["LOCAL_DEMO_CONTENT_ACCESS_KEY"] = state.Values[blobReference.name]["MINIO_ROOT_USER"]
				state.Values[reference.name]["LOCAL_DEMO_CONTENT_SECRET_KEY"] = state.Values[blobReference.name]["MINIO_ROOT_PASSWORD"]
			}
		}
		encoded, marshalErr := json.Marshal(state)
		if marshalErr != nil {
			return nil, fmt.Errorf("encode local development secret state: %w", marshalErr)
		}
		if err := writePrivate(path, append(encoded, '\n')); err != nil {
			return nil, err
		}
	}
	stateReference, stateFound := secretReferenceByID(references, "state-db-secret")
	sandboxReference, sandboxFound := secretReferenceByID(references, "sandbox-state-secret")
	blobReference, blobFound := secretReferenceByID(references, "blob-storage-secret")
	orchestrationReference, orchestrationFound := secretReferenceByID(references, "orchestration-payload-blob-secret")
	runtimeAPIReference, runtimeAPIFound := secretReferenceByID(references, "runtime-api-secret")
	modelReference, modelFound := secretReferenceByID(references, "model-secret")
	toolReference, toolFound := secretReferenceByID(references, "tool-broker-secret")
	if !stateFound || !sandboxFound || !blobFound || !orchestrationFound || !runtimeAPIFound || !modelFound || !toolFound {
		return nil, fmt.Errorf("materialize local development secrets: reviewed Stack is missing required credential references")
	}
	statePassword := state.Values[stateReference.name]["POSTGRES_PASSWORD"]
	state.Values[stateReference.name]["STATE_DATABASE_DSN"] = "postgres://postgres:" + statePassword + "@state:5432/agent_runtime?sslmode=disable"
	state.Values[sandboxReference.name]["SANDBOX_STATE_DSN"] = state.Values[stateReference.name]["STATE_DATABASE_DSN"]
	state.Values[orchestrationReference.name]["ORCHESTRATION_PAYLOAD_BLOB_ACCESS_KEY"] = state.Values[blobReference.name]["MINIO_ROOT_USER"]
	state.Values[orchestrationReference.name]["ORCHESTRATION_PAYLOAD_BLOB_SECRET_KEY"] = state.Values[blobReference.name]["MINIO_ROOT_PASSWORD"]
	state.Values[runtimeAPIReference.name]["AR_RUNTIME_MINIO_ACCESS_KEY"] = state.Values[blobReference.name]["MINIO_ROOT_USER"]
	state.Values[runtimeAPIReference.name]["AR_RUNTIME_MINIO_SECRET_KEY"] = state.Values[blobReference.name]["MINIO_ROOT_PASSWORD"]
	if profile == "local" {
		for _, reference := range []localSecretReference{modelReference, toolReference} {
			state.Values[reference.name]["LOCAL_DEMO_STATE_DSN"] = state.Values[stateReference.name]["STATE_DATABASE_DSN"]
			state.Values[reference.name]["LOCAL_DEMO_CONTENT_ACCESS_KEY"] = state.Values[blobReference.name]["MINIO_ROOT_USER"]
			state.Values[reference.name]["LOCAL_DEMO_CONTENT_SECRET_KEY"] = state.Values[blobReference.name]["MINIO_ROOT_PASSWORD"]
		}
	}
	metadata, err := localSecretControllerMetadata(stackName, profile, root)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(references))
	for _, reference := range references {
		items = append(items, map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": reference.name, "labels": metadata.labels, "annotations": metadata.annotations}, "type": "Opaque", "stringData": state.Values[reference.name]})
	}
	encoded, err := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "List", "items": items})
	if err != nil {
		return nil, fmt.Errorf("encode local development Secret manifests: %w", err)
	}
	return encoded, nil
}

type localSecretMetadata struct {
	labels      map[string]string
	annotations map[string]string
}

func localSecretControllerMetadata(stackName, profile, root string) (localSecretMetadata, error) {
	labels := map[string]string{"app.kubernetes.io/part-of": "agent-runtime", "agent-runtime.dev/stack": stackName, "agent-runtime.dev/profile": profile}
	if profile != "local" {
		return localSecretMetadata{labels: labels}, nil
	}
	capabilityPath := bootstrapCapabilityPath(root, stackName)
	if _, err := os.Stat(capabilityPath); os.IsNotExist(err) {
		return localSecretMetadata{labels: labels}, nil
	} else if err != nil {
		return localSecretMetadata{}, fmt.Errorf("read local Stack bootstrap capability for generated Secrets: %w", err)
	}
	authority, err := stack.ReadBootstrapAuthority(capabilityPath)
	if err != nil {
		return localSecretMetadata{}, fmt.Errorf("read local Stack bootstrap capability for generated Secrets: %w", err)
	}
	if authority.Stack != stackName || authority.Profile != stack.ProfileLocal || authority.Namespace != profileNamespace(stackName, profile) || authority.NamespaceUID == "" || authority.RenderDigest == "" {
		return localSecretMetadata{}, fmt.Errorf("read local Stack bootstrap capability for generated Secrets: capability does not match the rendered local Stack")
	}
	labels["agent-runtime.dev/external-controller"] = "local-generated"
	return localSecretMetadata{labels: labels, annotations: map[string]string{"agent-runtime.dev/bootstrap-uid": string(authority.NamespaceUID), "agent-runtime.dev/render-digest": authority.RenderDigest}}, nil
}

func secretStatePath(root, stackName, profile string) string {
	if profile == "local" {
		return filepath.Join(root, ".runtime", "dev", stackName+".secrets.json")
	}
	return filepath.Join(root, ".runtime", "dev", stackName+"."+profile+".secrets.json")
}

type localSecretReference struct {
	id   stack.ResourceID
	name string
	keys []string
}

func localSecretReferences(stackName, profile string) ([]localSecretReference, error) {
	document, err := renderStack(stackName, profile, localFixtureScenarioWorkspaceApprovalReset)
	if err != nil {
		return nil, err
	}
	spec, err := stack.Parse(bytes.NewReader(document))
	if err != nil {
		return nil, fmt.Errorf("parse local Stack for Secret inventory: %w", err)
	}
	rendered, err := stack.Render(spec, stack.Profile(profile))
	if err != nil {
		return nil, fmt.Errorf("render local Stack Secret inventory: %w", err)
	}
	references := make([]localSecretReference, 0)
	for _, resource := range rendered.Resources() {
		if resource.Kind != stack.ResourceSecretReference {
			continue
		}
		references = append(references, localSecretReference{id: resource.ID, name: resource.SecretReference.Reference, keys: append([]string(nil), resource.SecretReference.Keys...)})
	}
	sort.Slice(references, func(left, right int) bool { return references[left].name < references[right].name })
	if len(references) == 0 {
		return nil, fmt.Errorf("render local Stack Secret inventory: no local-generated Secret references were declared")
	}
	return references, nil
}

func secretReferenceByID(references []localSecretReference, id stack.ResourceID) (localSecretReference, bool) {
	for _, reference := range references {
		if reference.id == id {
			return reference, true
		}
	}
	return localSecretReference{}, false
}

func matchesSecretReferences(values map[string]map[string]string, references []localSecretReference) bool {
	if len(values) != len(references) {
		return false
	}
	for _, reference := range references {
		provided, exists := values[reference.name]
		if !exists || len(provided) != len(reference.keys) {
			return false
		}
		for _, key := range reference.keys {
			if provided[key] == "" {
				return false
			}
		}
	}
	return true
}

func randomValue(reader io.Reader) string {
	bytes := make([]byte, 32)
	if _, err := io.ReadFull(reader, bytes); err != nil {
		panic(fmt.Sprintf("read local development random material: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func writePrivate(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create private local development state directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("protect local development state directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return fmt.Errorf("create private local development state: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect local development state: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write local development state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync local development state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close local development state: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("commit local development state: %w", err)
	}
	return nil
}

func preflight(ctx context.Context, root, kubeconfig string, output io.Writer) error {
	for _, program := range []string{"tilt", "kubectl", "docker"} {
		if _, err := exec.LookPath(program); err != nil {
			return fmt.Errorf("check local development prerequisite %s: install it; no automatic installation was attempted", program)
		}
	}
	command := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfig, "--context", "orbstack", "get", "--raw=/readyz")
	command.Dir = root
	if output != nil {
		command.Stdout = output
		command.Stderr = output
	}
	if err := command.Run(); err != nil {
		return fmt.Errorf("check local development OrbStack context: start OrbStack Kubernetes or repair its explicit orbstack context: %w", err)
	}
	return nil
}

func up(ctx context.Context, stack, root, kubeconfig, actor string, scenario localFixtureScenario, output io.Writer) error {
	if err := preflight(ctx, root, kubeconfig, output); err != nil {
		return err
	}
	stackPath := filepath.Join(root, ".runtime", "dev", stack+".stack.json")
	document, err := renderStack(stack, "local", scenario)
	if err != nil {
		return err
	}
	if err := writePrivate(stackPath, document); err != nil {
		return err
	}
	port, err := allocatePort()
	if err != nil {
		return err
	}
	state, err := encodeState(stack, root, port, kubeconfig, actor, scenario)
	if err != nil {
		return err
	}
	if err := writePrivate(statePath(root, stack), state); err != nil {
		return err
	}
	if err := bootstrap(ctx, stack, root, kubeconfig, actor, output); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "tilt", localTiltUpArguments(stack, port, scenario)...)
	command.Env = commandEnvironment(kubeconfig)
	command.Dir = root
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		return fmt.Errorf("start isolated local Tilt Stack %s: %w", stack, err)
	}
	// Tilt has applied the declared Kubernetes resources. Reconcile provider
	// resources only after its migration and Temporal deployments are ready:
	// bootstrap alone cannot create a Temporal namespace before Temporal exists.
	return reconcile(ctx, stack, root, output)
}

func localTiltUpArguments(stack string, port int, scenario localFixtureScenario) []string {
	return []string{"up", "--context", "orbstack", "--namespace", profileNamespace(stack, "local"), "--port", fmt.Sprint(port), "--", "--stack=" + stack, "--fixture-scenario=" + string(scenario)}
}

func reconcile(ctx context.Context, stack, root string, output io.Writer) error {
	state, err := loadState(root, stack)
	if err != nil {
		return err
	}
	if err := verifyNamespace(ctx, state); err != nil {
		return err
	}
	for _, deployment := range []string{"migration-runner", "temporal"} {
		ready := exec.CommandContext(ctx, "kubectl", "--kubeconfig", state.Kubeconfig, "--context", "orbstack", "--namespace", state.Namespace, "rollout", "status", "deployment/"+deployment, "--timeout=120s")
		ready.Dir, ready.Stdout, ready.Stderr = root, output, output
		if err := ready.Run(); err != nil {
			return fmt.Errorf("wait for verified local Stack %s readiness: %w", deployment, err)
		}
	}
	if err := runStackctl(ctx, root, output, "reconcile", state); err != nil {
		return fmt.Errorf("reconcile verified local Stack providers: %w", err)
	}
	ready := exec.CommandContext(ctx, "kubectl", "--kubeconfig", state.Kubeconfig, "--context", "orbstack", "--namespace", state.Namespace, "rollout", "status", "deployment/orchestration", "--timeout=120s")
	ready.Dir, ready.Stdout, ready.Stderr = root, output, output
	if err := ready.Run(); err != nil {
		return fmt.Errorf("wait for reconciled local Stack orchestration readiness: %w", err)
	}
	return nil
}

func bootstrap(ctx context.Context, stack, root, kubeconfig, actor string, output io.Writer) error {
	capability := bootstrapCapabilityPath(root, stack)
	if _, err := os.Stat(capability); err == nil {
		state, stateErr := loadState(root, stack)
		if stateErr != nil {
			return fmt.Errorf("reuse local Stack bootstrap capability: %w", stateErr)
		}
		if state.Kubeconfig != kubeconfig || state.OperatorActor != actor {
			return fmt.Errorf("reuse local Stack bootstrap capability: refuse a different kubeconfig or operator actor")
		}
		if verifyErr := verifyNamespace(ctx, state); verifyErr == nil {
			return nil
		} else if goneErr := verifyNamespaceGone(ctx, state); goneErr != nil {
			return fmt.Errorf("reuse local Stack bootstrap capability: %w", verifyErr)
		} else if retireErr := retireBootstrapCapability(root, state); retireErr != nil {
			return retireErr
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read local Stack bootstrap capability: %w", err)
	}
	state, err := loadState(root, stack)
	if err != nil {
		return err
	}
	if state.Kubeconfig != kubeconfig || state.OperatorActor != actor {
		return fmt.Errorf("bootstrap local Stack: state does not match explicit kubeconfig and operator actor")
	}
	if err := runStackctl(ctx, root, output, "bootstrap", state); err != nil {
		return fmt.Errorf("bootstrap isolated local Stack %s: %w", stack, err)
	}
	return nil
}

func runStackctl(ctx context.Context, root string, output io.Writer, action string, state localState) error {
	arguments := []string{"run", "./cmd/stackctl", action,
		"--stack-file", filepath.Join(root, ".runtime", "dev", state.Stack+".stack.json"),
		"--stack", state.Stack,
		"--profile", "local",
		"--kubeconfig", state.Kubeconfig,
		"--context", "orbstack",
		"--actor", state.OperatorActor,
		"--audit-file", operatorAuditPath(root, state.Stack),
		"--migration-root", filepath.Join(root, "deploy", "production"),
		"--bootstrap-capability-file", bootstrapCapabilityPath(root, state.Stack),
	}
	if action == "reconcile" {
		arguments = append(arguments, "--providers-only")
	}
	command := exec.CommandContext(ctx, "go", arguments...)
	command.Dir, command.Stdout, command.Stderr = root, output, output
	if err := command.Run(); err != nil {
		return fmt.Errorf("run audited Stack operator %s: %w", action, err)
	}
	return nil
}

func status(stack, root string, output io.Writer) error {
	state, err := loadState(root, stack)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "stack=%s\nnamespace=%s\ndashboard=http://127.0.0.1:%d\nstack_file=%s\n", state.Stack, state.Namespace, state.DashboardPort, filepath.Join(root, ".runtime", "dev", stack+".stack.json"))
	return err
}

func reset(ctx context.Context, stack, root string, output io.Writer) error {
	state, err := loadState(root, stack)
	if err != nil {
		return err
	}
	if err := verifyNamespace(ctx, state); err != nil {
		return err
	}
	roles := []string{"api", "runtime-api", "orchestration", "model", "tool", "blob-role", "codec", "sandbox-control", "sandbox-host"}
	arguments := []string{"--kubeconfig", state.Kubeconfig, "--context", "orbstack", "--namespace", state.Namespace, "rollout", "restart"}
	for _, role := range roles {
		arguments = append(arguments, "deployment/"+role)
	}
	command := exec.CommandContext(ctx, "kubectl", arguments...)
	command.Dir, command.Stdout, command.Stderr = root, output, output
	if err := command.Run(); err != nil {
		return fmt.Errorf("reset only declared local Stack roles: %w", err)
	}
	for _, role := range roles {
		ready := exec.CommandContext(ctx, "kubectl", "--kubeconfig", state.Kubeconfig, "--context", "orbstack", "--namespace", state.Namespace, "rollout", "status", "deployment/"+role, "--timeout=120s")
		ready.Dir, ready.Stdout, ready.Stderr = root, output, output
		if err := ready.Run(); err != nil {
			return fmt.Errorf("await reset local Stack role %s: %w", role, err)
		}
	}
	return nil
}

func api(ctx context.Context, stack, root string, output io.Writer) error {
	state, err := loadState(root, stack)
	if err != nil {
		return err
	}
	if err := verifyNamespace(ctx, state); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "kubectl", "--kubeconfig", state.Kubeconfig, "--context", "orbstack", "--namespace", state.Namespace, "port-forward", "service/runtime-api", ":8088")
	command.Dir, command.Stdout, command.Stderr = root, output, output
	if err := command.Run(); err != nil {
		return fmt.Errorf("forward only verified local Stack API: %w", err)
	}
	return nil
}

func down(ctx context.Context, stack, root string, output io.Writer) error {
	state, err := loadState(root, stack)
	if err != nil {
		return err
	}
	if err := verifyNamespace(ctx, state); err != nil {
		if goneErr := verifyNamespaceGone(ctx, state); goneErr == nil {
			return retireBootstrapCapability(root, state)
		}
		return err
	}
	command := exec.CommandContext(ctx, "tilt", "down", "--context", "orbstack", "--namespace", state.Namespace, "--delete-namespaces", "--", "--stack="+stack)
	command.Env = commandEnvironment(state.Kubeconfig)
	command.Dir, command.Stdout, command.Stderr = root, output, output
	if err := command.Run(); err != nil {
		return fmt.Errorf("tear down only verified local Stack %s: %w", stack, err)
	}
	if err := verifyNamespaceGone(ctx, state); err != nil {
		return err
	}
	if err := retireBootstrapCapability(root, state); err != nil {
		return err
	}
	return nil
}

func statePath(root, stack string) string {
	return filepath.Join(root, ".runtime", "dev", stack+".state.json")
}

func bootstrapCapabilityPath(root, stack string) string {
	return filepath.Join(root, ".runtime", "dev", stack+".bootstrap-capability.json")
}

func operatorAuditPath(root, stack string) string {
	return filepath.Join(root, ".runtime", "dev", stack+".operator-audit.jsonl")
}

func encodeState(stack, root string, port int, kubeconfig, actor string, scenario localFixtureScenario) ([]byte, error) {
	if !filepath.IsAbs(kubeconfig) || !operatorActorPattern.MatchString(actor) {
		return nil, fmt.Errorf("encode local development state: explicit absolute kubeconfig and bounded operator actor are required")
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("canonicalize local development worktree: %w", err)
	}
	sum := sha256.Sum256([]byte(canonical))
	if _, err := parseLocalFixtureScenario(string(scenario)); err != nil {
		return nil, err
	}
	return json.Marshal(localState{Stack: stack, Namespace: profileNamespace(stack, "local"), DashboardPort: port, WorktreeFingerprint: fmt.Sprintf("sha256:%x", sum), Kubeconfig: kubeconfig, OperatorActor: actor, FixtureScenario: string(scenario)})
}

func loadState(root, stack string) (localState, error) {
	data, err := os.ReadFile(statePath(root, stack))
	if err != nil {
		return localState{}, fmt.Errorf("read local development Stack state: run dev up for this Stack first: %w", err)
	}
	var state localState
	if err := json.Unmarshal(data, &state); err != nil {
		return localState{}, fmt.Errorf("read local development Stack state: refuse malformed or foreign Stack state")
	}
	if _, scenarioErr := parseLocalFixtureScenario(state.FixtureScenario); scenarioErr != nil || state.Stack != stack || state.Namespace != profileNamespace(stack, "local") || state.DashboardPort < 1 || state.WorktreeFingerprint == "" || !filepath.IsAbs(state.Kubeconfig) || !operatorActorPattern.MatchString(state.OperatorActor) {
		return localState{}, fmt.Errorf("read local development Stack state: refuse malformed or foreign Stack state")
	}
	return state, nil
}

func allocatePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("allocate local Tilt dashboard port: %w", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func commandEnvironment(kubeconfig string) []string {
	environment := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "KUBECONFIG=") {
			environment = append(environment, entry)
		}
	}
	return append(environment, "KUBECONFIG="+kubeconfig)
}

func verifyNamespace(ctx context.Context, state localState) error {
	command := exec.CommandContext(ctx, "kubectl", "--kubeconfig", state.Kubeconfig, "--context", "orbstack", "get", "namespace", state.Namespace, "-o", "json")
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("verify local Stack namespace containment: %w", err)
	}
	var observed struct {
		Metadata struct {
			UID    string            `json:"uid"`
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(output, &observed); err != nil || observed.Metadata.UID == "" || observed.Metadata.Labels["app.kubernetes.io/part-of"] != "agent-runtime" || observed.Metadata.Labels["agent-runtime.dev/stack"] != state.Stack || observed.Metadata.Labels["agent-runtime.dev/profile"] != "local" {
		return fmt.Errorf("verify local Stack namespace containment: namespace labels or UID do not prove ownership")
	}
	return nil
}

// verifyNamespaceGone proves Tilt deleted the same exact local namespace before
// its private bootstrap capability can be retired.
func verifyNamespaceGone(ctx context.Context, state localState) error {
	command := exec.CommandContext(ctx, "kubectl", "--kubeconfig", state.Kubeconfig, "--context", "orbstack", "get", "namespace", state.Namespace, "--ignore-not-found=true", "-o", "name")
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("verify local Stack namespace deletion: %w", err)
	}
	if strings.TrimSpace(string(output)) != "" {
		return fmt.Errorf("verify local Stack namespace deletion: verified local namespace %s remains", state.Namespace)
	}
	return nil
}

// retireBootstrapCapability prevents a later up from treating a deleted Stack
// as a live owned namespace. It runs only after namespace absence was proven.
func retireBootstrapCapability(root string, state localState) error {
	path := bootstrapCapabilityPath(root, state.Stack)
	authority, err := stack.ReadBootstrapAuthority(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("retire local Stack bootstrap capability: %w", err)
	}
	if authority.Stack != state.Stack || authority.Profile != stack.ProfileLocal || authority.Namespace != state.Namespace {
		return fmt.Errorf("retire local Stack bootstrap capability: refuse foreign capability")
	}
	if err := stack.RemoveBootstrapAuthority(path, authority); err != nil {
		return fmt.Errorf("retire local Stack bootstrap capability: %w", err)
	}
	return nil
}
