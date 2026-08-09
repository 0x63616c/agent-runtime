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

	"github.com/0x63616c/agent-runtime/internal/stack"
)

const quotaPolicy = `{"defaults":{"milli_cpu":500,"memory_bytes":536870912,"root_disk_bytes":4294967296,"tmpfs_bytes":268435456,"pids":128,"process_count":64,"open_files":1024,"inodes":100000,"files":50000,"lifetime_seconds":3600,"produced_output_bytes":67108864,"retained_output_bytes":16777216,"transfer_bytes":1073741824,"network_connections":64,"volume_bytes":10737418240,"snapshot_bytes":10737418240},"maximums":{"milli_cpu":4000,"memory_bytes":4294967296,"root_disk_bytes":34359738368,"tmpfs_bytes":2147483648,"pids":1024,"process_count":512,"open_files":8192,"inodes":1000000,"files":500000,"lifetime_seconds":86400,"produced_output_bytes":1073741824,"retained_output_bytes":268435456,"transfer_bytes":10737418240,"network_connections":1024,"volume_bytes":107374182400,"snapshot_bytes":107374182400}}`

var stackPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$`)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, output io.Writer) error {
	if len(arguments) == 0 {
		return fmt.Errorf("run local development command: render, secrets, preflight, up, status, api, reset, or down is required")
	}
	switch arguments[0] {
	case "render":
		stack, profile, destination, err := parseRenderArguments(arguments[1:])
		if err != nil {
			return err
		}
		document, err := renderStack(stack, profile)
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
		_, root, err := parseStackAndRoot("preflight", arguments[1:])
		if err != nil {
			return err
		}
		return preflight(ctx, root, output)
	case "up":
		stack, root, err := parseStackAndRoot("up", arguments[1:])
		if err != nil {
			return err
		}
		return up(ctx, stack, root, output)
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

func parseRenderArguments(arguments []string) (string, string, string, error) {
	flags := flag.NewFlagSet("render", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stack := flags.String("stack", "", "sole validated Stack identity")
	profile := flags.String("profile", "local", "local, ci, or production")
	destination := flags.String("output", "", "private local output path")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return "", "", "", fmt.Errorf("parse local Stack render arguments: --stack is required")
	}
	if err := validateStack(*stack); err != nil {
		return "", "", "", err
	}
	if *profile != "local" && *profile != "ci" && *profile != "production" {
		return "", "", "", fmt.Errorf("parse local Stack render arguments: --profile must be local, ci, or production")
	}
	return *stack, *profile, *destination, nil
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

func validateStack(stack string) error {
	if !stackPattern.MatchString(stack) {
		return fmt.Errorf("validate local Stack identity: --stack must be a lowercase DNS label up to 40 characters")
	}
	return nil
}

func renderStack(stack, profile string) ([]byte, error) {
	if err := validateStack(stack); err != nil {
		return nil, err
	}
	resources, err := reviewedLocalResources(stack)
	if err != nil {
		return nil, err
	}
	profiles := make(map[string]any, 3)
	for _, candidate := range []string{"local", "ci", "production"} {
		namespace := profileNamespace(stack, candidate)
		resolved := make([]json.RawMessage, len(resources))
		for index, resource := range resources {
			value := strings.ReplaceAll(string(resource), "ar-agent-runtime", namespace)
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

func reviewedLocalResources(stackName string) ([]json.RawMessage, error) {
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
				Profiles struct {
					Local struct {
						Resources []json.RawMessage `json:"resources"`
					} `json:"local"`
				} `json:"profiles"`
			}
			if err := json.Unmarshal(data, &document); err != nil {
				return nil, fmt.Errorf("decode reviewed local Stack profile: %w", err)
			}
			resources := document.Profiles.Local.Resources
			for index, resource := range resources {
				var object map[string]json.RawMessage
				if err := json.Unmarshal(resource, &object); err != nil {
					return nil, fmt.Errorf("decode reviewed local Stack resource: %w", err)
				}
				var id stack.ResourceID
				if err := json.Unmarshal(object["id"], &id); err != nil {
					return nil, fmt.Errorf("read reviewed local Stack resource identity: %w", err)
				}
				if !tiltBuiltResource(id) {
					continue
				}
				var kubernetes map[string]json.RawMessage
				if err := json.Unmarshal(object["kubernetes"], &kubernetes); err != nil {
					return nil, fmt.Errorf("decode reviewed local Stack workload: %w", err)
				}
				image, err := json.Marshal(devImage(stackName, id))
				if err != nil {
					return nil, fmt.Errorf("encode local Tilt image reference: %w", err)
				}
				kubernetes["image"] = image
				encodedKubernetes, err := json.Marshal(kubernetes)
				if err != nil {
					return nil, fmt.Errorf("encode reviewed local Stack workload: %w", err)
				}
				object["kubernetes"] = encodedKubernetes
				encodedResource, err := json.Marshal(object)
				if err != nil {
					return nil, fmt.Errorf("encode reviewed local Stack resource: %w", err)
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

func tiltBuiltResource(id stack.ResourceID) bool {
	switch id {
	case "api", "orchestration", "model", "tool", "blob-role", "codec", "sandbox-control", "sandbox-host", "egress-proxy":
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
		if !stateFound || !sandboxFound {
			return nil, fmt.Errorf("materialize local development secrets: reviewed Stack is missing required state credential references")
		}
		statePassword := state.Values[stateReference.name]["POSTGRES_PASSWORD"]
		stateDSN := "postgres://postgres:" + statePassword + "@state:5432/agent_runtime?sslmode=disable"
		state.Values[stateReference.name]["STATE_DATABASE_DSN"] = stateDSN
		state.Values[sandboxReference.name]["SANDBOX_STATE_DSN"] = stateDSN
		encoded, marshalErr := json.Marshal(state)
		if marshalErr != nil {
			return nil, fmt.Errorf("encode local development secret state: %w", marshalErr)
		}
		if err := writePrivate(path, append(encoded, '\n')); err != nil {
			return nil, err
		}
	}
	items := make([]map[string]any, 0, len(references))
	for _, reference := range references {
		items = append(items, map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": reference.name, "labels": map[string]string{"app.kubernetes.io/part-of": "agent-runtime", "agent-runtime.dev/stack": stackName, "agent-runtime.dev/profile": profile, "agent-runtime.dev/resource": string(reference.id)}}, "type": "Opaque", "stringData": state.Values[reference.name]})
	}
	encoded, err := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "List", "items": items})
	if err != nil {
		return nil, fmt.Errorf("encode local development Secret manifests: %w", err)
	}
	return encoded, nil
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
	document, err := renderStack(stackName, profile)
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

func preflight(ctx context.Context, root string, output io.Writer) error {
	for _, program := range []string{"tilt", "kubectl", "docker"} {
		if _, err := exec.LookPath(program); err != nil {
			return fmt.Errorf("check local development prerequisite %s: install it; no automatic installation was attempted", program)
		}
	}
	command := exec.CommandContext(ctx, "kubectl", "--context", "orbstack", "get", "--raw=/readyz")
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

func up(ctx context.Context, stack, root string, output io.Writer) error {
	if err := preflight(ctx, root, output); err != nil {
		return err
	}
	stackPath := filepath.Join(root, ".runtime", "dev", stack+".stack.json")
	document, err := renderStack(stack, "local")
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
	state, err := encodeState(stack, root, port)
	if err != nil {
		return err
	}
	if err := writePrivate(statePath(root, stack), state); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "tilt", "up", "--context", "orbstack", "--namespace", profileNamespace(stack, "local"), "--port", fmt.Sprint(port), "--", "--stack="+stack)
	command.Dir = root
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		return fmt.Errorf("start isolated local Tilt Stack %s: %w", stack, err)
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
	arguments := []string{"--context", "orbstack", "--namespace", state.Namespace, "rollout", "restart"}
	for _, role := range []string{"api", "orchestration", "model", "tool", "blob-role", "codec", "sandbox-control", "sandbox-host"} {
		arguments = append(arguments, "deployment/"+role)
	}
	command := exec.CommandContext(ctx, "kubectl", arguments...)
	command.Dir, command.Stdout, command.Stderr = root, output, output
	if err := command.Run(); err != nil {
		return fmt.Errorf("reset only declared local Stack roles: %w", err)
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
	command := exec.CommandContext(ctx, "kubectl", "--context", "orbstack", "--namespace", state.Namespace, "port-forward", "service/api", ":8080")
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
		return err
	}
	command := exec.CommandContext(ctx, "tilt", "down", "--context", "orbstack", "--namespace", state.Namespace, "--delete-namespaces", "--", "--stack="+stack)
	command.Dir, command.Stdout, command.Stderr = root, output, output
	if err := command.Run(); err != nil {
		return fmt.Errorf("tear down only verified local Stack %s: %w", stack, err)
	}
	return nil
}

func statePath(root, stack string) string {
	return filepath.Join(root, ".runtime", "dev", stack+".state.json")
}

func encodeState(stack, root string, port int) ([]byte, error) {
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("canonicalize local development worktree: %w", err)
	}
	sum := sha256.Sum256([]byte(canonical))
	return json.Marshal(localState{Stack: stack, Namespace: profileNamespace(stack, "local"), DashboardPort: port, WorktreeFingerprint: fmt.Sprintf("sha256:%x", sum)})
}

func loadState(root, stack string) (localState, error) {
	data, err := os.ReadFile(statePath(root, stack))
	if err != nil {
		return localState{}, fmt.Errorf("read local development Stack state: run dev up for this Stack first: %w", err)
	}
	var state localState
	if err := json.Unmarshal(data, &state); err != nil || state.Stack != stack || state.Namespace != profileNamespace(stack, "local") || state.DashboardPort < 1 || state.WorktreeFingerprint == "" {
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

func verifyNamespace(ctx context.Context, state localState) error {
	command := exec.CommandContext(ctx, "kubectl", "--context", "orbstack", "get", "namespace", state.Namespace, "-o", "json")
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
