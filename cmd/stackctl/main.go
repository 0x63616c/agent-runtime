// Command stackctl renders and inspects reviewed declarative Stack documents.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/0x63616c/agent-runtime/internal/roles"
	"github.com/0x63616c/agent-runtime/internal/stack"
	"github.com/cockroachdb/errors"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, output io.Writer) error {
	return runWithProbe(ctx, arguments, output, systemProbe{})
}

func runWithProbe(ctx context.Context, arguments []string, output io.Writer, probe stack.HostProbe) error {
	if err := ctx.Err(); err != nil {
		return errors.Wrap(err, "run stack operator command")
	}
	if len(arguments) == 0 {
		return errors.New("run stack operator command: render, manifests, role-configs, check, diff, preflight, bootstrap, apply, observe, reconcile, rollback, or teardown is required")
	}
	switch arguments[0] {
	case "render":
		stackPath, profile, _, err := parseArguments("render", arguments[1:], false)
		if err != nil {
			return err
		}
		rendered, err := loadAndRender(stackPath, profile)
		if err != nil {
			return err
		}
		if _, err := output.Write(rendered.JSON()); err != nil {
			return errors.Wrap(err, "write rendered stack")
		}
		return nil
	case "check":
		stackPath, profile, observedPath, err := parseArguments("check", arguments[1:], true)
		if err != nil {
			return err
		}
		rendered, err := loadAndRender(stackPath, profile)
		if err != nil {
			return err
		}
		observed, err := os.Open(observedPath)
		if err != nil {
			return errors.Wrap(err, "open observed rendered stack")
		}
		defer func() { _ = observed.Close() }()
		return stack.Check(rendered, observed)
	case "manifests":
		stackPath, profile, _, err := parseArguments("manifests", arguments[1:], false)
		if err != nil {
			return err
		}
		rendered, err := loadAndRender(stackPath, profile)
		if err != nil {
			return err
		}
		manifests, err := stack.RenderKubernetes(rendered)
		if err != nil {
			return err
		}
		if _, err := output.Write(manifests.JSON()); err != nil {
			return errors.Wrap(err, "write rendered Kubernetes manifests")
		}
		return nil
	case "role-configs":
		stackPath, profile, _, err := parseArguments("role-configs", arguments[1:], false)
		if err != nil {
			return err
		}
		rendered, err := loadAndRender(stackPath, profile)
		if err != nil {
			return err
		}
		configurations, err := extractRoleConfigurations(rendered.Resources())
		if err != nil {
			return err
		}
		if err := json.NewEncoder(output).Encode(configurations); err != nil {
			return errors.Wrap(err, "write rendered runtime role configurations")
		}
		return nil
	case "diff":
		stackPath, profile, observedPath, err := parseArguments("diff", arguments[1:], true)
		if err != nil {
			return err
		}
		rendered, err := loadAndRender(stackPath, profile)
		if err != nil {
			return err
		}
		observed, err := os.Open(observedPath)
		if err != nil {
			return errors.Wrap(err, "open observed rendered stack")
		}
		defer func() { _ = observed.Close() }()
		difference, err := stack.Diff(rendered, observed)
		if err != nil {
			return err
		}
		if err := json.NewEncoder(output).Encode(difference); err != nil {
			return errors.Wrap(err, "write rendered stack difference")
		}
		return nil
	case "preflight":
		stackPath, profile, target, err := parsePreflightArguments(arguments[1:])
		if err != nil {
			return err
		}
		spec, err := loadSpec(stackPath)
		if err != nil {
			return err
		}
		report, err := stack.Preflight(ctx, spec, profile, target, probe)
		if err != nil {
			return err
		}
		if err := json.NewEncoder(output).Encode(report); err != nil {
			return errors.Wrap(err, "write stack preflight report")
		}
		if !report.Passed() {
			return errors.New("check stack prerequisites: one or more declared prerequisites failed")
		}
		return nil
	case "bootstrap", "apply", "observe", "diff-live", "reconcile", "rollback", "teardown":
		request, stackPath, profile, rollbackPath, auditPath, err := parseOperatorArguments(arguments[0], arguments[1:])
		if err != nil {
			return err
		}
		rendered, err := loadAndRenderNamed(stackPath, request.Stack, profile)
		if err != nil {
			return err
		}
		if arguments[0] == "bootstrap" {
			authority, authorityErr := stack.NewBootstrapAuthority(rendered, "")
			if authorityErr != nil {
				return authorityErr
			}
			request.OperatorRequest.BootstrapAuthority = authority
		} else if requiresBootstrapAuthority(arguments[0]) {
			authority, authorityErr := stack.ReadBootstrapAuthority(request.CapabilityFile)
			if authorityErr != nil {
				return authorityErr
			}
			request.OperatorRequest.BootstrapAuthority = authority
		}
		adapter, err := stack.NewKubectlAdapter(stack.SystemKubectlRunner{})
		if err != nil {
			return err
		}
		providers, err := stack.NewKubectlDeclaredProviderAdapter(stack.SystemKubectlRunner{})
		if err != nil {
			return err
		}
		operator, err := stack.NewKubernetesOperatorWithProviders(adapter, providers, stack.JSONLineAuditLog{Path: auditPath})
		if err != nil {
			return err
		}
		switch arguments[0] {
		case "bootstrap":
			observation, bootstrapErr := operator.Bootstrap(ctx, request.OperatorRequest, rendered)
			if bootstrapErr != nil {
				return bootstrapErr
			}
			request.OperatorRequest.BootstrapAuthority.NamespaceUID = observation.UID
			if authorityErr := stack.WriteBootstrapAuthority(request.CapabilityFile, request.OperatorRequest.BootstrapAuthority); authorityErr != nil {
				return authorityErr
			}
			return encodeOperatorResult(output, observation)
		case "apply":
			observation, applyErr := operator.Apply(ctx, request.OperatorRequest, rendered)
			if applyErr != nil {
				return applyErr
			}
			return encodeOperatorResult(output, observation)
		case "observe":
			observation, observeErr := operator.Observe(ctx, request.OperatorRequest, rendered)
			if observeErr != nil {
				return observeErr
			}
			return encodeOperatorResult(output, observation)
		case "diff-live":
			difference, diffErr := operator.Diff(ctx, request.OperatorRequest, rendered)
			if diffErr != nil {
				return diffErr
			}
			return encodeOperatorResult(output, difference)
		case "reconcile":
			result, reconcileErr := operator.Reconcile(ctx, request.OperatorRequest, rendered)
			if reconcileErr != nil {
				return reconcileErr
			}
			return encodeOperatorResult(output, result)
		case "rollback":
			previous, rollbackLoadErr := loadAndRenderNamed(rollbackPath, request.Stack, profile)
			if rollbackLoadErr != nil {
				return rollbackLoadErr
			}
			observation, rollbackErr := operator.Rollback(ctx, request.OperatorRequest, rendered, previous)
			if rollbackErr != nil {
				return rollbackErr
			}
			return encodeOperatorResult(output, observation)
		case "teardown":
			if teardownErr := operator.Teardown(ctx, request.OperatorRequest, rendered); teardownErr != nil {
				return teardownErr
			}
			currentAuthority, authorityErr := stack.ReadBootstrapAuthority(request.CapabilityFile)
			if authorityErr != nil {
				return authorityErr
			}
			if authorityErr := stack.RemoveBootstrapAuthority(request.CapabilityFile, currentAuthority); authorityErr != nil {
				return authorityErr
			}
			return encodeOperatorResult(output, struct{}{})
		}
		return errors.New("run stack operator command: unreachable operator action")
	default:
		return errors.Newf("run stack operator command: unknown command %q", arguments[0])
	}
}

func extractRoleConfigurations(resources []stack.Resource) (map[string]json.RawMessage, error) {
	configurations := make(map[string]json.RawMessage)
	for _, resource := range resources {
		if resource.Kubernetes == nil {
			continue
		}
		for _, variable := range resource.Kubernetes.Environment {
			if variable.Name != "RUNTIME_ROLE_CONFIG" {
				continue
			}
			configuration, err := roles.Parse(strings.NewReader(variable.Value))
			if err != nil {
				return nil, errors.Wrapf(err, "extract runtime role configuration from resource %s", resource.ID)
			}
			role := string(configuration.Role())
			if _, duplicate := configurations[role]; duplicate {
				return nil, errors.Newf("extract runtime role configurations: role %s is declared more than once", role)
			}
			var canonical bytes.Buffer
			if err := json.Compact(&canonical, []byte(variable.Value)); err != nil {
				return nil, errors.Wrapf(err, "canonicalize runtime role configuration %s", role)
			}
			configurations[role] = append(json.RawMessage(nil), canonical.Bytes()...)
		}
	}
	if len(configurations) == 0 {
		return nil, errors.New("extract runtime role configurations: Stack declares no runtime roles")
	}
	return configurations, nil
}

func parsePreflightArguments(arguments []string) (string, stack.Profile, stack.OperatorTarget, error) {
	flags := flag.NewFlagSet("preflight", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stackPath := flags.String("stack-file", "", "path to the sole Stack document")
	profile := flags.String("profile", "", "local, ci, or production")
	kubeconfig := flags.String("kubeconfig", "", "absolute explicit kubeconfig path")
	contextName := flags.String("context", "", "explicit Kubernetes context")
	if err := flags.Parse(arguments); err != nil {
		return "", "", stack.OperatorTarget{}, errors.Wrap(err, "parse preflight arguments")
	}
	target := stack.OperatorTarget{Kubeconfig: *kubeconfig, Context: *contextName}
	if flags.NArg() != 0 || *stackPath == "" || *profile == "" || *kubeconfig == "" || !filepath.IsAbs(*kubeconfig) || *contextName == "" || len(*contextName) > 253 {
		return "", "", stack.OperatorTarget{}, errors.New("parse preflight arguments: --stack-file and --profile are required; explicit absolute kubeconfig and context are required")
	}
	return *stackPath, stack.Profile(*profile), target, nil
}

type operatorArguments struct {
	stack.OperatorRequest
	Stack          string
	CapabilityFile string
}

func parseOperatorArguments(command string, arguments []string) (operatorArguments, string, stack.Profile, string, string, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stackPath := flags.String("stack-file", "", "path to the sole Stack document")
	stackName := flags.String("stack", "", "reviewed Stack identity")
	profile := flags.String("profile", "", "local, ci, or production")
	kubeconfig := flags.String("kubeconfig", "", "absolute explicit kubeconfig path")
	contextName := flags.String("context", "", "explicit Kubernetes context")
	actor := flags.String("actor", "", "operator identity")
	auditPath := flags.String("audit-file", "", "append-only operator audit file")
	migrationRoot := flags.String("migration-root", "", "absolute root containing reviewed migration artifacts")
	rollbackPath := flags.String("rollback-stack-file", "", "previous reviewed Stack document for rollback")
	capabilityFile := flags.String("bootstrap-capability-file", "", "absolute private capability file created by stackctl bootstrap")
	if err := flags.Parse(arguments); err != nil {
		return operatorArguments{}, "", "", "", "", errors.Wrap(err, "parse Kubernetes operator arguments")
	}
	if flags.NArg() != 0 || *stackPath == "" || *stackName == "" || *profile == "" || *kubeconfig == "" || *contextName == "" || *actor == "" || *auditPath == "" || *migrationRoot == "" || *capabilityFile == "" || !filepath.IsAbs(*capabilityFile) || (command == "rollback" && *rollbackPath == "") || (command != "rollback" && *rollbackPath != "") {
		return operatorArguments{}, "", "", "", "", errors.Newf("parse %s arguments: --stack-file, --stack, --profile, --kubeconfig, --context, --actor, --audit-file, --migration-root, and absolute --bootstrap-capability-file are required; --rollback-stack-file is required only for rollback", command)
	}
	return operatorArguments{Stack: *stackName, CapabilityFile: *capabilityFile, OperatorRequest: stack.OperatorRequest{Actor: *actor, Target: stack.OperatorTarget{Kubeconfig: *kubeconfig, Context: *contextName, MigrationRoot: *migrationRoot}}}, *stackPath, stack.Profile(*profile), *rollbackPath, *auditPath, nil
}

func requiresBootstrapAuthority(command string) bool {
	return command == "apply" || command == "reconcile" || command == "rollback" || command == "teardown"
}

func loadAndRenderNamed(path, name string, profile stack.Profile) (stack.Rendered, error) {
	spec, err := loadSpec(path)
	if err != nil {
		return stack.Rendered{}, err
	}
	if spec.Name.String() != name {
		return stack.Rendered{}, errors.New("render Stack operator input: --stack does not match the reviewed Stack document")
	}
	return stack.Render(spec, profile)
}

func encodeOperatorResult(output io.Writer, value any) error {
	if err := json.NewEncoder(output).Encode(value); err != nil {
		return errors.Wrap(err, "write Kubernetes operator result")
	}
	return nil
}

func parseArguments(command string, arguments []string, requireObserved bool) (string, stack.Profile, string, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stackPath := flags.String("stack-file", "", "path to the sole Stack document")
	profile := flags.String("profile", "", "local, ci, or production")
	observed := flags.String("observed", "", "path to observed rendered desired state")
	if err := flags.Parse(arguments); err != nil {
		return "", "", "", errors.Wrap(err, "parse stack operator arguments")
	}
	if flags.NArg() != 0 || *stackPath == "" || *profile == "" || (requireObserved && *observed == "") || (!requireObserved && *observed != "") {
		return "", "", "", errors.Newf("parse %s arguments: --stack-file and --profile are required%s", command, observedRequirement(requireObserved))
	}
	return *stackPath, stack.Profile(*profile), *observed, nil
}

func observedRequirement(required bool) string {
	if required {
		return "; --observed is required"
	}
	return ""
}

func loadAndRender(path string, profile stack.Profile) (stack.Rendered, error) {
	spec, err := loadSpec(path)
	if err != nil {
		return stack.Rendered{}, err
	}
	return stack.Render(spec, profile)
}

func loadSpec(path string) (stack.Spec, error) {
	input, err := os.Open(path)
	if err != nil {
		return stack.Spec{}, errors.Wrap(err, "open stack specification")
	}
	defer func() { _ = input.Close() }()
	return stack.Parse(input)
}

type systemProbe struct{}

func (systemProbe) Executable(_ context.Context, name string) (bool, error) {
	_, err := exec.LookPath(name)
	return err == nil, nil
}

func (systemProbe) KubernetesContext(ctx context.Context, target stack.OperatorTarget) (string, error) {
	output, err := exec.CommandContext(ctx, "kubectl", "--kubeconfig", target.Kubeconfig, "--context", target.Context, "config", "get-contexts", target.Context, "--no-headers", "-o", "name").Output()
	if err != nil {
		return "", errors.Wrap(err, "read Kubernetes context")
	}
	return strings.TrimSpace(string(output)), nil
}

func (systemProbe) Architecture(context.Context) (string, error) { return runtime.GOARCH, nil }

func (systemProbe) FreeDiskBytes(context.Context) (int64, error) {
	var statistics syscall.Statfs_t
	if err := syscall.Statfs(".", &statistics); err != nil {
		return 0, errors.Wrap(err, "read free disk capacity")
	}
	return int64(statistics.Bavail) * int64(statistics.Bsize), nil
}
