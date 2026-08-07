package stack

import (
	"context"

	"github.com/cockroachdb/errors"
)

// PrerequisiteKind selects one read-only host capability probe.
type PrerequisiteKind string

const (
	// PrerequisiteExecutable checks whether a named executable is available.
	PrerequisiteExecutable PrerequisiteKind = "executable"
	// PrerequisiteKubernetesContext checks the selected context without changing it.
	PrerequisiteKubernetesContext PrerequisiteKind = "kubernetes_context"
	// PrerequisiteArchitecture checks the host/runtime architecture.
	PrerequisiteArchitecture PrerequisiteKind = "architecture"
	// PrerequisiteFreeDisk checks available disk against a finite minimum.
	PrerequisiteFreeDisk PrerequisiteKind = "free_disk"
)

// Prerequisite is one explicit read-only capability check and direct repair.
type Prerequisite struct {
	// Name is stable within the selected profile.
	Name string `json:"name"`
	// Kind selects the read-only probe operation.
	Kind PrerequisiteKind `json:"kind"`
	// Expected is the required exact value for non-numeric checks.
	Expected string `json:"expected"`
	// MinimumBytes is the finite threshold for free-disk checks.
	MinimumBytes int64 `json:"minimum_bytes"`
	// Repair tells an operator how to fix failure without automatic mutation.
	Repair string `json:"repair"`
}

// HostProbe exposes only read operations and cannot mutate credentials or context.
type HostProbe interface {
	// Executable reports whether a named command is available.
	Executable(context.Context, string) (bool, error)
	// KubernetesContext returns the selected context without changing it.
	KubernetesContext(context.Context, OperatorTarget) (string, error)
	// Architecture returns the relevant host/runtime architecture.
	Architecture(context.Context) (string, error)
	// FreeDiskBytes returns currently available disk bytes.
	FreeDiskBytes(context.Context) (int64, error)
}

// PrerequisiteResult is a bounded secret-safe check outcome.
type PrerequisiteResult struct {
	// Name identifies the declared prerequisite.
	Name string `json:"name"`
	// Passed is true only when the exact declaration is satisfied.
	Passed bool `json:"passed"`
	// Repair is present only on failure.
	Repair string `json:"repair,omitempty"`
}

// PreflightReport is the complete read-only result for one profile.
type PreflightReport struct {
	// Results preserves declaration order for operator diagnostics.
	Results []PrerequisiteResult `json:"results"`
}

// Passed reports whether every declared prerequisite passed.
func (report PreflightReport) Passed() bool {
	for _, result := range report.Results {
		if !result.Passed {
			return false
		}
	}
	return true
}

// Preflight checks declared prerequisites without applying any repair or host mutation.
func Preflight(ctx context.Context, spec Spec, profile Profile, target OperatorTarget, probe HostProbe) (PreflightReport, error) {
	if err := ctx.Err(); err != nil {
		return PreflightReport{}, errors.Wrap(err, "check stack prerequisites")
	}
	if probe == nil {
		return PreflightReport{}, errors.New("check stack prerequisites: host probe is required")
	}
	if err := validateOperatorTarget(target); err != nil {
		return PreflightReport{}, errors.Wrap(err, "check stack prerequisites")
	}
	selectedContext, err := probe.KubernetesContext(ctx, target)
	if err != nil {
		return PreflightReport{}, errors.Wrap(err, "check stack prerequisites: validate explicit Kubernetes target")
	}
	if selectedContext != target.Context {
		return PreflightReport{}, errors.New("check stack prerequisites: selected context does not match explicit target")
	}
	selected, ok := spec.profile(profile)
	if !ok {
		return PreflightReport{}, errors.New("check stack prerequisites: profile must be local, ci, or production")
	}
	report := PreflightReport{Results: make([]PrerequisiteResult, 0, len(selected.Prerequisites))}
	for _, prerequisite := range selected.Prerequisites {
		passed, err := checkPrerequisite(ctx, target, selectedContext, probe, prerequisite)
		if err != nil {
			return PreflightReport{}, errors.Wrapf(err, "check stack prerequisite %s", prerequisite.Name)
		}
		result := PrerequisiteResult{Name: prerequisite.Name, Passed: passed}
		if !passed {
			result.Repair = prerequisite.Repair
		}
		report.Results = append(report.Results, result)
	}
	return report, nil
}

func checkPrerequisite(ctx context.Context, target OperatorTarget, selectedContext string, probe HostProbe, prerequisite Prerequisite) (bool, error) {
	switch prerequisite.Kind {
	case PrerequisiteExecutable:
		return probe.Executable(ctx, prerequisite.Name)
	case PrerequisiteKubernetesContext:
		return target.Context == prerequisite.Expected && selectedContext == target.Context, nil
	case PrerequisiteArchitecture:
		value, err := probe.Architecture(ctx)
		return value == prerequisite.Expected, err
	case PrerequisiteFreeDisk:
		value, err := probe.FreeDiskBytes(ctx)
		return value >= prerequisite.MinimumBytes, err
	default:
		return false, errors.New("unsupported prerequisite kind")
	}
}

func validatePrerequisite(prerequisite Prerequisite) error {
	if !resourceIDPattern.MatchString(prerequisite.Name) || prerequisite.Repair == "" || len(prerequisite.Repair) > 512 {
		return errors.New("prerequisite must declare a valid name and bounded repair")
	}
	switch prerequisite.Kind {
	case PrerequisiteExecutable:
		if prerequisite.Expected != "present" || prerequisite.MinimumBytes != 0 {
			return errors.Newf("prerequisite %s executable expectation must be present", prerequisite.Name)
		}
	case PrerequisiteKubernetesContext, PrerequisiteArchitecture:
		if prerequisite.Expected == "" || prerequisite.MinimumBytes != 0 {
			return errors.Newf("prerequisite %s must declare expected value", prerequisite.Name)
		}
	case PrerequisiteFreeDisk:
		if prerequisite.Expected != "" || prerequisite.MinimumBytes <= 0 {
			return errors.Newf("prerequisite %s must declare finite minimum bytes", prerequisite.Name)
		}
	default:
		return errors.Newf("prerequisite %s has unsupported kind", prerequisite.Name)
	}
	return nil
}
