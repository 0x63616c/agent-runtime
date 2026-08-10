package sandboxcontrol

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/0x63616c/agent-runtime/sandbox"
	"github.com/cockroachdb/errors"
)

var publicEnvironmentName = regexp.MustCompile(`^PUBLIC_[A-Z0-9_]{1,120}$`)

var ordinaryEnvironmentNames = map[string]struct{}{
	"LANG": {}, "LC_ALL": {}, "LOG_LEVEL": {}, "MODE": {}, "TERM": {}, "TZ": {},
}

type dispatchEnvelope struct {
	Version string                   `json:"version"`
	Kind    string                   `json:"kind"`
	Request sandbox.OperationRequest `json:"request"`
}

// validateDispatchBody permits only the canonical typed control request (or
// the exact metadata-only test/reference sentinel). Durable environment is an
// explicit public allow-list; secret authority stays reference-only.
func validateDispatchBody(body string) error {
	if body == "" || body == `{}` || body == `{"version":"sandbox.control/v1"}` {
		return nil
	}
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.DisallowUnknownFields()
	var envelope dispatchEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return errors.New("accept sandbox operation: dispatch body must be a typed control request")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("accept sandbox operation: dispatch body must contain one value")
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, []byte(body)) || envelope.Version != "sandbox.control/v1" || envelope.Kind != "operation-request" {
		return errors.New("accept sandbox operation: dispatch body must be canonical sandbox.control/v1")
	}
	if err := validateRequestDispatch(envelope.Request); err != nil {
		return err
	}
	return nil
}

func validateRequestDispatch(request sandbox.OperationRequest) error {
	if request.CreateSandbox != nil {
		if err := validateOrdinaryEnvironment(request.CreateSandbox.Spec.Environment); err != nil {
			return err
		}
	}
	if request.ExecProcess != nil {
		if err := validateOrdinaryEnvironment(request.ExecProcess.Command.Environment); err != nil {
			return err
		}
		for _, argument := range append([]string{string(request.ExecProcess.Command.Executable)}, request.ExecProcess.Command.Argv...) {
			if directCredentialWire(argument) {
				return errors.New("accept sandbox operation: command contains direct credential material")
			}
		}
	}
	return nil
}

func validateOrdinaryEnvironment(environment map[string]string) error {
	for name, value := range environment {
		if _, allowed := ordinaryEnvironmentNames[name]; !allowed && !publicEnvironmentName.MatchString(name) {
			return errors.New("accept sandbox operation: durable environment name is not explicitly public")
		}
		if directCredentialWire(value) {
			return errors.New("accept sandbox operation: durable environment contains direct credential material")
		}
	}
	return nil
}

func directCredentialWire(value string) bool {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	return strings.HasPrefix(lower, "bearer ") || strings.HasPrefix(trimmed, "-----BEGIN ") || strings.HasPrefix(lower, "sk-") || strings.HasPrefix(trimmed, "AKIA") || strings.Contains(lower, "aws_secret_access_key")
}
