package sandbox

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
)

const operationRequestKind = "operation-request"

const (
	maxControlV1Bytes      = 1 << 20
	maxControlV1Nesting    = 64
	maxControlV1Collection = 4096
)

type operationRequestEnvelope struct {
	Version string           `json:"version"`
	Kind    string           `json:"kind"`
	Request OperationRequest `json:"request"`
}

func encodeOperationRequestV1(request OperationRequest) ([]byte, error) {
	if err := validateCanonicalStrings(reflect.ValueOf(request)); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(operationRequestEnvelope{Version: controlV1, Kind: operationRequestKind, Request: copyRequest(request)})
	if err != nil {
		return nil, newFailure(FailureInvalidArgument, "operation request cannot be encoded", RetryNever)
	}
	if len(encoded) > maxControlV1Bytes {
		return nil, newFailure(FailureResourceLimitExceeded, "operation request exceeds the finite wire limit", RetryNever)
	}
	return encoded, nil
}

func decodeOperationRequestV1(data []byte) (OperationRequest, error) {
	if err := validateStrictJSON(data); err != nil {
		return OperationRequest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var envelope operationRequestEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return OperationRequest{}, newFailure(FailureInvalidArgument, "operation request is invalid", RetryNever)
	}
	if envelope.Version != controlV1 || envelope.Kind != operationRequestKind {
		return OperationRequest{}, newFailure(FailureInvalidArgument, "operation request violates sandbox.control/v1", RetryNever)
	}
	canonical, err := encodeOperationRequestV1(envelope.Request)
	if err != nil || !bytes.Equal(canonical, data) {
		return OperationRequest{}, newFailure(FailureInvalidArgument, "operation request is not canonical sandbox.control/v1", RetryNever)
	}
	return copyRequest(envelope.Request), nil
}

// validateStrictJSON rejects every form that encoding/json would otherwise
// quietly normalize: duplicate keys, trailing values, float/exponent numbers,
// and aliases that do not round-trip to canonical bytes.
func validateStrictJSON(data []byte) error {
	if len(data) == 0 || len(data) > maxControlV1Bytes {
		return newFailure(FailureResourceLimitExceeded, "sandbox.control/v1 exceeds the finite wire limit", RetryNever)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return newFailure(FailureInvalidArgument, "sandbox.control/v1 has trailing JSON data", RetryNever)
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth >= maxControlV1Nesting {
		return newFailure(FailureResourceLimitExceeded, "sandbox.control/v1 nesting exceeds the finite limit", RetryNever)
	}
	token, err := decoder.Token()
	if err != nil {
		return newFailure(FailureInvalidArgument, "sandbox.control/v1 contains invalid JSON", RetryNever)
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			seen := make(map[string]struct{})
			entries := 0
			for decoder.More() {
				entries++
				if entries > maxControlV1Collection {
					return newFailure(FailureResourceLimitExceeded, "sandbox.control/v1 object exceeds the finite entry limit", RetryNever)
				}
				key, err := decoder.Token()
				if err != nil {
					return newFailure(FailureInvalidArgument, "sandbox.control/v1 object key is invalid", RetryNever)
				}
				name, ok := key.(string)
				if !ok || name == "" {
					return newFailure(FailureInvalidArgument, "sandbox.control/v1 object key is invalid", RetryNever)
				}
				if _, duplicate := seen[name]; duplicate {
					return newFailure(FailureInvalidArgument, "sandbox.control/v1 contains a duplicate key", RetryNever)
				}
				seen[name] = struct{}{}
				if err := scanJSONValue(decoder, depth+1); err != nil {
					return err
				}
			}
			if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
				return newFailure(FailureInvalidArgument, "sandbox.control/v1 object is incomplete", RetryNever)
			}
		case '[':
			entries := 0
			for decoder.More() {
				entries++
				if entries > maxControlV1Collection {
					return newFailure(FailureResourceLimitExceeded, "sandbox.control/v1 array exceeds the finite entry limit", RetryNever)
				}
				if err := scanJSONValue(decoder, depth+1); err != nil {
					return err
				}
			}
			if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
				return newFailure(FailureInvalidArgument, "sandbox.control/v1 array is incomplete", RetryNever)
			}
		default:
			return newFailure(FailureInvalidArgument, "sandbox.control/v1 delimiter is invalid", RetryNever)
		}
	case json.Number:
		text := value.String()
		if strings.ContainsAny(text, ".eE") || strings.HasPrefix(text, "+") || (len(text) > 1 && text[0] == '0') || strings.HasPrefix(text, "-0") {
			return newFailure(FailureInvalidArgument, "sandbox.control/v1 number is not a canonical integer", RetryNever)
		}
	}
	return nil
}
