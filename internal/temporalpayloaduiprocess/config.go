// Package temporalpayloaduiprocess composes the local Temporal UI payload-inspection handler from explicit policy.
package temporalpayloaduiprocess

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
)

const (
	maximumConfigBytes      = 16 << 10
	maximumPolicyEntries    = 64
	maximumPolicyValueBytes = 512
	maximumBlobBytes        = 1 << 30
)

// Config is a validated immutable Temporal UI payload-inspection policy.
type Config struct {
	blobPrefix       string
	maximumBlobBytes int
	ioTimeout        time.Duration
	namespaces       []string
	origins          []string
}

type document struct {
	Version               int      `json:"version"`
	BlobPrefix            string   `json:"blob_prefix"`
	MaximumBlobBytes      int      `json:"maximum_blob_bytes"`
	IOTimeoutMilliseconds int64    `json:"io_timeout_milliseconds"`
	TemporalUINamespaces  []string `json:"temporal_ui_namespaces"`
	TemporalUIOrigins     []string `json:"temporal_ui_origins"`
}

// Parse decodes one strict, bounded versioned Temporal UI inspection policy.
func Parse(input io.Reader) (Config, error) {
	if input == nil {
		return Config{}, errors.New("parse Temporal UI payload configuration: input is required")
	}
	encoded, err := io.ReadAll(io.LimitReader(input, maximumConfigBytes+1))
	if err != nil {
		return Config{}, errors.Wrap(err, "parse Temporal UI payload configuration")
	}
	if len(encoded) > maximumConfigBytes {
		return Config{}, errors.New("parse Temporal UI payload configuration: document exceeds the supported bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var decoded document
	if err := decoder.Decode(&decoded); err != nil {
		return Config{}, errors.Wrap(err, "parse Temporal UI payload configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Config{}, errors.New("parse Temporal UI payload configuration: exactly one document is required")
	}
	if decoded.Version != 1 {
		return Config{}, errors.New("validate Temporal UI payload configuration: version must be 1")
	}
	prefix, err := validateBlobPrefix(decoded.BlobPrefix)
	if err != nil {
		return Config{}, errors.Wrap(err, "validate Temporal UI payload configuration")
	}
	if decoded.MaximumBlobBytes <= 0 || decoded.MaximumBlobBytes > maximumBlobBytes {
		return Config{}, errors.New("validate Temporal UI payload configuration: maximum blob bytes is outside the supported bound")
	}
	if decoded.IOTimeoutMilliseconds <= 0 || decoded.IOTimeoutMilliseconds > int64(time.Minute/time.Millisecond) {
		return Config{}, errors.New("validate Temporal UI payload configuration: I/O timeout is outside the supported bound")
	}
	namespaces, err := validateNamespaces(decoded.TemporalUINamespaces)
	if err != nil {
		return Config{}, errors.Wrap(err, "validate Temporal UI payload configuration")
	}
	origins, err := validateOrigins(decoded.TemporalUIOrigins)
	if err != nil {
		return Config{}, errors.Wrap(err, "validate Temporal UI payload configuration")
	}
	return Config{
		blobPrefix:       prefix,
		maximumBlobBytes: decoded.MaximumBlobBytes,
		ioTimeout:        time.Duration(decoded.IOTimeoutMilliseconds) * time.Millisecond,
		namespaces:       namespaces,
		origins:          origins,
	}, nil
}

func validateBlobPrefix(value string) (string, error) {
	value = strings.TrimSuffix(value, "/")
	if value == "" || len(value) > maximumPolicyValueBytes || path.Clean(value) != value || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") {
		return "", errors.New("blob prefix is invalid")
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("blob prefix is invalid")
		}
	}
	return value, nil
}

func validateNamespaces(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > maximumPolicyEntries {
		return nil, errors.New("Temporal UI namespaces must be nonempty and bounded")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || len(value) > maximumPolicyValueBytes {
			return nil, errors.New("Temporal UI namespace is invalid")
		}
		if _, found := seen[value]; found {
			return nil, errors.New("Temporal UI namespace is duplicated")
		}
		seen[value] = struct{}{}
	}
	return slices.Clone(values), nil
}

func validateOrigins(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > maximumPolicyEntries {
		return nil, errors.New("Temporal UI origins must be nonempty and bounded")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if len(value) > maximumPolicyValueBytes {
			return nil, errors.New("Temporal UI origin is invalid")
		}
		origin, err := url.ParseRequestURI(value)
		if err != nil || origin.Scheme == "" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || (origin.Scheme != "http" && origin.Scheme != "https") {
			return nil, errors.New("Temporal UI origin is invalid")
		}
		if _, found := seen[value]; found {
			return nil, errors.New("Temporal UI origin is duplicated")
		}
		seen[value] = struct{}{}
	}
	return slices.Clone(values), nil
}
