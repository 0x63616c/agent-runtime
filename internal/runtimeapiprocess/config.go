// Package runtimeapiprocess composes the separately runnable public API role from explicit operator configuration.
package runtimeapiprocess

import (
	"encoding/json"
	"io"
	"net"
	"regexp"

	"github.com/0x63616c/agent-runtime/internal/runtimeapi"
	"github.com/cockroachdb/errors"
)

var environmentName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// Config is a validated immutable runtime API process declaration.
type Config struct {
	listenAddress   string
	modelProfiles   []string
	maxRequestBytes int64
	principals      []principal
}

type document struct {
	Version         int                 `json:"version"`
	ListenAddress   string              `json:"listen_address"`
	Storage         storageDocument     `json:"storage"`
	ModelProfiles   []string            `json:"model_profiles"`
	MaxRequestBytes int64               `json:"max_request_bytes"`
	Principals      []principalDocument `json:"principals"`
}

type storageDocument struct {
	Mode string `json:"mode"`
}

type principalDocument struct {
	Tenant                 string `json:"tenant"`
	Principal              string `json:"principal"`
	Admin                  bool   `json:"admin"`
	BearerTokenEnvironment string `json:"bearer_token_environment"`
}

type principal struct {
	identity    runtimeapi.Identity
	environment string
}

// Parse decodes exactly one strict, versioned process declaration.
func Parse(input io.Reader) (Config, error) {
	if input == nil {
		return Config{}, errors.New("parse runtime API configuration: input is required")
	}
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	var decoded document
	if err := decoder.Decode(&decoded); err != nil {
		return Config{}, errors.Wrap(err, "parse runtime API configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Config{}, errors.New("parse runtime API configuration: exactly one document is required")
	}
	if decoded.Version != 1 {
		return Config{}, errors.New("validate runtime API configuration: version must be 1")
	}
	host, port, err := net.SplitHostPort(decoded.ListenAddress)
	if err != nil || port == "" || (host != "127.0.0.1" && host != "::1") {
		return Config{}, errors.New("validate runtime API configuration: listen_address must be an explicit loopback bind address")
	}
	if decoded.Storage.Mode != "memory-unsafe" {
		return Config{}, errors.New("validate runtime API configuration: storage mode must explicitly be memory-unsafe until a durable repository is available")
	}
	if len(decoded.ModelProfiles) == 0 || len(decoded.ModelProfiles) > 32 || decoded.MaxRequestBytes < 3<<20 || decoded.MaxRequestBytes > 16<<20 {
		return Config{}, errors.New("validate runtime API configuration: profiles and request bound are invalid")
	}
	if len(decoded.Principals) == 0 || len(decoded.Principals) > 256 {
		return Config{}, errors.New("validate runtime API configuration: at least one bounded principal is required")
	}
	principals := make([]principal, len(decoded.Principals))
	seen := make(map[string]struct{})
	for index, configured := range decoded.Principals {
		if configured.Tenant == "" || len(configured.Tenant) > 128 || configured.Principal == "" || len(configured.Principal) > 128 || !environmentName.MatchString(configured.BearerTokenEnvironment) {
			return Config{}, errors.New("validate runtime API configuration: principal is invalid")
		}
		key := configured.Tenant + "\x00" + configured.Principal
		if _, exists := seen[key]; exists {
			return Config{}, errors.New("validate runtime API configuration: principal is duplicated")
		}
		seen[key] = struct{}{}
		principals[index] = principal{identity: runtimeapi.Identity{Tenant: configured.Tenant, Principal: configured.Principal, Admin: configured.Admin}, environment: configured.BearerTokenEnvironment}
	}
	return Config{listenAddress: decoded.ListenAddress, modelProfiles: append([]string(nil), decoded.ModelProfiles...), maxRequestBytes: decoded.MaxRequestBytes, principals: principals}, nil
}
