// Package sandboxhostbootstrap enrolls one already-mounted local or CI host
// identity in the sandbox control ledger. It deliberately has no production
// profile: production enrollment remains an external operator authority.
package sandboxhostbootstrap

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"regexp"
	"time"

	"github.com/cockroachdb/errors"
)

const maxConfigurationBytes = 16 << 10

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var environmentName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// Config is the strict, non-secret declaration for a one-shot bootstrap.
type Config struct {
	databaseDSNEnvironment string
	hostID                 string
	tenant                 string
	pool                   string
	generation             uint64
	certificateFile        string
	signingKeyFile         string
	capabilityDigest       string
	expiresAt              time.Time
}

type document struct {
	Version                int       `json:"version"`
	DatabaseDSNEnvironment string    `json:"database_dsn_environment"`
	HostID                 string    `json:"host_id"`
	Tenant                 string    `json:"tenant"`
	Pool                   string    `json:"pool"`
	Generation             uint64    `json:"generation"`
	CertificateFile        string    `json:"certificate_file"`
	SigningKeyFile         string    `json:"signing_key_file"`
	CapabilityDigest       string    `json:"capability_digest"`
	ExpiresAt              time.Time `json:"expires_at"`
}

// Parse decodes exactly one strict local/CI bootstrap declaration.
func Parse(input io.Reader) (Config, error) {
	if input == nil {
		return Config{}, errors.New("parse sandbox-host bootstrap configuration: input is required")
	}
	wire, err := io.ReadAll(io.LimitReader(input, maxConfigurationBytes+1))
	if err != nil || len(wire) == 0 || len(wire) > maxConfigurationBytes {
		return Config{}, errors.New("parse sandbox-host bootstrap configuration: bounded input is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var decoded document
	if err := decoder.Decode(&decoded); err != nil {
		return Config{}, errors.Wrap(err, "parse sandbox-host bootstrap configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Config{}, errors.New("parse sandbox-host bootstrap configuration: exactly one document is required")
	}
	if decoded.Version != 1 || !environmentName.MatchString(decoded.DatabaseDSNEnvironment) || !identifier.MatchString(decoded.HostID) || !identifier.MatchString(decoded.Tenant) || !identifier.MatchString(decoded.Pool) || decoded.Generation == 0 || !filepath.IsAbs(decoded.CertificateFile) || !filepath.IsAbs(decoded.SigningKeyFile) || decoded.CertificateFile == decoded.SigningKeyFile || !validDigest(decoded.CapabilityDigest) || decoded.ExpiresAt.IsZero() || decoded.ExpiresAt.Location() != time.UTC {
		return Config{}, errors.New("validate sandbox-host bootstrap configuration: explicit local/CI identity, mounted files, capability and UTC expiry are required")
	}
	return Config{databaseDSNEnvironment: decoded.DatabaseDSNEnvironment, hostID: decoded.HostID, tenant: decoded.Tenant, pool: decoded.Pool, generation: decoded.Generation, certificateFile: decoded.CertificateFile, signingKeyFile: decoded.SigningKeyFile, capabilityDigest: decoded.CapabilityDigest, expiresAt: decoded.ExpiresAt}, nil
}

func validDigest(value string) bool {
	return len(value) > len("sha256:") && len(value) <= 128 && regexp.MustCompile(`^sha256:[a-f0-9]+$`).MatchString(value)
}
