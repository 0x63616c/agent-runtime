// Package sandboxhostprocess composes the separately runnable reference host.
// It exercises protocol refusal and durability, not Linux/KVM isolation.
package sandboxhostprocess

import (
	"encoding/json"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"time"

	"github.com/cockroachdb/errors"
)

var environmentName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// Config is one validated immutable reference-host declaration.
type Config struct {
	controlURL                  string
	serverName                  string
	trustBundleFile             string
	clientCertificateFile       string
	clientPrivateKeyFile        string
	hostID                      string
	hostGeneration              uint64
	journalFile                 string
	maximumReceipts             int
	controlKeyID                string
	controlPublicKeyEnvironment string
	hostSigningKeyEnvironment   string
	requestTimeout              time.Duration
	testFaultAfterJournal       bool
	testFaultAfterReceipt       bool
	testFaultAfterResultSend    bool
}

type document struct {
	Version                     int    `json:"version"`
	ControlURL                  string `json:"control_url"`
	ServerName                  string `json:"server_name"`
	TrustBundleFile             string `json:"trust_bundle_file"`
	ClientCertificateFile       string `json:"client_certificate_file"`
	ClientPrivateKeyFile        string `json:"client_private_key_file"`
	HostID                      string `json:"host_id"`
	HostGeneration              uint64 `json:"host_generation"`
	JournalFile                 string `json:"journal_file"`
	MaximumReceipts             int    `json:"maximum_receipts"`
	ControlKeyID                string `json:"control_key_id"`
	ControlPublicKeyEnvironment string `json:"control_public_key_environment"`
	HostSigningKeyEnvironment   string `json:"host_signing_key_environment"`
	RequestTimeoutSeconds       uint32 `json:"request_timeout_seconds"`
	TestFaultAfterJournal       bool   `json:"test_fault_after_journal"`
	TestFaultAfterReceipt       bool   `json:"test_fault_after_receipt"`
	TestFaultAfterResultSend    bool   `json:"test_fault_after_result_send"`
}

// Parse decodes exactly one strict reference-host declaration.
func Parse(input io.Reader) (Config, error) {
	if input == nil {
		return Config{}, errors.New("parse sandbox-host configuration: input is required")
	}
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	var decoded document
	if err := decoder.Decode(&decoded); err != nil {
		return Config{}, errors.Wrap(err, "parse sandbox-host configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Config{}, errors.New("parse sandbox-host configuration: exactly one document is required")
	}
	endpoint, err := url.Parse(decoded.ControlURL)
	if decoded.Version != 1 || err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return Config{}, errors.New("validate sandbox-host configuration: version 1 and one HTTPS origin are required")
	}
	if decoded.ServerName == "" || decoded.HostID == "" || decoded.HostGeneration == 0 || decoded.ControlKeyID == "" || decoded.MaximumReceipts <= 0 || decoded.MaximumReceipts > 100000 {
		return Config{}, errors.New("validate sandbox-host configuration: bounded identity and receipt limit are required")
	}
	for _, path := range []string{decoded.TrustBundleFile, decoded.ClientCertificateFile, decoded.ClientPrivateKeyFile, decoded.JournalFile} {
		if !filepath.IsAbs(path) {
			return Config{}, errors.New("validate sandbox-host configuration: explicit absolute mounted paths are required")
		}
	}
	if decoded.ClientCertificateFile == decoded.ClientPrivateKeyFile || !environmentName.MatchString(decoded.ControlPublicKeyEnvironment) || !environmentName.MatchString(decoded.HostSigningKeyEnvironment) {
		return Config{}, errors.New("validate sandbox-host configuration: distinct TLS paths and secret environment references are required")
	}
	timeout := time.Duration(decoded.RequestTimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > time.Minute {
		return Config{}, errors.New("validate sandbox-host configuration: finite request timeout is required")
	}
	return Config{controlURL: decoded.ControlURL, serverName: decoded.ServerName, trustBundleFile: decoded.TrustBundleFile, clientCertificateFile: decoded.ClientCertificateFile, clientPrivateKeyFile: decoded.ClientPrivateKeyFile, hostID: decoded.HostID, hostGeneration: decoded.HostGeneration, journalFile: decoded.JournalFile, maximumReceipts: decoded.MaximumReceipts, controlKeyID: decoded.ControlKeyID, controlPublicKeyEnvironment: decoded.ControlPublicKeyEnvironment, hostSigningKeyEnvironment: decoded.HostSigningKeyEnvironment, requestTimeout: timeout, testFaultAfterJournal: decoded.TestFaultAfterJournal, testFaultAfterReceipt: decoded.TestFaultAfterReceipt, testFaultAfterResultSend: decoded.TestFaultAfterResultSend}, nil
}
