package sandboxhostbootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/0x63616c/agent-runtime/internal/sandboxcontrol"
	"github.com/0x63616c/agent-runtime/internal/sandboxhostprotocol"
	"github.com/cockroachdb/errors"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SecretLookup resolves only an explicit already-mounted database value.
type SecretLookup func(string) (string, bool)

// Run opens the existing ledger and creates or proves the exact enrollment.
// It never migrates a database, writes secret files, starts a host or logs
// configuration material.
func Run(ctx context.Context, config Config, lookup SecretLookup) error {
	if ctx == nil || lookup == nil {
		return errors.New("run sandbox-host bootstrap: context and secret lookup are required")
	}
	dsn, ok := lookup(config.databaseDSNEnvironment)
	if !ok || dsn == "" {
		return errors.New("run sandbox-host bootstrap: required database configuration is unavailable")
	}
	certificate, err := readLeafCertificate(config.certificateFile)
	if err != nil {
		return err
	}
	if err := verifyCertificateIdentity(certificate, config.hostID, config.generation); err != nil {
		return err
	}
	signingKey, err := readSigningKey(config.signingKeyFile)
	if err != nil {
		return err
	}
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return errors.New("run sandbox-host bootstrap: database configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.Wrap(err, "run sandbox-host bootstrap: open database")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.Wrap(err, "run sandbox-host bootstrap: ping database")
	}
	ledger, err := sandboxcontrol.NewPostgresLedger(pool)
	if err != nil {
		return errors.Wrap(err, "run sandbox-host bootstrap: open sandbox ledger")
	}
	digest := sha256.Sum256(certificate.Raw)
	enrollment := sandboxcontrol.HostEnrollment{HostID: config.hostID, Tenant: config.tenant, Pool: config.pool, Generation: config.generation, ProtocolVersion: sandboxhostprotocol.Version, CertificateDigest: "sha256:" + hex.EncodeToString(digest[:]), SigningPublicKey: signingKey.Public().(ed25519.PublicKey), CapabilityDigest: config.capabilityDigest, Status: sandboxcontrol.HostActive, ExpiresAt: config.expiresAt}
	if err := ledger.ProvisionHost(ctx, enrollment, sandboxcontrol.AttestationInput{Profile: sandboxcontrol.AttestationProfileLocalMetadata}, nil); err != nil {
		return errors.Wrap(err, "run sandbox-host bootstrap: provision mounted host identity")
	}
	return nil
}

func readLeafCertificate(path string) (*x509.Certificate, error) {
	wire, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "read sandbox-host bootstrap certificate")
	}
	block, trailing := pem.Decode(wire)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("read sandbox-host bootstrap certificate: PEM leaf certificate is required")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "read sandbox-host bootstrap certificate")
	}
	for len(trailing) != 0 {
		block, trailing = pem.Decode(trailing)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("read sandbox-host bootstrap certificate: certificate chain contains invalid PEM")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, errors.Wrap(err, "read sandbox-host bootstrap certificate chain")
		}
	}
	return certificate, nil
}

func readSigningKey(path string) (ed25519.PrivateKey, error) {
	wire, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "read sandbox-host bootstrap signing key")
	}
	decoded, err := base64.RawStdEncoding.DecodeString(string(wire))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("read sandbox-host bootstrap signing key: one base64 raw Ed25519 private key is required")
	}
	return ed25519.PrivateKey(decoded), nil
}

func verifyCertificateIdentity(certificate *x509.Certificate, hostID string, generation uint64) error {
	if certificate == nil || len(certificate.URIs) != 1 || certificate.URIs[0].String() != "spiffe://agent-runtime/sandbox-host/"+hostID+"/generation/"+itoa(generation) {
		return errors.New("read sandbox-host bootstrap certificate: mounted mTLS identity does not match host configuration")
	}
	return nil
}

func itoa(value uint64) string {
	return fmt.Sprintf("%d", value)
}
