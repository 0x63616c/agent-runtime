// Package runtimeoperations owns the protected operational-evidence drill.
// It is intentionally separate from the runtime data plane: its inputs are
// operator-provided capabilities and it never makes a production claim from a
// disposable run.
package runtimeoperations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	RunnerContract = "protected-runtime-operations-v1"
	SchemaVersion  = "agent-runtime.operations-evidence/v1"
)

// Config contains only the explicit protected-run authority. It is never
// marshalled into the retained report.
type Config struct {
	SourceDSN, RestoreDSN                   string
	AuditSinkURL, AuditRetentionURL         string
	RetentionTenant, RetentionAuthorization string
	PITRTenant, PITRAuthorization           string
	PITRRecoveryPoint, SourceRevision       string
	PITRExpectedGeneration                  int64
}

// Evidence is the redacted, schema-validated outcome of one actual protected
// run. It deliberately contains no DSN, endpoint, credential, or authority ID.
type Evidence struct {
	SchemaVersion  string            `json:"schema_version"`
	ProofLevel     string            `json:"proof_level"`
	Result         string            `json:"result"`
	OccurredAt     string            `json:"occurred_at"`
	SourceRevision string            `json:"source_revision"`
	Database       DatabaseEvidence  `json:"database"`
	AuditSink      AuditSinkEvidence `json:"audit_sink"`
	PITR           PITREvidence      `json:"pitr"`
	Limitations    []string          `json:"limitations"`
}

type DatabaseEvidence struct {
	AppRoleMember      bool `json:"app_role_member"`
	OperatorRoleMember bool `json:"operator_role_member"`
	RetentionScheduled bool `json:"retention_scheduled"`
	RetentionExecuted  bool `json:"retention_executed"`
	PartitionCount     int  `json:"partition_count"`
}

type AuditSinkEvidence struct {
	OutageStatus     int   `json:"outage_status"`
	RecoveryStatus   int   `json:"recovery_status"`
	RetentionSeconds int64 `json:"retention_seconds"`
}

type PITREvidence struct {
	ArchiveModeOn       bool   `json:"archive_mode_on"`
	SourcePrimary       bool   `json:"source_primary"`
	IsolatedTarget      bool   `json:"isolated_target"`
	RecoveredGeneration int64  `json:"recovered_generation"`
	RecoveryPoint       string `json:"recovery_point"`
}

// LoadConfig requires every protected-run capability. Missing authority is a
// refusal, not a blocked evidence artifact.
func LoadConfig(getenv func(string) string) (Config, error) {
	if getenv("RUNTIME_OPERATIONS_RUNNER_CONTRACT") != RunnerContract {
		return Config{}, errors.New("runtime operations drill: protected runner contract is absent")
	}
	config := Config{
		SourceDSN: getenv("AR_RUNTIME_OPERATIONS_DATABASE_DSN"), RestoreDSN: getenv("AR_RUNTIME_OPERATIONS_PITR_RESTORE_DSN"),
		AuditSinkURL: getenv("AR_RUNTIME_OPERATIONS_AUDIT_SINK_URL"), AuditRetentionURL: getenv("AR_RUNTIME_OPERATIONS_AUDIT_RETENTION_URL"),
		RetentionTenant: getenv("AR_RUNTIME_OPERATIONS_RETENTION_TENANT"), RetentionAuthorization: getenv("AR_RUNTIME_OPERATIONS_RETENTION_AUTHORIZATION_ID"),
		PITRTenant: getenv("AR_RUNTIME_OPERATIONS_PITR_TENANT"), PITRAuthorization: getenv("AR_RUNTIME_OPERATIONS_PITR_AUTHORIZATION_ID"),
		PITRRecoveryPoint: getenv("AR_RUNTIME_OPERATIONS_PITR_RECOVERY_POINT"), SourceRevision: getenv("GITHUB_SHA"),
	}
	if config.SourceRevision == "" {
		config.SourceRevision = getenv("AR_RUNTIME_OPERATIONS_SOURCE_REVISION")
	}
	generation, err := strconv.ParseInt(getenv("AR_RUNTIME_OPERATIONS_PITR_EXPECTED_GENERATION"), 10, 64)
	if err != nil || generation < 1 {
		return Config{}, errors.New("runtime operations drill: positive PITR expected generation is required")
	}
	config.PITRExpectedGeneration = generation
	for name, value := range map[string]string{
		"database DSN": config.SourceDSN, "PITR restore DSN": config.RestoreDSN, "audit sink URL": config.AuditSinkURL,
		"audit retention URL": config.AuditRetentionURL, "retention tenant": config.RetentionTenant,
		"retention authorization": config.RetentionAuthorization, "PITR tenant": config.PITRTenant,
		"PITR authorization": config.PITRAuthorization, "PITR recovery point": config.PITRRecoveryPoint,
		"source revision": config.SourceRevision,
	} {
		if strings.TrimSpace(value) == "" {
			return Config{}, fmt.Errorf("runtime operations drill: %s is required", name)
		}
	}
	if !validAuthorityID(config.RetentionAuthorization) || !validAuthorityID(config.PITRAuthorization) {
		return Config{}, errors.New("runtime operations drill: bounded authorization identifiers are required")
	}
	if !validTenant(config.RetentionTenant) || !validTenant(config.PITRTenant) {
		return Config{}, errors.New("runtime operations drill: bounded tenant identifiers are required")
	}
	if _, err := time.Parse(time.RFC3339, config.PITRRecoveryPoint); err != nil {
		return Config{}, errors.New("runtime operations drill: RFC3339 PITR recovery point is required")
	}
	if _, err := pgx.ParseConfig(config.SourceDSN); err != nil {
		return Config{}, errors.New("runtime operations drill: source database DSN is invalid")
	}
	if source, err := pgx.ParseConfig(config.SourceDSN); err == nil {
		restore, restoreErr := pgx.ParseConfig(config.RestoreDSN)
		if restoreErr != nil || source.Database == "" || restore.Database == "" || source.Database == restore.Database {
			return Config{}, errors.New("runtime operations drill: isolated PITR restore database is required")
		}
	}
	if !validHTTPS(config.AuditSinkURL) || !validHTTPS(config.AuditRetentionURL) {
		return Config{}, errors.New("runtime operations drill: explicit HTTPS audit URLs are required")
	}
	return config, nil
}

func validTenant(value string) bool {
	return len(value) >= 1 && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
func validAuthorityID(value string) bool {
	return len(value) >= 16 && len(value) <= 128 && !strings.ContainsAny(value, "\x00\r\n")
}
func validHTTPS(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

// Run verifies the operator-prepared, live controls. It fails before a report
// is written if any authorization, database observation, sink phase, or PITR
// recovery check cannot be observed through the supplied capabilities.
func Run(ctx context.Context, config Config) (Evidence, error) {
	source, err := pgxpool.New(ctx, config.SourceDSN)
	if err != nil {
		return Evidence{}, fmt.Errorf("open protected source database: %w", err)
	}
	defer source.Close()
	if err := source.Ping(ctx); err != nil {
		return Evidence{}, fmt.Errorf("ping protected source database: %w", err)
	}
	appMember, operatorMember, partitions, retentionExecuted, retentionScheduled, archiveModeOn, sourcePrimary, err := inspectSource(ctx, source, config)
	if err != nil {
		return Evidence{}, err
	}
	if !appMember || !operatorMember || !retentionScheduled || !retentionExecuted || partitions != 4 || !archiveModeOn || !sourcePrimary {
		return Evidence{}, errors.New("runtime operations drill: database authority or retention/PITR precondition was not observed")
	}
	outage, recovery, retention, err := inspectAuditSink(ctx, config)
	if err != nil {
		return Evidence{}, err
	}
	recovered, isolated, err := inspectRestore(ctx, config)
	if err != nil {
		return Evidence{}, err
	}
	if !isolated || recovered != config.PITRExpectedGeneration {
		return Evidence{}, errors.New("runtime operations drill: isolated PITR target did not contain the authorized expected generation")
	}
	return Evidence{
		SchemaVersion: SchemaVersion, ProofLevel: "protected_authorized_operational_drill", Result: "passed", OccurredAt: time.Now().UTC().Format(time.RFC3339), SourceRevision: config.SourceRevision,
		Database:    DatabaseEvidence{AppRoleMember: appMember, OperatorRoleMember: operatorMember, RetentionScheduled: retentionScheduled, RetentionExecuted: retentionExecuted, PartitionCount: partitions},
		AuditSink:   AuditSinkEvidence{OutageStatus: outage, RecoveryStatus: recovery, RetentionSeconds: retention},
		PITR:        PITREvidence{ArchiveModeOn: archiveModeOn, SourcePrimary: sourcePrimary, IsolatedTarget: isolated, RecoveredGeneration: recovered, RecoveryPoint: config.PITRRecoveryPoint},
		Limitations: []string{"This artifact records one protected authorized operational drill, not a perpetual production guarantee.", "No credentials, DSNs, audit endpoint, authority identifier, or tenant identifier are retained."},
	}, nil
}

func inspectSource(ctx context.Context, pool *pgxpool.Pool, config Config) (bool, bool, int, bool, bool, bool, bool, error) {
	var appMember, operatorMember bool
	if err := pool.QueryRow(ctx, `SELECT pg_has_role(current_user, 'runtime_state_app', 'member'), pg_has_role(current_user, 'runtime_state_operator', 'member')`).Scan(&appMember, &operatorMember); err != nil {
		return false, false, 0, false, false, false, false, fmt.Errorf("read protected role grants: %w", err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, false, 0, false, false, false, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE runtime_state_app`); err != nil {
		return false, false, 0, false, false, false, false, fmt.Errorf("assume protected app role: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('runtime.tenant_id', $1, true)`, config.RetentionTenant); err != nil {
		return false, false, 0, false, false, false, false, err
	}
	var last time.Time
	var next time.Time
	var authorization string
	if err := tx.QueryRow(ctx, `SELECT last_collection_at, next_collection_at, last_authorization_id FROM runtime.tenant_retention_jobs WHERE tenant_id = $1`, config.RetentionTenant).Scan(&last, &next, &authorization); err != nil {
		return false, false, 0, false, false, false, false, fmt.Errorf("read protected scheduled retention record: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, false, 0, false, false, false, false, err
	}
	operator, err := pool.Begin(ctx)
	if err != nil {
		return false, false, 0, false, false, false, false, err
	}
	defer func() { _ = operator.Rollback(ctx) }()
	if _, err := operator.Exec(ctx, `SET LOCAL ROLE runtime_state_operator`); err != nil {
		return false, false, 0, false, false, false, false, fmt.Errorf("assume protected operator role: %w", err)
	}
	var partitions int
	if err := operator.QueryRow(ctx, `SELECT count(*) FROM pg_inherits child JOIN pg_class parent ON child.inhparent = parent.oid JOIN pg_namespace namespace ON parent.relnamespace = namespace.oid WHERE namespace.nspname = 'runtime' AND parent.relname = 'runtime_state_snapshots'`).Scan(&partitions); err != nil {
		return false, false, 0, false, false, false, false, err
	}
	if err := operator.Commit(ctx); err != nil {
		return false, false, 0, false, false, false, false, err
	}
	var archiveMode, archiveCommand string
	var recovering bool
	if err := pool.QueryRow(ctx, `SELECT current_setting('archive_mode'), current_setting('archive_command'), pg_is_in_recovery()`).Scan(&archiveMode, &archiveCommand, &recovering); err != nil {
		return false, false, 0, false, false, false, false, fmt.Errorf("read protected WAL archive settings: %w", err)
	}
	retentionExecuted, retentionScheduled := retentionEvidence(last, next, authorization, config.RetentionAuthorization)
	return appMember, operatorMember, partitions, retentionExecuted, retentionScheduled, archiveMode == "on" && strings.TrimSpace(archiveCommand) != "", !recovering, nil
}

// retentionEvidence separates an observed completed collection from the
// independently scheduled next collection. A future schedule alone must never
// make protected-run evidence claim that retention was executed.
func retentionEvidence(last, next time.Time, authorization, expectedAuthorization string) (executed, scheduled bool) {
	scheduled = !next.IsZero() && (last.IsZero() || next.After(last))
	executed = scheduled && !last.IsZero() && authorization == expectedAuthorization
	return executed, scheduled
}

func inspectAuditSink(ctx context.Context, config Config) (int, int, int64, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	body := []byte(`{"schema_version":"agent-runtime.audit-drill/v1","kind":"protected.drill","redacted":true}`)
	post := func(mode string) (int, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, config.AuditSinkURL, bytes.NewReader(body))
		if err != nil {
			return 0, err
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Agent-Runtime-Drill-Mode", mode)
		response, err := client.Do(request)
		if err != nil {
			return 0, err
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return response.StatusCode, nil
	}
	outage, err := post("outage")
	if err != nil {
		return 0, 0, 0, fmt.Errorf("exercise configured audit-sink outage: %w", err)
	}
	if outage < 500 || outage > 599 {
		return 0, 0, 0, errors.New("runtime operations drill: audit sink did not reject the outage phase")
	}
	recovery, err := post("recovery")
	if err != nil {
		return 0, 0, 0, fmt.Errorf("exercise configured audit-sink recovery: %w", err)
	}
	if recovery < 200 || recovery > 299 {
		return 0, 0, 0, errors.New("runtime operations drill: audit sink did not accept the recovery phase")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, config.AuditRetentionURL, nil)
	if err != nil {
		return 0, 0, 0, err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("read configured audit-sink retention: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return 0, 0, 0, errors.New("runtime operations drill: audit retention endpoint rejected the probe")
	}
	var retention struct {
		SchemaVersion    string `json:"schema_version"`
		RetentionSeconds int64  `json:"retention_seconds"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&retention); err != nil || retention.SchemaVersion != "agent-runtime.audit-sink-retention/v1" || retention.RetentionSeconds < 1 {
		return 0, 0, 0, errors.New("runtime operations drill: audit retention response is invalid")
	}
	return outage, recovery, retention.RetentionSeconds, nil
}

func inspectRestore(ctx context.Context, config Config) (int64, bool, error) {
	restore, err := pgxpool.New(ctx, config.RestoreDSN)
	if err != nil {
		return 0, false, fmt.Errorf("open protected PITR restore target: %w", err)
	}
	defer restore.Close()
	if err := restore.Ping(ctx); err != nil {
		return 0, false, fmt.Errorf("ping protected PITR restore target: %w", err)
	}
	tx, err := restore.Begin(ctx)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE runtime_state_app`); err != nil {
		return 0, false, fmt.Errorf("assume restore app role: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('runtime.tenant_id', $1, true)`, config.PITRTenant); err != nil {
		return 0, false, err
	}
	var generation int64
	if err := tx.QueryRow(ctx, `SELECT generation FROM runtime.runtime_state_snapshots WHERE tenant_id = $1`, config.PITRTenant).Scan(&generation); err != nil {
		return 0, false, fmt.Errorf("read authorized PITR tenant state: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, false, err
	}
	sourceConfig, _ := pgx.ParseConfig(config.SourceDSN)
	restoreConfig, _ := pgx.ParseConfig(config.RestoreDSN)
	return generation, sourceConfig.Database != restoreConfig.Database, nil
}

// Validate checks the retained schema before a report is written or accepted.
func (evidence Evidence) Validate() error {
	if evidence.SchemaVersion != SchemaVersion || evidence.ProofLevel != "protected_authorized_operational_drill" || evidence.Result != "passed" || evidence.SourceRevision == "" {
		return errors.New("validate operational evidence: required identity is invalid")
	}
	if _, err := time.Parse(time.RFC3339, evidence.OccurredAt); err != nil {
		return errors.New("validate operational evidence: occurred_at is invalid")
	}
	if !evidence.Database.AppRoleMember || !evidence.Database.OperatorRoleMember || !evidence.Database.RetentionScheduled || !evidence.Database.RetentionExecuted || evidence.Database.PartitionCount != 4 {
		return errors.New("validate operational evidence: database proof is incomplete")
	}
	if evidence.AuditSink.OutageStatus < 500 || evidence.AuditSink.OutageStatus > 599 || evidence.AuditSink.RecoveryStatus < 200 || evidence.AuditSink.RecoveryStatus > 299 || evidence.AuditSink.RetentionSeconds < 1 {
		return errors.New("validate operational evidence: audit sink proof is incomplete")
	}
	if !evidence.PITR.ArchiveModeOn || !evidence.PITR.SourcePrimary || !evidence.PITR.IsolatedTarget || evidence.PITR.RecoveredGeneration < 1 {
		return errors.New("validate operational evidence: PITR proof is incomplete")
	}
	if _, err := time.Parse(time.RFC3339, evidence.PITR.RecoveryPoint); err != nil {
		return errors.New("validate operational evidence: recovery point is invalid")
	}
	if len(evidence.Limitations) == 0 {
		return errors.New("validate operational evidence: limitations are required")
	}
	return nil
}

// WriteEvidence creates a report only after a successful validated run. It
// never replaces an earlier artifact, preventing a local retry from masking a
// protected-run record.
func WriteEvidence(path string, evidence Evidence) error {
	if err := evidence.Validate(); err != nil {
		return err
	}
	if path == "" || filepath.Dir(path) == "." && filepath.Base(path) == "." {
		return errors.New("write operational evidence: report path is required")
	}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write operational evidence: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write operational evidence: %w", err)
	}
	return nil
}

// ReadEvidence parses and validates a retained artifact without connecting to
// any external system.
func ReadEvidence(path string) (Evidence, error) {
	file, err := os.Open(path)
	if err != nil {
		return Evidence{}, err
	}
	defer file.Close()
	var evidence Evidence
	decoder := json.NewDecoder(io.LimitReader(file, 64*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil {
		return Evidence{}, err
	}
	if err := evidence.Validate(); err != nil {
		return Evidence{}, err
	}
	return evidence, nil
}
