// Command milestone-notify retains and sends the bounded M0 completion report.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/0x63616c/agent-runtime/internal/clock"
	"github.com/0x63616c/agent-runtime/internal/milestone"
	"github.com/0x63616c/agent-runtime/internal/runtimeconfig"
	"github.com/cockroachdb/errors"
)

var expectedM0TerminalRequirements = []milestone.RequirementID{"DOC-005", "DOC-008", "MON-004", "MON-005", "MON-006", "MON-007", "MON-008"}

func main() {
	if err := run(os.Args[1:], os.Stdout, wallClock{}, &http.Client{Timeout: 15 * time.Second}, os.LookupEnv); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer, source clock.Clock, client milestone.HTTPClient, lookupEnv func(string) (string, bool)) error {
	flags := flag.NewFlagSet("milestone-notify", flag.ContinueOnError)
	flags.SetOutput(output)
	var catalogPath, ledgerPath, recordDirectory, revision, tokenEnvironment, uncertainty string
	var retry bool
	flags.StringVar(&catalogPath, "catalog", "", "path to the complete canonical requirement catalog JSON file")
	flags.StringVar(&ledgerPath, "ledger", "", "path to the complete canonical evidence ledger JSON file")
	flags.StringVar(&recordDirectory, "record-dir", "", "private directory for durable milestone delivery records")
	flags.StringVar(&revision, "revision", "", "immutable source revision for this report")
	flags.StringVar(&tokenEnvironment, "access-token-env", "NTFY_ACCESS_TOKEN", "environment variable containing an optional ntfy access token")
	flags.StringVar(&uncertainty, "uncertainty", "", "comma-separated bounded uncertainty references")
	flags.BoolVar(&retry, "retry", false, "retry an existing retained failed delivery instead of creating a new record")
	if err := flags.Parse(arguments); err != nil {
		return errors.Wrap(err, "parse milestone notification arguments")
	}
	if catalogPath == "" || ledgerPath == "" || recordDirectory == "" || revision == "" {
		return errors.New("milestone notification requires -catalog, -ledger, -record-dir, and -revision")
	}
	if source == nil || client == nil || lookupEnv == nil {
		return errors.New("milestone notification requires clock, HTTP client, and environment lookup")
	}
	catalogData, err := os.ReadFile(catalogPath)
	if err != nil {
		return errors.Wrap(err, "read milestone catalog")
	}
	catalog, err := milestone.ParseCatalog(bytes.NewReader(catalogData))
	if err != nil {
		return errors.Wrap(err, "parse milestone catalog")
	}
	ledgerData, err := os.ReadFile(ledgerPath)
	if err != nil {
		return errors.Wrap(err, "read milestone ledger")
	}
	ledger, err := milestone.ParseLedger(bytes.NewReader(ledgerData))
	if err != nil {
		return errors.Wrap(err, "parse milestone ledger")
	}
	required, err := m0TerminalRequirements(catalog)
	if err != nil {
		return err
	}
	uncertainties, err := splitUncertainty(uncertainty)
	if err != nil {
		return err
	}
	token, _ := lookupEnv(tokenEnvironment)
	config, err := runtimeconfig.New(runtimeconfig.Input{Version: 1, Notifier: runtimeconfig.NotifierInput{AccessToken: token}})
	if err != nil {
		return errors.Wrap(err, "create notifier configuration")
	}
	store, err := milestone.NewFileStore(recordDirectory)
	if err != nil {
		return err
	}
	notifier, err := milestone.NewNtfyNotifier(client)
	if err != nil {
		return err
	}
	config.Notifier.ApplyAuthorization(notifier)
	service, err := milestone.NewService(config.Notifier, source, store, notifier)
	if err != nil {
		return err
	}
	input := milestone.ReportInput{
		Milestone:              "M0 foundation",
		NextMilestone:          "M1 isolated Tilt environment",
		Revision:               milestone.RevisionRef(revision),
		TerminalRequirementIDs: required,
		Uncertainty:            uncertainties,
	}
	var record milestone.Record
	if retry {
		record, err = service.Retry(context.Background(), input.Milestone)
	} else {
		record, err = service.Publish(context.Background(), catalog, ledger, input)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Milestone milestone.MilestoneID `json:"milestone"`
		Status    milestone.Status      `json:"status"`
		Delivery  milestone.Delivery    `json:"delivery"`
		Attempts  int                   `json:"attempts"`
	}{Milestone: record.Report.Milestone, Status: record.Report.Status, Delivery: record.Delivery, Attempts: record.Attempts})
}

func m0TerminalRequirements(catalog milestone.Catalog) ([]milestone.RequirementID, error) {
	actual := make([]milestone.RequirementID, 0, len(expectedM0TerminalRequirements))
	for _, requirement := range catalog.Requirements {
		if requirement.Milestone == "M0" {
			actual = append(actual, requirement.ID)
		}
	}
	sort.Slice(actual, func(left, right int) bool { return actual[left] < actual[right] })
	if len(actual) != len(expectedM0TerminalRequirements) {
		return nil, errors.New("validate M0 terminal requirements: catalog ownership mismatch")
	}
	for index, requirement := range expectedM0TerminalRequirements {
		if actual[index] != requirement {
			return nil, errors.New("validate M0 terminal requirements: catalog ownership mismatch")
		}
	}
	return append([]milestone.RequirementID(nil), actual...), nil
}

func splitUncertainty(value string) ([]milestone.EvidenceReference, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	result := make([]milestone.EvidenceReference, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errors.New("parse report uncertainty: reference is required")
		}
		result = append(result, milestone.EvidenceReference{Kind: milestone.EvidenceUncertainty, Reference: milestone.EvidenceRef(part)})
	}
	return result, nil
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now().UTC() }
