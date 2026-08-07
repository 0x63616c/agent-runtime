// Package milestone builds retained status evidence and notification attempts.
package milestone

import "time"

// RequirementID is a permanent binding requirement identifier.
type RequirementID string

// MilestoneID is a bounded operator-facing milestone name.
type MilestoneID string

// RevisionRef is a bounded immutable source revision reference.
type RevisionRef string

// CommandID identifies a reviewed verification command without embedding argv.
type CommandID string

// ArtifactRef identifies retained evidence without embedding a storage URL.
type ArtifactRef string

// EvidenceRef identifies bounded, caller-safe status evidence.
type EvidenceRef string

// RequirementStatus classifies the evidence state of a binding requirement.
type RequirementStatus string

const (
	// RequirementCompleted means the requirement has retained passing evidence.
	RequirementCompleted RequirementStatus = "completed"
	// RequirementInProgress means implementation or evidence work has started.
	RequirementInProgress RequirementStatus = "in_progress"
	// RequirementBlocked means a named external condition prevents progress.
	RequirementBlocked RequirementStatus = "blocked"
	// RequirementNotStarted means implementation evidence does not yet exist.
	RequirementNotStarted RequirementStatus = "not_started"
)

// ProofLevel describes the scope of retained evidence.
type ProofLevel string

const (
	// ProofUnit identifies deterministic unit or property evidence.
	ProofUnit ProofLevel = "unit"
	// ProofWorkflow identifies deterministic orchestration and replay evidence.
	ProofWorkflow ProofLevel = "workflow"
	// ProofContract identifies black-box interface or adapter conformance evidence.
	ProofContract ProofLevel = "contract"
	// ProofIntegration identifies a real dependency integration result.
	ProofIntegration ProofLevel = "integration"
	// ProofLocalTiltE2E identifies a complete local-stack public-path result.
	ProofLocalTiltE2E ProofLevel = "local_tilt_e2e"
	// ProofLinuxKVME2E identifies Linux/KVM security or Firecracker evidence.
	ProofLinuxKVME2E ProofLevel = "linux_kvm_e2e"
	// ProofManual identifies retained operator evidence that cannot be automated.
	ProofManual ProofLevel = "manual"
	// ProofDocumentation identifies published or generated documentation evidence.
	ProofDocumentation ProofLevel = "documentation"
	// ProofIndependentReview identifies an independent standards or spec review.
	ProofIndependentReview ProofLevel = "independent_review"
	// ProofRelease identifies immutable release or main-delivery evidence.
	ProofRelease ProofLevel = "release"
	// ProofMainCI identifies a required main-branch CI result for an immutable revision.
	ProofMainCI ProofLevel = "main_ci"
)

// Proof is a bounded, secret-safe reference to one retained verification result.
type Proof struct {
	// Revision identifies the immutable source state checked.
	Revision RevisionRef `json:"revision"`
	// UTCTime records when the check completed in UTC.
	UTCTime time.Time `json:"utc_time"`
	// Level identifies the proof scope.
	Level ProofLevel `json:"proof_level"`
	// CommandID identifies reviewed argv stored outside this record.
	CommandID CommandID `json:"command_id"`
	// ArtifactRef identifies the retained machine-readable result.
	ArtifactRef ArtifactRef `json:"artifact_ref"`
	// Result is completed only when its literal value is passed.
	Result string `json:"result"`
}

// Requirement is one requirement evidence state from a ledger snapshot.
type Requirement struct {
	// ID is the permanent requirement identifier.
	ID RequirementID `json:"id"`
	// Status is the current evidence state.
	Status RequirementStatus `json:"status"`
	// Evidence contains retained proof references for completed status.
	Evidence []Proof `json:"evidence,omitempty"`
}

// Ledger is a versioned evidence snapshot; it cannot supply weights itself.
type Ledger struct {
	// Version selects the ledger schema.
	Version int `json:"version"`
	// Requirements contains exactly one row per canonical requirement.
	Requirements []Requirement `json:"requirements"`
}

// CatalogRequirement assigns one permanent requirement to an owning milestone and weight.
type CatalogRequirement struct {
	// ID is the permanent requirement identifier.
	ID RequirementID `json:"id"`
	// Milestone is the explicit owner sourced from the work map.
	Milestone MilestoneID `json:"milestone"`
	// Weight is the positive contribution to the overall estimate.
	Weight int `json:"weight"`
}

// Catalog is the complete canonical weighted requirement register.
type Catalog struct {
	// Version selects the catalog schema.
	Version int `json:"version"`
	// Requirements contains the complete generated ownership register.
	Requirements []CatalogRequirement `json:"requirements"`
}

// Status classifies an overall milestone report without overstating completion.
type Status string

const (
	// StatusCompleted means every canonical requirement has green evidence.
	StatusCompleted Status = "completed"
	// StatusInProgress means unfinished work exists without an active blocker.
	StatusInProgress Status = "in_progress"
	// StatusBlocked means at least one canonical requirement is blocked.
	StatusBlocked Status = "blocked"
)

// EvidenceKind classifies an entry within the notifier evidence_summary field.
type EvidenceKind string

const (
	// EvidenceCompleted identifies a completed requirement.
	EvidenceCompleted EvidenceKind = "completed"
	// EvidenceInProgress identifies an in-progress or not-started requirement.
	EvidenceInProgress EvidenceKind = "in_progress"
	// EvidenceBlocked identifies a blocked requirement.
	EvidenceBlocked EvidenceKind = "blocked"
	// EvidenceUncertainty identifies bounded uncertainty or a missing proof condition.
	EvidenceUncertainty EvidenceKind = "uncertainty"
)

// EvidenceReference is a structured, bounded status entry; it never contains raw output.
type EvidenceReference struct {
	// Kind describes how the reference contributes to status.
	Kind EvidenceKind `json:"kind"`
	// Reference is a bounded safe requirement or uncertainty reference.
	Reference EvidenceRef `json:"reference"`
}

// ReportInput supplies safe operator-facing context for a status report.
type ReportInput struct {
	// Milestone identifies the current milestone.
	Milestone MilestoneID
	// NextMilestone identifies the next observable milestone.
	NextMilestone MilestoneID
	// Revision identifies the immutable source state when available.
	Revision RevisionRef
	// TerminalRequirementIDs names the bounded requirement rows that decide this milestone's status.
	TerminalRequirementIDs []RequirementID
	// Uncertainty names bounded missing proof or external conditions.
	Uncertainty []EvidenceReference
}

// Report is the exact seven-field notifier transport schema from ADR-0007.
type Report struct {
	// Milestone identifies the reported milestone.
	Milestone MilestoneID `json:"milestone"`
	// EstimatedOverallPercent is the weighted green share of all requirements.
	EstimatedOverallPercent int `json:"estimated_overall_percent"`
	// EvidenceSummary carries structured completed, in-progress, blocked, and uncertainty entries.
	EvidenceSummary []EvidenceReference `json:"evidence_summary"`
	// NextMilestone identifies the next observable milestone.
	NextMilestone MilestoneID `json:"next_milestone"`
	// CommitOrRevision identifies the immutable source state.
	CommitOrRevision RevisionRef `json:"commit_or_revision"`
	// UTCTime is the injected report time normalized to UTC.
	UTCTime time.Time `json:"utc_time"`
	// Status summarizes the most severe evidence state.
	Status Status `json:"status"`
}

// Estimate is retained evidence context, deliberately separate from notifier transport.
type Estimate struct {
	// Completed lists requirements with retained passing evidence.
	Completed []RequirementID `json:"completed"`
	// InProgress lists in-progress and not-started requirements.
	InProgress []RequirementID `json:"in_progress"`
	// Blocked lists requirements with a named blocker.
	Blocked []RequirementID `json:"blocked"`
	// Uncertainty lists bounded missing-proof conditions.
	Uncertainty []EvidenceReference `json:"uncertainty"`
}

// Delivery records the observable delivery state of retained milestone evidence.
type Delivery string

const (
	// DeliveryPending means evidence is retained and delivery has not succeeded.
	DeliveryPending Delivery = "pending"
	// DeliveryFailed means delivery failed and remains retryable.
	DeliveryFailed Delivery = "failed"
	// DeliverySent means the configured notifier accepted the report.
	DeliverySent Delivery = "sent"
)

// FailureCode is a safe classified notifier failure, never provider error text.
type FailureCode string

const (
	// FailureUnavailable means the notifier was temporarily unavailable.
	FailureUnavailable FailureCode = "unavailable"
	// FailureRejected means the notifier rejected a validly shaped delivery request.
	FailureRejected FailureCode = "rejected"
	// FailureUnclassified means an adapter returned an untyped failure.
	FailureUnclassified FailureCode = "unclassified"
)

// Record retains a transport report, rich estimate, and secret-safe delivery state.
type Record struct {
	// Report is the exact notifier payload.
	Report Report `json:"report"`
	// Estimate retains richer local evidence context.
	Estimate Estimate `json:"estimate"`
	// Delivery is the current notifier delivery state.
	Delivery Delivery `json:"delivery"`
	// Attempts counts recorded notifier outcomes.
	Attempts int `json:"attempts"`
	// Failure is the last safe classified failure.
	Failure FailureCode `json:"failure,omitempty"`
}
