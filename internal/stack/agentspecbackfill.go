package stack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfillcrd"
	"github.com/cockroachdb/errors"
)

// StaticAgentSpecBackfillV1 is the optional, immutable render-only declaration of the static backfill control plane.
type StaticAgentSpecBackfillV1 struct {
	// Version is the sole supported declaration version.
	Version int `json:"version"`
	// CRDDigest pins the exact generated AgentSpecBackfill CRD declaration.
	CRDDigest string `json:"crd_digest"`
	// Controller pins the controller process image, argv, configuration digest, and finite resources.
	Controller StaticAgentSpecBackfillController `json:"controller"`
	// Identities fixes the only controller and limited-operator Kubernetes identities.
	Identities StaticAgentSpecBackfillIdentities `json:"identities"`
	// Routes is the complete explicit Kubernetes API, database, blob, and optional DNS egress set.
	Routes []StaticAgentSpecBackfillRoute `json:"routes"`
	// RBAC pins the reviewed controller and limited-operator role/binding declarations.
	RBAC StaticAgentSpecBackfillRBAC `json:"rbac"`
	// Credentials pins non-secret credential-reference and capability declarations.
	Credentials StaticAgentSpecBackfillCredentials `json:"credentials"`
	// EvidenceRetentionDays is the finite terminal-evidence retention period.
	EvidenceRetentionDays int `json:"evidence_retention_days"`
	// TeardownInventory is the complete static resource inventory for declarative teardown.
	TeardownInventory []string `json:"teardown_inventory"`
	// Inventory supplies every explicit non-secret authority fact required by the static inventory compiler.
	Inventory *StaticAgentSpecBackfillInventoryV1 `json:"inventory,omitempty"`
}

// StaticAgentSpecBackfillInventoryV1 names the explicit authority facts for one non-applying static inventory.
// It deliberately declares rather than infers profile, cluster ownership, identities, routes, and UID handoff.
type StaticAgentSpecBackfillInventoryV1 struct {
	// Profile binds the inventory to one reviewed Stack profile.
	Profile Profile `json:"profile"`
	// ClusterOwnership identifies the separately declared owner of cluster-scoped static resources.
	ClusterOwnership StaticAgentSpecBackfillClusterOwnership `json:"cluster_ownership"`
	// ControllerIdentity declares the controller subject, reference, and least-privilege rules.
	ControllerIdentity StaticAgentSpecBackfillIdentity `json:"controller_identity"`
	// OperatorIdentity declares the request-creator subject, reference, and least-privilege rules.
	OperatorIdentity StaticAgentSpecBackfillIdentity `json:"operator_identity"`
	// LifecycleIdentity declares the distinct read-only readiness observer.
	LifecycleIdentity StaticAgentSpecBackfillLifecycleIdentity `json:"lifecycle_identity"`
	// ArchiveIdentity declares the distinct retained-evidence exporter.
	ArchiveIdentity StaticAgentSpecBackfillArchiveIdentity `json:"archive_identity"`
	// Admission pins the static validating policy and binding that fence request mutation authority.
	Admission StaticAgentSpecBackfillAdmission `json:"admission"`
	// RuntimeTarget declares the runtime namespace and an explicit later UID-bound ingress handoff.
	RuntimeTarget StaticAgentSpecBackfillRuntimeTarget `json:"runtime_target"`
}

// StaticAgentSpecBackfillClusterOwnership identifies a declared cluster-scoped authority without choosing one.
type StaticAgentSpecBackfillClusterOwnership struct {
	Owner           string `json:"owner"`
	AuthorityDigest string `json:"authority_digest"`
}

// StaticAgentSpecBackfillIdentity declares one explicit Kubernetes or external identity and narrow rules.
type StaticAgentSpecBackfillIdentity struct {
	SubjectKind               string       `json:"subject_kind"`
	Subject                   string       `json:"subject"`
	Namespace                 string       `json:"namespace"`
	CredentialReferenceDigest string       `json:"credential_reference_digest"`
	RBACDigest                string       `json:"rbac_digest"`
	Permissions               []Permission `json:"permissions"`
}

// StaticAgentSpecBackfillLifecycleIdentity declares the static readiness observer's distinct authority.
type StaticAgentSpecBackfillLifecycleIdentity struct {
	Name                       string                          `json:"name"`
	CredentialReferenceDigest  string                          `json:"credential_reference_digest"`
	RBACDigest                 string                          `json:"rbac_digest"`
	ObservationAuthorityDigest string                          `json:"observation_authority_digest"`
	Identity                   StaticAgentSpecBackfillIdentity `json:"identity"`
}

// StaticAgentSpecBackfillArchiveIdentity declares the retained-evidence export authority.
type StaticAgentSpecBackfillArchiveIdentity struct {
	Name                      string                          `json:"name"`
	CredentialReferenceDigest string                          `json:"credential_reference_digest"`
	RBACDigest                string                          `json:"rbac_digest"`
	ArchivePolicyDigest       string                          `json:"archive_policy_digest"`
	Identity                  StaticAgentSpecBackfillIdentity `json:"identity"`
}

// StaticAgentSpecBackfillAdmission pins the static validating admission policy and its binding.
type StaticAgentSpecBackfillAdmission struct {
	PolicyDigest  string `json:"policy_digest"`
	BindingDigest string `json:"binding_digest"`
}

// StaticAgentSpecBackfillRuntimeTarget declares a target namespace and the not-yet-realized UID-bound ingress handoff.
type StaticAgentSpecBackfillRuntimeTarget struct {
	Namespace           string `json:"namespace"`
	TargetIngressDigest string `json:"target_ingress_digest"`
	UIDHandshakeDigest  string `json:"uid_handshake_digest"`
}

// StaticAgentSpecBackfillController is the immutable controller workload declaration.
type StaticAgentSpecBackfillController struct {
	// Image is an immutable digest-qualified controller image reference.
	Image string `json:"image"`
	// Command is the reviewed executable argv prefix.
	Command []string `json:"command"`
	// Arguments is the reviewed controller argv suffix.
	Arguments []string `json:"arguments"`
	// ConfigDigest pins the bounded controller configuration without embedding it.
	ConfigDigest string `json:"config_digest"`
	// Resources bounds controller CPU and memory.
	Resources *ComputeResources `json:"resources"`
}

// StaticAgentSpecBackfillIdentities is the exact namespaced controller/operator identity set.
type StaticAgentSpecBackfillIdentities struct {
	Namespace                string `json:"namespace"`
	ControllerServiceAccount string `json:"controller_service_account"`
	ControllerRole           string `json:"controller_role"`
	ControllerRoleBinding    string `json:"controller_role_binding"`
	OperatorServiceAccount   string `json:"operator_service_account"`
	OperatorRole             string `json:"operator_role"`
	OperatorRoleBinding      string `json:"operator_role_binding"`
}

// StaticAgentSpecBackfillRoute is one exact named service egress authority.
type StaticAgentSpecBackfillRoute struct {
	Kind            string `json:"kind"`
	Namespace       string `json:"namespace"`
	Service         string `json:"service"`
	PortName        string `json:"port_name"`
	PortNumber      int    `json:"port_number"`
	Protocol        string `json:"protocol"`
	AuthorityDigest string `json:"authority_digest"`
}

// StaticAgentSpecBackfillRBAC pins static Kubernetes RBAC declarations without embedding rules.
type StaticAgentSpecBackfillRBAC struct {
	ControllerDigest string `json:"controller_digest"`
	OperatorDigest   string `json:"operator_digest"`
}

// StaticAgentSpecBackfillCredentials pins non-secret external credential/capability declarations.
type StaticAgentSpecBackfillCredentials struct {
	ControllerReferenceDigest    string `json:"controller_reference_digest"`
	DatabaseReadCapabilityDigest string `json:"database_read_capability_digest"`
	BlobReadCapabilityDigest     string `json:"blob_read_capability_digest"`
}

// StaticAgentSpecBackfillPlan is immutable canonical desired state for a control plane that is deliberately not applied.
type StaticAgentSpecBackfillPlan struct {
	digest string
	data   []byte
}

// Digest returns the canonical SHA-256 identity of the render-only control-plane plan.
func (plan StaticAgentSpecBackfillPlan) Digest() string { return plan.digest }

// JSON returns a copy of the canonical render-only plan.
func (plan StaticAgentSpecBackfillPlan) JSON() []byte { return append([]byte(nil), plan.data...) }

// StaticAgentSpecBackfillInventory is immutable canonical static control-plane desired state.
// It is deliberately non-applicable; a separately authorized future operator must consume it.
type StaticAgentSpecBackfillInventory struct {
	digest string
	data   []byte
}

// Digest returns the canonical SHA-256 identity of the non-applying static inventory.
func (inventory StaticAgentSpecBackfillInventory) Digest() string { return inventory.digest }

// JSON returns a copy of the canonical non-applying static inventory.
func (inventory StaticAgentSpecBackfillInventory) JSON() []byte {
	return append([]byte(nil), inventory.data...)
}

type staticAgentSpecBackfillPlanDocument struct {
	Version               int                                `json:"version"`
	Stack                 string                             `json:"stack"`
	NotApplied            bool                               `json:"not_applied"`
	CRDDigest             string                             `json:"crd_digest"`
	Controller            StaticAgentSpecBackfillController  `json:"controller"`
	Identities            StaticAgentSpecBackfillIdentities  `json:"identities"`
	Routes                []StaticAgentSpecBackfillRoute     `json:"routes"`
	RBAC                  StaticAgentSpecBackfillRBAC        `json:"rbac"`
	Credentials           StaticAgentSpecBackfillCredentials `json:"credentials"`
	EvidenceRetentionDays int                                `json:"evidence_retention_days"`
	TeardownInventory     []string                           `json:"teardown_inventory"`
	Digest                string                             `json:"digest,omitempty"`
}

type staticAgentSpecBackfillInventoryDocument struct {
	Version               int                                `json:"version"`
	Stack                 string                             `json:"stack"`
	NotApplied            bool                               `json:"not_applied"`
	CRDDigest             string                             `json:"crd_digest"`
	Controller            StaticAgentSpecBackfillController  `json:"controller"`
	Identities            StaticAgentSpecBackfillIdentities  `json:"identities"`
	Routes                []StaticAgentSpecBackfillRoute     `json:"routes"`
	RBAC                  StaticAgentSpecBackfillRBAC        `json:"rbac"`
	Credentials           StaticAgentSpecBackfillCredentials `json:"credentials"`
	EvidenceRetentionDays int                                `json:"evidence_retention_days"`
	TeardownInventory     []string                           `json:"teardown_inventory"`
	Inventory             StaticAgentSpecBackfillInventoryV1 `json:"inventory"`
	Digest                string                             `json:"digest,omitempty"`
}

var staticAgentSpecBackfillTeardownInventory = []string{
	"agent-spec-backfill-controller",
	"agent-spec-backfill-controller-role",
	"agent-spec-backfill-controller-role-binding",
	"agent-spec-backfill-controller-service-account",
	"agent-spec-backfill-credentials",
	"agent-spec-backfill-operator-role",
	"agent-spec-backfill-operator-role-binding",
	"agent-spec-backfill-operator-service-account",
	"agent-spec-backfill-routes",
	"agentspecbackfill-crd",
	"agentspecbackfill-validating-admission-policy",
	"agentspecbackfill-validating-admission-policy-binding",
}

var staticAgentSpecBackfillRoutes = map[string]StaticAgentSpecBackfillRoute{
	"kubernetes_api": {Kind: "kubernetes_api", Namespace: "kube-system", Service: "kubernetes", PortName: "https", PortNumber: 443, Protocol: "TCP"},
	"database":       {Kind: "database", Namespace: "runtime", Service: "postgres", PortName: "postgres", PortNumber: 5432, Protocol: "TCP"},
	"blob":           {Kind: "blob", Namespace: "runtime", Service: "object-store", PortName: "https", PortNumber: 443, Protocol: "TCP"},
	"dns_tcp":        {Kind: "dns_tcp", Namespace: "kube-system", Service: "kube-dns", PortName: "dns-tcp", PortNumber: 53, Protocol: "TCP"},
	"dns_udp":        {Kind: "dns_udp", Namespace: "kube-system", Service: "kube-dns", PortName: "dns-udp", PortNumber: 53, Protocol: "UDP"},
}

func validateStaticAgentSpecBackfill(declaration StaticAgentSpecBackfillV1) error {
	if declaration.Version != 1 || !sha256Pattern.MatchString(declaration.CRDDigest) {
		return errors.New("validate static AgentSpecBackfill declaration: version and CRD digest are required")
	}
	crd, err := agentspecbackfillcrd.Render()
	if err != nil {
		return errors.Wrap(err, "validate static AgentSpecBackfill declaration CRD")
	}
	sum := sha256.Sum256(crd)
	if declaration.CRDDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		return errors.New("validate static AgentSpecBackfill declaration: CRD digest does not match generated CRD")
	}
	if err := validateStaticAgentSpecBackfillController(declaration.Controller); err != nil {
		return err
	}
	if err := validateStaticAgentSpecBackfillIdentities(declaration.Identities); err != nil {
		return err
	}
	if err := validateStaticAgentSpecBackfillRoutes(declaration.Routes); err != nil {
		return err
	}
	if !sha256Pattern.MatchString(declaration.RBAC.ControllerDigest) || !sha256Pattern.MatchString(declaration.RBAC.OperatorDigest) || declaration.RBAC.ControllerDigest == declaration.RBAC.OperatorDigest {
		return errors.New("validate static AgentSpecBackfill declaration: distinct controller and operator RBAC digests are required")
	}
	credentialDigests := []string{declaration.Credentials.ControllerReferenceDigest, declaration.Credentials.DatabaseReadCapabilityDigest, declaration.Credentials.BlobReadCapabilityDigest}
	if !allDistinctDigests(credentialDigests) {
		return errors.New("validate static AgentSpecBackfill declaration: distinct credential reference and capability digests are required")
	}
	if declaration.EvidenceRetentionDays < 30 || declaration.EvidenceRetentionDays > 3650 {
		return errors.New("validate static AgentSpecBackfill declaration: evidence retention must be between 30 and 3650 days")
	}
	if !sameStringSet(declaration.TeardownInventory, staticAgentSpecBackfillTeardownInventory) {
		return errors.New("validate static AgentSpecBackfill declaration: complete unique teardown inventory is required")
	}
	return nil
}

func validateStaticAgentSpecBackfillController(controller StaticAgentSpecBackfillController) error {
	if !imageDigestPattern.MatchString(controller.Image) || !sha256Pattern.MatchString(controller.ConfigDigest) || controller.Resources == nil {
		return errors.New("validate static AgentSpecBackfill declaration: immutable controller image, config digest, and resources are required")
	}
	if err := validateCompute("agent-spec-backfill-controller", controller.Resources); err != nil {
		return errors.Wrap(err, "validate static AgentSpecBackfill controller")
	}
	if !slices.Equal(controller.Command, []string{"agent-spec-backfill-controller"}) || !slices.Equal(controller.Arguments, []string{"--config", "/etc/agent-runtime/controller.json"}) {
		return errors.New("validate static AgentSpecBackfill declaration: controller command and arguments must be fixed reviewed argv")
	}
	return nil
}

func validateStaticAgentSpecBackfillIdentities(identities StaticAgentSpecBackfillIdentities) error {
	values := []string{identities.Namespace, identities.ControllerServiceAccount, identities.ControllerRole, identities.ControllerRoleBinding, identities.OperatorServiceAccount, identities.OperatorRole, identities.OperatorRoleBinding}
	for _, value := range values {
		if !resourceIDPattern.MatchString(value) {
			return errors.New("validate static AgentSpecBackfill declaration: fixed identity names are required")
		}
	}
	if identities.Namespace != "agent-spec-backfill" ||
		identities.ControllerServiceAccount != "agent-spec-backfill-controller" ||
		identities.ControllerRole != "agent-spec-backfill-controller" ||
		identities.ControllerRoleBinding != "agent-spec-backfill-controller" ||
		identities.OperatorServiceAccount != "agent-spec-backfill-operator" ||
		identities.OperatorRole != "agent-spec-backfill-operator" ||
		identities.OperatorRoleBinding != "agent-spec-backfill-operator" ||
		identities.ControllerServiceAccount == identities.OperatorServiceAccount {
		return errors.New("validate static AgentSpecBackfill declaration: controller and operator identities are invalid or ambiguous")
	}
	return nil
}

func validateStaticAgentSpecBackfillRoutes(routes []StaticAgentSpecBackfillRoute) error {
	if len(routes) < 3 || len(routes) > 5 {
		return errors.New("validate static AgentSpecBackfill declaration: complete fixed route set is required")
	}
	required := map[string]bool{"kubernetes_api": false, "database": false, "blob": false}
	dns := map[string]bool{"dns_tcp": false, "dns_udp": false}
	for _, route := range routes {
		if _, found := required[route.Kind]; !found {
			if _, found := dns[route.Kind]; !found {
				return errors.New("validate static AgentSpecBackfill declaration: route kind is not allowed")
			}
			if dns[route.Kind] {
				return errors.New("validate static AgentSpecBackfill declaration: routes must not be ambiguous")
			}
			dns[route.Kind] = true
		} else {
			if required[route.Kind] {
				return errors.New("validate static AgentSpecBackfill declaration: routes must not be ambiguous")
			}
			required[route.Kind] = true
		}
		if !resourceIDPattern.MatchString(route.Namespace) || !resourceIDPattern.MatchString(route.Service) || !resourceIDPattern.MatchString(route.PortName) || route.PortNumber < 1 || route.PortNumber > 65535 || !sha256Pattern.MatchString(route.AuthorityDigest) {
			return errors.New("validate static AgentSpecBackfill declaration: routes must declare bounded names, ports, and authority digests")
		}
		expected := staticAgentSpecBackfillRoutes[route.Kind]
		if route.Namespace != expected.Namespace || route.Service != expected.Service || route.PortName != expected.PortName || route.PortNumber != expected.PortNumber || route.Protocol != expected.Protocol {
			return errors.New("validate static AgentSpecBackfill declaration: route endpoint, port, and protocol must match the fixed reviewed authority")
		}
	}
	for _, present := range required {
		if !present {
			return errors.New("validate static AgentSpecBackfill declaration: Kubernetes API, database, and blob routes are required")
		}
	}
	if dns["dns_tcp"] != dns["dns_udp"] {
		return errors.New("validate static AgentSpecBackfill declaration: DNS routes must declare both TCP and UDP or neither")
	}
	return nil
}

func allDistinctDigests(digests []string) bool {
	seen := make(map[string]struct{}, len(digests))
	for _, digest := range digests {
		if !sha256Pattern.MatchString(digest) {
			return false
		}
		if _, duplicate := seen[digest]; duplicate {
			return false
		}
		seen[digest] = struct{}{}
	}
	return true
}

func sameStringSet(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	actual = append([]string(nil), actual...)
	expected = append([]string(nil), expected...)
	sort.Strings(actual)
	sort.Strings(expected)
	if !slices.Equal(actual, expected) {
		return false
	}
	for index := 1; index < len(actual); index++ {
		if actual[index-1] == actual[index] {
			return false
		}
	}
	return true
}

func cloneStaticAgentSpecBackfill(declaration StaticAgentSpecBackfillV1) StaticAgentSpecBackfillV1 {
	clone := declaration
	clone.Controller.Command = append([]string(nil), declaration.Controller.Command...)
	clone.Controller.Arguments = append([]string(nil), declaration.Controller.Arguments...)
	if declaration.Controller.Resources != nil {
		resources := *declaration.Controller.Resources
		clone.Controller.Resources = &resources
	}
	clone.Routes = append([]StaticAgentSpecBackfillRoute(nil), declaration.Routes...)
	clone.TeardownInventory = append([]string(nil), declaration.TeardownInventory...)
	if declaration.Inventory != nil {
		inventory := cloneStaticAgentSpecBackfillInventory(*declaration.Inventory)
		clone.Inventory = &inventory
	}
	return clone
}

func cloneStaticAgentSpecBackfillInventory(inventory StaticAgentSpecBackfillInventoryV1) StaticAgentSpecBackfillInventoryV1 {
	clone := inventory
	clone.ControllerIdentity.Permissions = clonePermissions(inventory.ControllerIdentity.Permissions)
	clone.OperatorIdentity.Permissions = clonePermissions(inventory.OperatorIdentity.Permissions)
	clone.LifecycleIdentity.Identity.Permissions = clonePermissions(inventory.LifecycleIdentity.Identity.Permissions)
	clone.ArchiveIdentity.Identity.Permissions = clonePermissions(inventory.ArchiveIdentity.Identity.Permissions)
	return clone
}

func clonePermissions(permissions []Permission) []Permission {
	clone := append([]Permission(nil), permissions...)
	for index := range clone {
		clone[index].Verbs = append([]string(nil), clone[index].Verbs...)
	}
	return clone
}

// RenderStaticAgentSpecBackfill compiles one declared static control plane into canonical non-applicable desired state.
func RenderStaticAgentSpecBackfill(spec Spec) (StaticAgentSpecBackfillPlan, error) {
	declaration, found := spec.StaticAgentSpecBackfill()
	if !found {
		return StaticAgentSpecBackfillPlan{}, errors.New("render static AgentSpecBackfill control plane: declaration is not declared")
	}
	if err := validateStaticAgentSpecBackfill(declaration); err != nil {
		return StaticAgentSpecBackfillPlan{}, errors.Wrap(err, "render static AgentSpecBackfill control plane")
	}
	sort.Slice(declaration.Routes, func(left, right int) bool { return declaration.Routes[left].Kind < declaration.Routes[right].Kind })
	sort.Strings(declaration.TeardownInventory)
	document := staticAgentSpecBackfillPlanDocument{
		Version: declaration.Version, Stack: spec.Name.String(), NotApplied: true, CRDDigest: declaration.CRDDigest,
		Controller: declaration.Controller, Identities: declaration.Identities, Routes: declaration.Routes,
		RBAC: declaration.RBAC, Credentials: declaration.Credentials, EvidenceRetentionDays: declaration.EvidenceRetentionDays,
		TeardownInventory: declaration.TeardownInventory,
	}
	unsigned, err := json.Marshal(document)
	if err != nil {
		return StaticAgentSpecBackfillPlan{}, errors.Wrap(err, "render static AgentSpecBackfill control plane")
	}
	document.Digest = digest(unsigned)
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return StaticAgentSpecBackfillPlan{}, errors.Wrap(err, "render static AgentSpecBackfill control plane")
	}
	return StaticAgentSpecBackfillPlan{digest: document.Digest, data: append(encoded, '\n')}, nil
}

// CompileStaticAgentSpecBackfillInventory compiles declared static control-plane facts without provider effects.
func CompileStaticAgentSpecBackfillInventory(spec Spec) (StaticAgentSpecBackfillInventory, error) {
	declaration, found := spec.StaticAgentSpecBackfill()
	if !found {
		return StaticAgentSpecBackfillInventory{}, errors.New("compile static AgentSpecBackfill inventory: declaration is not declared")
	}
	if err := validateStaticAgentSpecBackfill(declaration); err != nil {
		return StaticAgentSpecBackfillInventory{}, errors.Wrap(err, "compile static AgentSpecBackfill inventory")
	}
	if err := validateStaticAgentSpecBackfillInventory(declaration); err != nil {
		return StaticAgentSpecBackfillInventory{}, errors.Wrap(err, "compile static AgentSpecBackfill inventory")
	}
	inventory := cloneStaticAgentSpecBackfillInventory(*declaration.Inventory)
	sort.Slice(declaration.Routes, func(left, right int) bool { return declaration.Routes[left].Kind < declaration.Routes[right].Kind })
	sort.Strings(declaration.TeardownInventory)
	canonicalizeStaticIdentity(&inventory.ControllerIdentity)
	canonicalizeStaticIdentity(&inventory.OperatorIdentity)
	canonicalizeStaticIdentity(&inventory.LifecycleIdentity.Identity)
	canonicalizeStaticIdentity(&inventory.ArchiveIdentity.Identity)
	document := staticAgentSpecBackfillInventoryDocument{
		Version: declaration.Version, Stack: spec.Name.String(), NotApplied: true, CRDDigest: declaration.CRDDigest,
		Controller: declaration.Controller, Identities: declaration.Identities, Routes: declaration.Routes,
		RBAC: declaration.RBAC, Credentials: declaration.Credentials, EvidenceRetentionDays: declaration.EvidenceRetentionDays,
		TeardownInventory: declaration.TeardownInventory, Inventory: inventory,
	}
	unsigned, err := json.Marshal(document)
	if err != nil {
		return StaticAgentSpecBackfillInventory{}, errors.Wrap(err, "compile static AgentSpecBackfill inventory")
	}
	document.Digest = digest(unsigned)
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return StaticAgentSpecBackfillInventory{}, errors.Wrap(err, "compile static AgentSpecBackfill inventory")
	}
	return StaticAgentSpecBackfillInventory{digest: document.Digest, data: append(encoded, '\n')}, nil
}

func validateStaticAgentSpecBackfillInventory(declaration StaticAgentSpecBackfillV1) error {
	if declaration.Inventory == nil {
		return errors.New("static AgentSpecBackfill inventory must declare every authority fact")
	}
	inventory := declaration.Inventory
	if inventory.Profile != ProfileLocal && inventory.Profile != ProfileCI && inventory.Profile != ProfileProduction {
		return errors.New("static AgentSpecBackfill inventory must declare one reviewed profile")
	}
	if !resourceIDPattern.MatchString(inventory.ClusterOwnership.Owner) || !sha256Pattern.MatchString(inventory.ClusterOwnership.AuthorityDigest) {
		return errors.New("static AgentSpecBackfill inventory must declare cluster ownership")
	}
	if err := validateStaticIdentity(inventory.ControllerIdentity, declaration.Identities.Namespace, declaration.Identities.ControllerServiceAccount, declaration.RBAC.ControllerDigest, declaration.Credentials.ControllerReferenceDigest, controllerStaticPermissions()); err != nil {
		return errors.Wrap(err, "validate static AgentSpecBackfill controller identity")
	}
	if err := validateStaticIdentity(inventory.OperatorIdentity, "", "", declaration.RBAC.OperatorDigest, "", operatorStaticPermissions()); err != nil {
		return errors.Wrap(err, "validate static AgentSpecBackfill operator identity")
	}
	if !resourceIDPattern.MatchString(inventory.LifecycleIdentity.Name) || !allDistinctDigests([]string{inventory.LifecycleIdentity.CredentialReferenceDigest, inventory.LifecycleIdentity.RBACDigest, inventory.LifecycleIdentity.ObservationAuthorityDigest}) {
		return errors.New("static AgentSpecBackfill inventory must declare distinct lifecycle identity authority")
	}
	if err := validateStaticIdentity(inventory.LifecycleIdentity.Identity, "", "", inventory.LifecycleIdentity.RBACDigest, inventory.LifecycleIdentity.CredentialReferenceDigest, nil); err != nil {
		return errors.Wrap(err, "validate static AgentSpecBackfill lifecycle identity")
	}
	if err := validateStaticReadOnlyPermissions(inventory.LifecycleIdentity.Identity.Permissions); err != nil {
		return errors.Wrap(err, "validate static AgentSpecBackfill lifecycle identity")
	}
	if !resourceIDPattern.MatchString(inventory.ArchiveIdentity.Name) || !allDistinctDigests([]string{inventory.ArchiveIdentity.CredentialReferenceDigest, inventory.ArchiveIdentity.RBACDigest, inventory.ArchiveIdentity.ArchivePolicyDigest}) {
		return errors.New("static AgentSpecBackfill inventory must declare distinct archive identity authority")
	}
	if err := validateStaticIdentity(inventory.ArchiveIdentity.Identity, "", "", inventory.ArchiveIdentity.RBACDigest, inventory.ArchiveIdentity.CredentialReferenceDigest, archiveStaticPermissions()); err != nil {
		return errors.Wrap(err, "validate static AgentSpecBackfill archive identity")
	}
	identityCredentials := []string{inventory.ControllerIdentity.CredentialReferenceDigest, inventory.OperatorIdentity.CredentialReferenceDigest, inventory.LifecycleIdentity.CredentialReferenceDigest, inventory.ArchiveIdentity.CredentialReferenceDigest}
	if !allDistinctDigests(identityCredentials) {
		return errors.New("static AgentSpecBackfill inventory must keep identity credential authority distinct")
	}
	if !allDistinctDigests([]string{inventory.Admission.PolicyDigest, inventory.Admission.BindingDigest}) {
		return errors.New("static AgentSpecBackfill inventory must declare distinct admission policy and binding authority")
	}
	if !resourceIDPattern.MatchString(inventory.RuntimeTarget.Namespace) || !sha256Pattern.MatchString(inventory.RuntimeTarget.TargetIngressDigest) || !sha256Pattern.MatchString(inventory.RuntimeTarget.UIDHandshakeDigest) {
		return errors.New("static AgentSpecBackfill inventory must declare runtime target and UID handoff")
	}
	return nil
}

func validateStaticIdentity(identity StaticAgentSpecBackfillIdentity, expectedNamespace, expectedSubject, expectedRBACDigest, expectedCredentialDigest string, expectedPermissions []Permission) error {
	if (identity.SubjectKind != "service_account" && identity.SubjectKind != "external") || !resourceIDPattern.MatchString(identity.Subject) || !sha256Pattern.MatchString(identity.CredentialReferenceDigest) || !sha256Pattern.MatchString(identity.RBACDigest) || identity.RBACDigest != expectedRBACDigest || (expectedPermissions != nil && !samePermissions(identity.Permissions, expectedPermissions)) {
		return errors.New("identity kind, subject, credential, RBAC, and exact permissions are required")
	}
	if expectedCredentialDigest != "" && identity.CredentialReferenceDigest != expectedCredentialDigest {
		return errors.New("identity credential reference does not match static declaration")
	}
	if identity.SubjectKind == "service_account" {
		if !resourceIDPattern.MatchString(identity.Namespace) {
			return errors.New("service-account identity namespace is required")
		}
	} else if identity.Namespace != "" {
		return errors.New("external identity must not imply a Kubernetes namespace")
	}
	if expectedNamespace != "" && identity.Namespace != expectedNamespace {
		return errors.New("identity namespace does not match static declaration")
	}
	if expectedSubject != "" && identity.Subject != expectedSubject {
		return errors.New("identity subject does not match static declaration")
	}
	return nil
}

func controllerStaticPermissions() []Permission {
	return []Permission{{APIGroup: "runtime.0x63616c.dev", Resource: "agentspecbackfills", Verbs: []string{"get", "list", "watch"}}, {APIGroup: "runtime.0x63616c.dev", Resource: "agentspecbackfills/status", Verbs: []string{"patch", "update"}}}
}

func operatorStaticPermissions() []Permission {
	return []Permission{{APIGroup: "runtime.0x63616c.dev", Resource: "agentspecbackfills", Verbs: []string{"create", "get"}}}
}

func archiveStaticPermissions() []Permission {
	return []Permission{{APIGroup: "runtime.0x63616c.dev", Resource: "agentspecbackfills", Verbs: []string{"get", "list"}}}
}

func validateStaticReadOnlyPermissions(permissions []Permission) error {
	if len(permissions) == 0 {
		return errors.New("at least one explicit read-only permission is required")
	}
	seen := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		if permission.APIGroup == "*" || permission.Resource == "" || permission.Resource == "*" || len(permission.Verbs) != 1 || permission.Verbs[0] != "get" {
			return errors.New("read-only permissions must contain one explicit resource and get verb")
		}
		key := permission.APIGroup + "\x00" + permission.Resource
		if _, duplicate := seen[key]; duplicate {
			return errors.New("read-only permissions must not repeat resources")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func samePermissions(actual, expected []Permission) bool {
	actual = clonePermissions(actual)
	expected = clonePermissions(expected)
	canonicalizePermissions(actual)
	canonicalizePermissions(expected)
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index].APIGroup != expected[index].APIGroup || actual[index].Resource != expected[index].Resource || !slices.Equal(actual[index].Verbs, expected[index].Verbs) {
			return false
		}
	}
	return true
}

func canonicalizeStaticIdentity(identity *StaticAgentSpecBackfillIdentity) {
	canonicalizePermissions(identity.Permissions)
}

func canonicalizePermissions(permissions []Permission) {
	for index := range permissions {
		sort.Strings(permissions[index].Verbs)
	}
	sort.Slice(permissions, func(left, right int) bool {
		if permissions[left].APIGroup != permissions[right].APIGroup {
			return permissions[left].APIGroup < permissions[right].APIGroup
		}
		return permissions[left].Resource < permissions[right].Resource
	})
}
