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
