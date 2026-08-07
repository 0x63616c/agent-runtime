package stack

import (
	"sort"

	"github.com/cockroachdb/errors"
)

// ObservedUID is an opaque provider identity captured during audited apply/observe.
type ObservedUID string

// OwnershipLabels are the exact containment labels attached to owned resources.
type OwnershipLabels struct {
	// PartOf must equal agent-runtime.
	PartOf string `json:"app.kubernetes.io/part-of"`
	// Stack is the sole validated Stack identity.
	Stack string `json:"agent-runtime.dev/stack"`
	// Profile is the rendered profile.
	Profile Profile `json:"agent-runtime.dev/profile"`
}

// ObservedResource is provider-observed identity and labels, never trusted state alone.
type ObservedResource struct {
	// ID is the desired resource identity.
	ID ResourceID `json:"id"`
	// UID is the current provider-observed object identity.
	UID ObservedUID `json:"uid"`
	// Labels are re-read from the target before teardown.
	Labels OwnershipLabels `json:"labels"`
}

// ObservedState is the audited operator observation required for safe teardown.
type ObservedState struct {
	// Stack is the observed Stack identity.
	Stack string `json:"stack"`
	// Profile is the observed profile.
	Profile Profile `json:"profile"`
	// Namespace is the observed explicit namespace.
	Namespace string `json:"namespace"`
	// NamespaceUID is the provider-observed namespace identity.
	NamespaceUID ObservedUID `json:"namespace_uid"`
	// RenderDigest binds observation to reviewed desired state.
	RenderDigest string `json:"render_digest"`
	// Labels are provider-observed namespace ownership labels.
	Labels OwnershipLabels `json:"labels"`
	// Resources is the complete provider-observed owned-resource set.
	Resources []ObservedResource `json:"resources"`
}

// TeardownAction is one identity-bound operator action in safe dependency order.
type TeardownAction struct {
	// Resource identifies the desired resource.
	Resource ResourceID `json:"resource"`
	// UID is the exact current provider identity that must still match at execution.
	UID ObservedUID `json:"uid"`
	// Behavior selects delete, tombstone, or retain.
	Behavior DeleteBehavior `json:"behavior"`
}

// TeardownPlan is immutable input to a separately audited operator adapter.
type TeardownPlan struct {
	// Stack is the sole Stack identity.
	Stack string `json:"stack"`
	// Profile is the reviewed profile.
	Profile Profile `json:"profile"`
	// Namespace is the explicit owned namespace.
	Namespace string `json:"namespace"`
	// NamespaceUID must still match before namespace deletion.
	NamespaceUID ObservedUID `json:"namespace_uid"`
	// RenderDigest binds every action to reviewed desired state.
	RenderDigest string `json:"render_digest"`
	// Actions are reverse dependency ordered.
	Actions []TeardownAction `json:"actions"`
}

// PlanTeardown refuses unproven ownership and returns no mutation capability.
func PlanTeardown(rendered Rendered, observed ObservedState) (TeardownPlan, error) {
	document, err := parseRenderedBytes(rendered.JSON())
	if err != nil {
		return TeardownPlan{}, errors.Wrap(err, "plan stack teardown")
	}
	expectedLabels := OwnershipLabels{PartOf: document.Labels.PartOf, Stack: document.Labels.Stack, Profile: document.Labels.Profile}
	if observed.Stack != document.Stack || observed.Profile != document.Profile || observed.Namespace != document.Namespace || observed.RenderDigest != document.Digest {
		return TeardownPlan{}, errors.New("plan stack teardown: observed stack identity does not match rendered desired state")
	}
	if observed.NamespaceUID == "" || observed.Labels != expectedLabels {
		return TeardownPlan{}, errors.New("plan stack teardown: namespace UID and ownership labels must match")
	}
	observedByID := make(map[ResourceID]ObservedResource, len(observed.Resources))
	for _, resource := range observed.Resources {
		if resource.ID == "" || resource.UID == "" || resource.Labels != expectedLabels {
			return TeardownPlan{}, errors.Newf("plan stack teardown: resource %s lacks matching UID or ownership labels", resource.ID)
		}
		if _, duplicate := observedByID[resource.ID]; duplicate {
			return TeardownPlan{}, errors.Newf("plan stack teardown: resource %s is observed more than once", resource.ID)
		}
		observedByID[resource.ID] = resource
	}
	if len(observedByID) != len(document.Resources) {
		return TeardownPlan{}, errors.New("plan stack teardown: observed resource set differs from rendered desired state")
	}
	byID := make(map[ResourceID]Resource, len(document.Resources))
	for _, resource := range document.Resources {
		byID[resource.ID] = resource
		if _, exists := observedByID[resource.ID]; !exists {
			return TeardownPlan{}, errors.Newf("plan stack teardown: resource %s was not observed", resource.ID)
		}
	}
	order := reverseDependencyOrder(byID)
	actions := make([]TeardownAction, 0, len(order))
	for _, id := range order {
		actions = append(actions, TeardownAction{Resource: id, UID: observedByID[id].UID, Behavior: byID[id].DeleteBehavior})
	}
	return TeardownPlan{
		Stack: document.Stack, Profile: document.Profile, Namespace: document.Namespace,
		NamespaceUID: observed.NamespaceUID, RenderDigest: document.Digest, Actions: actions,
	}, nil
}

func reverseDependencyOrder(resources map[ResourceID]Resource) []ResourceID {
	ids := make([]ResourceID, 0, len(resources))
	for id := range resources {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	visited := map[ResourceID]bool{}
	ordered := make([]ResourceID, 0, len(ids))
	var visit func(ResourceID)
	visit = func(id ResourceID) {
		if visited[id] {
			return
		}
		visited[id] = true
		dependencies := append([]ResourceID(nil), resources[id].Dependencies...)
		sort.Slice(dependencies, func(left, right int) bool { return dependencies[left] < dependencies[right] })
		for _, dependency := range dependencies {
			visit(dependency)
		}
		ordered = append(ordered, id)
	}
	for _, id := range ids {
		visit(id)
	}
	for left, right := 0, len(ordered)-1; left < right; left, right = left+1, right-1 {
		ordered[left], ordered[right] = ordered[right], ordered[left]
	}
	return ordered
}
