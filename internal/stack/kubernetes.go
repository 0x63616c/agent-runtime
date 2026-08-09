package stack

import (
	"encoding/json"
	"fmt"
	"sort"
)

const (
	stackLabel    = "agent-runtime.dev/stack"
	profileLabel  = "agent-runtime.dev/profile"
	resourceLabel = "agent-runtime.dev/resource"
	partOfLabel   = "app.kubernetes.io/part-of"
)

// KubernetesMetadata is the typed identity and containment label set of one manifest.
type KubernetesMetadata struct {
	// Name is the Kubernetes object name.
	Name string `json:"name"`
	// Namespace is empty only for a Namespace object.
	Namespace string `json:"namespace,omitempty"`
	// Labels bind this object to exactly one rendered Stack and profile.
	Labels map[string]string `json:"labels"`
	// Annotations carry reviewed or operation-specific Kubernetes metadata.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// KubernetesManifest is one typed Kubernetes object rendered from a Stack resource.
// Resource is internal rendering provenance and is deliberately not serialized to Kubernetes.
type KubernetesManifest struct {
	// Resource is the Stack resource identity, or "namespace" for the profile namespace.
	Resource ResourceID `json:"-"`
	// APIVersion is the exact Kubernetes API version.
	APIVersion string `json:"apiVersion"`
	// Kind is the exact Kubernetes kind.
	Kind string `json:"kind"`
	// Metadata is explicit object identity and containment labels.
	Metadata KubernetesMetadata `json:"metadata"`
	// Spec is the typed resource projection in Kubernetes API JSON form.
	Spec json.RawMessage `json:"spec,omitempty"`
	// Data is the explicit non-secret ConfigMap data projection.
	Data map[string]string `json:"data,omitempty"`
	// Rules is the bounded Role rule projection.
	Rules []kubernetesRoleRule `json:"rules,omitempty"`
	// RoleRef is the RoleBinding reference projection.
	RoleRef *kubernetesRoleReference `json:"roleRef,omitempty"`
	// Subjects is the RoleBinding subject projection.
	Subjects []kubernetesSubject `json:"subjects,omitempty"`
}

type kubernetesRoleRule struct {
	APIgroups []string `json:"apiGroups"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}

type kubernetesRoleReference struct {
	APIGroup string `json:"apiGroup"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
}

type kubernetesSubject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// KubernetesManifests is an immutable, canonical Kubernetes List for one rendered Stack profile.
type KubernetesManifests struct {
	namespace KubernetesManifest
	objects   []KubernetesManifest
	data      []byte
	stack     string
	profile   Profile
	digest    string
}

// Namespace returns a copy of the explicitly rendered profile Namespace manifest.
func (manifests KubernetesManifests) Namespace() KubernetesManifest {
	return cloneManifest(manifests.namespace)
}

// Objects returns copies of Stack resource manifests in canonical ResourceID order.
func (manifests KubernetesManifests) Objects() []KubernetesManifest {
	objects := make([]KubernetesManifest, len(manifests.objects))
	for index := range manifests.objects {
		objects[index] = cloneManifest(manifests.objects[index])
	}
	return objects
}

// All returns copies of the Namespace followed by canonical Stack resource manifests.
func (manifests KubernetesManifests) All() []KubernetesManifest {
	objects := make([]KubernetesManifest, 0, len(manifests.objects)+1)
	objects = append(objects, manifests.Namespace())
	objects = append(objects, manifests.Objects()...)
	return objects
}

// JSON returns a canonical Kubernetes v1/List document accepted by kubectl apply -f -.
func (manifests KubernetesManifests) JSON() []byte {
	return append([]byte(nil), manifests.data...)
}

// RenderKubernetes converts typed rendered desired state into canonical typed Kubernetes manifests.
// It reads no provider, credentials, environment, or clock state.
func RenderKubernetes(rendered Rendered) (KubernetesManifests, error) {
	document, err := parseRenderedBytes(rendered.JSON())
	if err != nil {
		return KubernetesManifests{}, err
	}
	labels := stackLabels(document.Stack, document.Profile)
	namespace := KubernetesManifest{
		Resource: "namespace", APIVersion: "v1", Kind: "Namespace",
		Metadata: KubernetesMetadata{Name: document.Namespace, Labels: labels},
	}
	objects := make([]KubernetesManifest, 0)
	resources := make(map[ResourceID]Resource, len(document.Resources))
	for _, resource := range document.Resources {
		resources[resource.ID] = resource
	}
	for _, resource := range document.Resources {
		if resource.Kind != ResourceKubernetes {
			continue
		}
		if resource.Kubernetes.Kind == "Namespace" {
			continue
		}
		manifest, manifestErr := renderKubernetesResource(resource, document.Namespace, document.Stack, document.Profile, resources)
		if manifestErr != nil {
			return KubernetesManifests{}, manifestErr
		}
		objects = append(objects, manifest)
	}
	sort.Slice(objects, func(left, right int) bool { return objects[left].Resource < objects[right].Resource })
	list := struct {
		APIVersion string               `json:"apiVersion"`
		Kind       string               `json:"kind"`
		Items      []KubernetesManifest `json:"items"`
	}{APIVersion: "v1", Kind: "List", Items: append([]KubernetesManifest{namespace}, objects...)}
	encoded, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return KubernetesManifests{}, fmt.Errorf("render Kubernetes manifests: marshal canonical list: %w", err)
	}
	return KubernetesManifests{namespace: namespace, objects: objects, data: append(encoded, '\n'), stack: document.Stack, profile: document.Profile, digest: document.Digest}, nil
}

func renderKubernetesResource(resource Resource, namespace, stack string, profile Profile, resources map[ResourceID]Resource) (KubernetesManifest, error) {
	object := resource.Kubernetes
	manifest := KubernetesManifest{
		Resource: resource.ID, APIVersion: object.APIVersion, Kind: object.Kind,
		Metadata: KubernetesMetadata{Name: object.Name, Namespace: namespace, Labels: resourceLabels(stack, profile, resource.ID)},
	}
	switch object.Kind {
	case "ServiceAccount":
		return manifest, nil
	case "ConfigMap":
		manifest.Data = cloneStringMap(object.Data)
		return manifest, nil
	case "Role":
		manifest.Rules = make([]kubernetesRoleRule, 0, len(object.Permissions))
		for _, permission := range object.Permissions {
			verbs := append([]string(nil), permission.Verbs...)
			sort.Strings(verbs)
			manifest.Rules = append(manifest.Rules, kubernetesRoleRule{APIgroups: []string{permission.APIGroup}, Resources: []string{permission.Resource}, Verbs: verbs})
		}
		return manifest, nil
	case "RoleBinding":
		manifest.RoleRef = &kubernetesRoleReference{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: object.Role}
		manifest.Subjects = []kubernetesSubject{{Kind: "ServiceAccount", Name: object.ServiceAccount, Namespace: namespace}}
		return manifest, nil
	case "Deployment", "StatefulSet", "Job":
		spec, err := marshalWorkloadSpec(resource, namespace, stack, profile, resources)
		manifest.Spec = spec
		return manifest, err
	case "Service":
		manifest.Spec = marshalJSON(kubernetesServiceSpec{Selector: map[string]string{resourceLabel: string(object.Selector)}, Ports: manifestPorts(object.Ports)})
		return manifest, nil
	case "NetworkPolicy":
		manifest.Spec = marshalJSON(networkPolicySpec(object.Network))
		return manifest, nil
	case "PersistentVolumeClaim":
		storage := object.Storage[0]
		manifest.Spec = marshalJSON(kubernetesPVCSpec{AccessModes: []string{"ReadWriteOnce"}, StorageClassName: storage.Class, Resources: kubernetesResourceRequirements{Requests: map[string]string{"storage": byteQuantity(storage.SizeBytes)}}})
		return manifest, nil
	case "ResourceQuota":
		manifest.Spec = marshalJSON(kubernetesResourceQuotaSpec{Hard: map[string]string{
			"requests.cpu":    milliCPUQuantity(object.Compute.RequestMilliCPU),
			"limits.cpu":      milliCPUQuantity(object.Compute.LimitMilliCPU),
			"requests.memory": byteQuantity(object.Compute.RequestMemoryBytes),
			"limits.memory":   byteQuantity(object.Compute.LimitMemoryBytes),
		}})
		return manifest, nil
	case "Ingress":
		manifest.Spec = marshalJSON(kubernetesIngressSpec{Rules: ingressRules(object.IngressRules, resources)})
		return manifest, nil
	default:
		return KubernetesManifest{}, fmt.Errorf("render Kubernetes resource %s: unsupported kind %s", resource.ID, object.Kind)
	}
}

type kubernetesWorkloadSpec struct {
	Replicas *int                  `json:"replicas,omitempty"`
	Selector kubernetesSelector    `json:"selector,omitempty"`
	Service  string                `json:"serviceName,omitempty"`
	Template kubernetesPodTemplate `json:"template"`
}

type kubernetesIngressSpec struct {
	Rules []kubernetesIngressRule `json:"rules"`
}

type kubernetesIngressRule struct {
	Host string                       `json:"host"`
	HTTP kubernetesIngressHTTPRuleSet `json:"http"`
}

type kubernetesIngressHTTPRuleSet struct {
	Paths []kubernetesIngressPath `json:"paths"`
}

type kubernetesIngressPath struct {
	Path     string                   `json:"path"`
	PathType string                   `json:"pathType"`
	Backend  kubernetesIngressBackend `json:"backend"`
}

type kubernetesIngressBackend struct {
	Service kubernetesIngressServiceBackend `json:"service"`
}

type kubernetesIngressServiceBackend struct {
	Name string                      `json:"name"`
	Port kubernetesIngressPortNumber `json:"port"`
}

type kubernetesIngressPortNumber struct {
	Name string `json:"name"`
}

type kubernetesSelector struct {
	MatchLabels map[string]string `json:"matchLabels"`
}

type kubernetesPodTemplate struct {
	Metadata kubernetesPodMetadata `json:"metadata"`
	Spec     kubernetesPodSpec     `json:"spec"`
}

type kubernetesPodMetadata struct {
	Labels map[string]string `json:"labels"`
}

type kubernetesPodSpec struct {
	ServiceAccountName           string                `json:"serviceAccountName"`
	AutomountServiceAccountToken bool                  `json:"automountServiceAccountToken"`
	EnableServiceLinks           bool                  `json:"enableServiceLinks"`
	RestartPolicy                string                `json:"restartPolicy,omitempty"`
	Containers                   []kubernetesContainer `json:"containers"`
	Volumes                      []kubernetesVolume    `json:"volumes,omitempty"`
}

type kubernetesVolume struct {
	Name                  string                          `json:"name"`
	PersistentVolumeClaim kubernetesPersistentVolumeClaim `json:"persistentVolumeClaim"`
}

type kubernetesPersistentVolumeClaim struct {
	ClaimName string `json:"claimName"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}

type kubernetesContainer struct {
	Name         string                          `json:"name"`
	Image        string                          `json:"image"`
	Command      []string                        `json:"command,omitempty"`
	Args         []string                        `json:"args,omitempty"`
	Env          []kubernetesEnvironmentVariable `json:"env,omitempty"`
	VolumeMounts []kubernetesVolumeMount         `json:"volumeMounts,omitempty"`
	Ports        []kubernetesContainerPort       `json:"ports,omitempty"`
	Resources    kubernetesResourceRequirements  `json:"resources"`
	Readiness    *kubernetesReadinessProbe       `json:"readinessProbe,omitempty"`
}

type kubernetesReadinessProbe struct {
	Exec                kubernetesExecAction `json:"exec"`
	InitialDelaySeconds int                  `json:"initialDelaySeconds"`
	PeriodSeconds       int                  `json:"periodSeconds"`
	FailureThreshold    int                  `json:"failureThreshold"`
}

type kubernetesExecAction struct {
	Command []string `json:"command"`
}

type kubernetesEnvironmentVariable struct {
	Name      string                          `json:"name"`
	Value     string                          `json:"value,omitempty"`
	ValueFrom *kubernetesEnvironmentValueFrom `json:"valueFrom,omitempty"`
}

type kubernetesEnvironmentValueFrom struct {
	SecretKeyRef kubernetesSecretKeyReference `json:"secretKeyRef"`
}

type kubernetesSecretKeyReference struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type kubernetesVolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}

type kubernetesContainerPort struct {
	Name          string `json:"name"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
}

type kubernetesResourceRequirements struct {
	Limits   map[string]string `json:"limits,omitempty"`
	Requests map[string]string `json:"requests,omitempty"`
}

func marshalWorkloadSpec(resource Resource, namespace, stack string, profile Profile, resources map[ResourceID]Resource) (json.RawMessage, error) {
	object := resource.Kubernetes
	podLabels := resourceLabels(stack, profile, resource.ID)
	ports := make([]kubernetesContainerPort, 0, len(object.Ports))
	for _, port := range object.Ports {
		ports = append(ports, kubernetesContainerPort{Name: port.Name, ContainerPort: port.Number, Protocol: port.Protocol})
	}
	environment := make([]kubernetesEnvironmentVariable, 0, len(object.Environment))
	for _, variable := range object.Environment {
		environment = append(environment, kubernetesEnvironmentVariable{Name: variable.Name, Value: variable.Value})
	}
	for _, variable := range object.SecretEnvironment {
		secret := resources[variable.Secret].SecretReference
		environment = append(environment, kubernetesEnvironmentVariable{Name: variable.Name, ValueFrom: &kubernetesEnvironmentValueFrom{SecretKeyRef: kubernetesSecretKeyReference{Name: secret.Reference, Key: variable.Key}}})
	}
	volumes := make([]kubernetesVolume, 0, len(object.VolumeMounts))
	mounts := make([]kubernetesVolumeMount, 0, len(object.VolumeMounts))
	for _, mount := range object.VolumeMounts {
		claim := resources[mount.Claim].Kubernetes
		volumes = append(volumes, kubernetesVolume{Name: string(mount.Claim), PersistentVolumeClaim: kubernetesPersistentVolumeClaim{ClaimName: claim.Name, ReadOnly: mount.ReadOnly}})
		mounts = append(mounts, kubernetesVolumeMount{Name: string(mount.Claim), MountPath: mount.Path, ReadOnly: mount.ReadOnly})
	}
	container := kubernetesContainer{
		Name: object.Name, Image: object.Image, Command: append([]string(nil), object.Command...), Args: append([]string(nil), object.Arguments...), Env: environment, Ports: ports,
		VolumeMounts: mounts,
		Resources:    kubernetesResourceRequirements{Limits: map[string]string{"cpu": milliCPUQuantity(object.Compute.LimitMilliCPU), "memory": byteQuantity(object.Compute.LimitMemoryBytes)}, Requests: map[string]string{"cpu": milliCPUQuantity(object.Compute.RequestMilliCPU), "memory": byteQuantity(object.Compute.RequestMemoryBytes)}},
	}
	if object.Readiness != nil {
		container.Readiness = &kubernetesReadinessProbe{Exec: kubernetesExecAction{Command: append([]string(nil), object.Readiness.Command...)}, InitialDelaySeconds: object.Readiness.InitialDelaySeconds, PeriodSeconds: object.Readiness.PeriodSeconds, FailureThreshold: object.Readiness.FailureThreshold}
	}
	spec := kubernetesWorkloadSpec{Selector: kubernetesSelector{MatchLabels: map[string]string{resourceLabel: string(resource.ID)}}, Template: kubernetesPodTemplate{Metadata: kubernetesPodMetadata{Labels: podLabels}, Spec: kubernetesPodSpec{ServiceAccountName: object.ServiceAccount, AutomountServiceAccountToken: false, EnableServiceLinks: false, Containers: []kubernetesContainer{container}, Volumes: volumes}}}
	switch object.Kind {
	case "Deployment":
		replicas := effectiveReplicas(object.Replicas)
		spec.Replicas = &replicas
	case "StatefulSet":
		replicas := effectiveReplicas(object.Replicas)
		spec.Replicas = &replicas
		spec.Service = object.Name
	case "Job":
		spec.Selector = kubernetesSelector{}
		spec.Template.Spec.RestartPolicy = "Never"
	}
	return marshalJSON(spec), nil
}

func effectiveReplicas(value int) int {
	if value == 0 {
		return 1
	}
	return value
}

func ingressRules(rules []IngressRule, resources map[ResourceID]Resource) []kubernetesIngressRule {
	result := make([]kubernetesIngressRule, 0, len(rules))
	for _, rule := range rules {
		service := resources[rule.Service].Kubernetes
		result = append(result, kubernetesIngressRule{Host: rule.Host, HTTP: kubernetesIngressHTTPRuleSet{Paths: []kubernetesIngressPath{{Path: rule.Path, PathType: rule.PathType, Backend: kubernetesIngressBackend{Service: kubernetesIngressServiceBackend{Name: service.Name, Port: kubernetesIngressPortNumber{Name: rule.ServicePort}}}}}}})
	}
	return result
}

type kubernetesServiceSpec struct {
	Selector map[string]string       `json:"selector"`
	Ports    []kubernetesServicePort `json:"ports"`
}

type kubernetesServicePort struct {
	Name       string `json:"name"`
	Port       int    `json:"port"`
	TargetPort int    `json:"targetPort"`
	Protocol   string `json:"protocol"`
}

func manifestPorts(ports []Port) []kubernetesServicePort {
	result := make([]kubernetesServicePort, 0, len(ports))
	for _, port := range ports {
		result = append(result, kubernetesServicePort{Name: port.Name, Port: port.Number, TargetPort: port.Number, Protocol: port.Protocol})
	}
	return result
}

type kubernetesPVCSpec struct {
	AccessModes      []string                       `json:"accessModes"`
	StorageClassName string                         `json:"storageClassName"`
	Resources        kubernetesResourceRequirements `json:"resources"`
}

type kubernetesResourceQuotaSpec struct {
	Hard map[string]string `json:"hard"`
}

type kubernetesNetworkPolicySpec struct {
	PodSelector kubernetesSelector              `json:"podSelector"`
	PolicyTypes []string                        `json:"policyTypes"`
	Egress      []kubernetesNetworkPolicyEgress `json:"egress,omitempty"`
}

type kubernetesNetworkPolicyEgress struct {
	To    []kubernetesNetworkPolicyPeer `json:"to"`
	Ports []kubernetesNetworkPolicyPort `json:"ports,omitempty"`
}

type kubernetesNetworkPolicyPeer struct {
	PodSelector       kubernetesSelector  `json:"podSelector"`
	NamespaceSelector *kubernetesSelector `json:"namespaceSelector,omitempty"`
}

type kubernetesNetworkPolicyPort struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

func networkPolicySpec(rules *NetworkRules) kubernetesNetworkPolicySpec {
	selector := kubernetesSelector{MatchLabels: map[string]string{}}
	if rules.Subject != "" {
		selector.MatchLabels[resourceLabel] = string(rules.Subject)
	}
	spec := kubernetesNetworkPolicySpec{PodSelector: selector, PolicyTypes: []string{"Egress"}}
	if rules.AllowDNS {
		namespaceSelector := kubernetesSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}}
		spec.Egress = append(spec.Egress, kubernetesNetworkPolicyEgress{
			To: []kubernetesNetworkPolicyPeer{{
				PodSelector:       kubernetesSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}},
				NamespaceSelector: &namespaceSelector,
			}},
			Ports: []kubernetesNetworkPolicyPort{{Protocol: "UDP", Port: 53}, {Protocol: "TCP", Port: 53}},
		})
	}
	for _, target := range rules.AllowedEgress {
		spec.Egress = append(spec.Egress, kubernetesNetworkPolicyEgress{To: []kubernetesNetworkPolicyPeer{{PodSelector: kubernetesSelector{MatchLabels: map[string]string{resourceLabel: string(target)}}}}})
	}
	return spec
}

func stackLabels(stack string, profile Profile) map[string]string {
	return map[string]string{partOfLabel: "agent-runtime", stackLabel: stack, profileLabel: string(profile)}
}

func resourceLabels(stack string, profile Profile, resource ResourceID) map[string]string {
	labels := stackLabels(stack, profile)
	labels[resourceLabel] = string(resource)
	return labels
}

func cloneManifest(manifest KubernetesManifest) KubernetesManifest {
	clone := manifest
	clone.Metadata.Labels = cloneStringMap(manifest.Metadata.Labels)
	clone.Data = cloneStringMap(manifest.Data)
	clone.Spec = append(json.RawMessage(nil), manifest.Spec...)
	clone.Rules = append([]kubernetesRoleRule(nil), manifest.Rules...)
	clone.Subjects = append([]kubernetesSubject(nil), manifest.Subjects...)
	if manifest.RoleRef != nil {
		roleReference := *manifest.RoleRef
		clone.RoleRef = &roleReference
	}
	return clone
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func marshalJSON(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

func milliCPUQuantity(value int) string { return fmt.Sprintf("%dm", value) }

func byteQuantity(value int64) string {
	for _, unit := range []struct {
		divisor int64
		suffix  string
	}{{1 << 30, "Gi"}, {1 << 20, "Mi"}, {1 << 10, "Ki"}} {
		if value%unit.divisor == 0 {
			return fmt.Sprintf("%d%s", value/unit.divisor, unit.suffix)
		}
	}
	return fmt.Sprintf("%d", value)
}
