// Package agentspecbackfillkube adapts the fixed AgentSpecBackfill Kubernetes resource to controller ports.
package agentspecbackfillkube

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/0x63616c/agent-runtime/internal/agentspecbackfill"
	"github.com/0x63616c/agent-runtime/internal/agentspecbackfillcr"
	"github.com/0x63616c/agent-runtime/internal/agentspecbackfillprocess"
	"github.com/cockroachdb/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

const maximumRequestTimeout = 30 * time.Second

var agentSpecBackfillResource = schema.GroupVersionResource{Group: "runtime.0x63616c.dev", Version: "v1alpha1", Resource: "agentspecbackfills"}

var (
	// ErrUnavailable identifies a Kubernetes API failure that may recover after a fresh list/watch.
	ErrUnavailable = errors.New("AgentSpecBackfill Kubernetes API unavailable")
	// ErrInvalidObject identifies a resource that is not the exact structural AgentSpecBackfill type.
	ErrInvalidObject = errors.New("AgentSpecBackfill Kubernetes object is invalid")
	// ErrConflict identifies a terminal status race whose winner cannot be safely accepted.
	ErrConflict = errors.New("AgentSpecBackfill Kubernetes status conflict")
	// ErrPermissionDenied identifies an API identity without the controller's declared resource authority.
	ErrPermissionDenied = errors.New("AgentSpecBackfill Kubernetes permission denied")
	// ErrRequestMissing identifies an immutable request that disappeared before terminal observation or status write.
	ErrRequestMissing = errors.New("AgentSpecBackfill Kubernetes request is missing")
)

// Config declares the complete explicit Kubernetes control-plane connection for one controller instance.
type Config struct {
	APIServerURL   string
	Namespace      string
	CAFile         string
	TokenFile      string
	TLSServerName  string
	RequestTimeout time.Duration
}

// Resource is the narrow namespaced dynamic resource interface required by the adapter.
type Resource interface {
	List(context.Context, metav1.ListOptions) (*unstructured.UnstructuredList, error)
	Watch(context.Context, metav1.ListOptions) (watch.Interface, error)
	Get(context.Context, string, metav1.GetOptions) (*unstructured.Unstructured, error)
	UpdateStatus(context.Context, *unstructured.Unstructured, metav1.UpdateOptions) (*unstructured.Unstructured, error)
}

// Adapter maps only the fixed AgentSpecBackfill resource to the controller's Source and StatusStore ports.
type Adapter struct {
	resource  Resource
	namespace string
	mutex     sync.Mutex
	version   string
}

var _ agentspecbackfillprocess.Source = (*Adapter)(nil)
var _ agentspecbackfillprocess.StatusStore = (*Adapter)(nil)

// New constructs an Adapter from a complete explicit configuration and one injected namespaced resource.
func New(config Config, resource Resource) (*Adapter, error) {
	if err := config.validate(); err != nil || resource == nil {
		return nil, errors.New("create AgentSpecBackfill Kubernetes adapter: explicit valid configuration and resource are required")
	}
	return &Adapter{resource: resource, namespace: config.Namespace}, nil
}

// NewREST constructs an Adapter using only the declared Kubernetes API endpoint and projected ServiceAccount token.
func NewREST(config Config) (*Adapter, error) {
	restConfig, err := restConfig(config)
	if err != nil {
		return nil, err
	}
	client, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, errors.Wrap(err, "create AgentSpecBackfill Kubernetes dynamic client")
	}
	return New(config, dynamicResource{resource: client.Resource(agentSpecBackfillResource).Namespace(config.Namespace)})
}

func restConfig(config Config) (*rest.Config, error) {
	if err := config.validate(); err != nil {
		return nil, errors.Wrap(err, "create AgentSpecBackfill Kubernetes REST configuration")
	}
	return &rest.Config{Host: config.APIServerURL, TLSClientConfig: rest.TLSClientConfig{CAFile: config.CAFile, ServerName: config.TLSServerName}, BearerTokenFile: config.TokenFile, Timeout: config.RequestTimeout, UserAgent: "agent-runtime-agent-spec-backfill-controller", DisableCompression: true, QPS: 5, Burst: 10, Proxy: func(*http.Request) (*url.URL, error) { return nil, nil }}, nil
}

// List projects a current namespaced list into deterministic canonical immutable request wires.
func (adapter *Adapter) List(ctx context.Context) ([][]byte, error) {
	if ctx == nil {
		return nil, errors.New("list AgentSpecBackfill requests: context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	items, err := adapter.resource.List(ctx, metav1.ListOptions{})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, classifyAPIError("list AgentSpecBackfill requests", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if items == nil || items.GetResourceVersion() == "" {
		return nil, errors.Wrap(ErrInvalidObject, "list AgentSpecBackfill requests: resource version is required")
	}
	wires := make([][]byte, 0, len(items.Items))
	for index := range items.Items {
		request, err := requestFromObject(adapter.namespace, &items.Items[index])
		if err != nil {
			return nil, errors.Wrap(err, "list AgentSpecBackfill requests")
		}
		wire, err := request.Canonical()
		if err != nil {
			return nil, errors.Wrap(ErrInvalidObject, "list AgentSpecBackfill requests: canonical request")
		}
		wires = append(wires, wire)
	}
	sort.Slice(wires, func(left, right int) bool { return bytes.Compare(wires[left], wires[right]) < 0 })
	adapter.mutex.Lock()
	adapter.version = items.GetResourceVersion()
	adapter.mutex.Unlock()
	return wires, nil
}

// Watch opens a cancellable fixed-resource watch from the preceding list resource version.
func (adapter *Adapter) Watch(ctx context.Context) (agentspecbackfillprocess.Watch, error) {
	if ctx == nil {
		return nil, errors.New("watch AgentSpecBackfill requests: context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	adapter.mutex.Lock()
	version := adapter.version
	adapter.mutex.Unlock()
	if version == "" {
		return nil, errors.Wrap(ErrInvalidObject, "watch AgentSpecBackfill requests: list resource version is required")
	}
	stream, err := adapter.resource.Watch(ctx, metav1.ListOptions{ResourceVersion: version, AllowWatchBookmarks: true})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, classifyAPIError("watch AgentSpecBackfill requests", err)
	}
	if stream == nil {
		return nil, errors.Wrap(ErrUnavailable, "watch AgentSpecBackfill requests: stream is required")
	}
	if err := ctx.Err(); err != nil {
		stream.Stop()
		return nil, err
	}
	return &watchReader{stream: stream, namespace: adapter.namespace}, nil
}

// ReadTerminal returns the exact existing terminal status bound to one immutable request.
func (adapter *Adapter) ReadTerminal(ctx context.Context, request agentspecbackfillcr.Request) (agentspecbackfillcr.Status, bool, error) {
	_, status, terminal, err := adapter.read(ctx, request)
	return status, terminal, err
}

// CreateTerminal conditionally records one terminal status without overwriting an existing terminal winner.
func (adapter *Adapter) CreateTerminal(ctx context.Context, request agentspecbackfillcr.Request, candidate agentspecbackfillcr.Status) (agentspecbackfillcr.Status, bool, error) {
	if ctx == nil {
		return agentspecbackfillcr.Status{}, false, errors.New("record AgentSpecBackfill terminal status: context is required")
	}
	if err := ctx.Err(); err != nil {
		return agentspecbackfillcr.Status{}, false, err
	}
	if _, err := candidate.CanonicalFor(request, candidate.CompletedAt); err != nil {
		return agentspecbackfillcr.Status{}, false, errors.Wrap(ErrInvalidObject, "record AgentSpecBackfill terminal status: candidate is invalid")
	}
	object, stored, terminal, err := adapter.read(ctx, request)
	if err != nil {
		return agentspecbackfillcr.Status{}, false, err
	}
	if terminal {
		return stored, false, nil
	}
	if object.GetResourceVersion() == "" {
		return agentspecbackfillcr.Status{}, false, errors.Wrap(ErrInvalidObject, "record AgentSpecBackfill terminal status: resource version is required")
	}
	statusObject, err := statusObject(request, candidate)
	if err != nil {
		return agentspecbackfillcr.Status{}, false, errors.Wrap(ErrInvalidObject, "record AgentSpecBackfill terminal status")
	}
	updated := object.DeepCopy()
	if err := unstructured.SetNestedMap(updated.Object, statusObject, "status"); err != nil {
		return agentspecbackfillcr.Status{}, false, errors.Wrap(ErrInvalidObject, "record AgentSpecBackfill terminal status")
	}
	if err := ctx.Err(); err != nil {
		return agentspecbackfillcr.Status{}, false, err
	}
	result, err := adapter.resource.UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	if err != nil {
		if ctx.Err() != nil {
			return agentspecbackfillcr.Status{}, false, ctx.Err()
		}
		classified := classifyAPIError("record AgentSpecBackfill terminal status", err)
		if !errors.Is(classified, ErrConflict) {
			return agentspecbackfillcr.Status{}, false, classified
		}
		return adapter.resolveConflict(ctx, request, err)
	}
	if err := ctx.Err(); err != nil {
		return agentspecbackfillcr.Status{}, false, err
	}
	actual, status, terminal, err := adapter.observe(request, result)
	if err != nil || !terminal || !sameStatus(status, candidate) || actual.GetResourceVersion() == object.GetResourceVersion() {
		return agentspecbackfillcr.Status{}, false, errors.Wrap(ErrInvalidObject, "record AgentSpecBackfill terminal status: status result is invalid")
	}
	return status, true, nil
}

func (adapter *Adapter) resolveConflict(ctx context.Context, request agentspecbackfillcr.Request, updateErr error) (agentspecbackfillcr.Status, bool, error) {
	_ = updateErr
	_, stored, terminal, err := adapter.read(ctx, request)
	if err != nil {
		return agentspecbackfillcr.Status{}, false, err
	}
	if terminal {
		return stored, false, nil
	}
	return agentspecbackfillcr.Status{}, false, errors.Wrap(ErrConflict, "record AgentSpecBackfill terminal status")
}

type statusProjection struct {
	Phase                 agentspecbackfill.Phase  `json:"phase"`
	RequestUID            string                   `json:"requestUID"`
	ObservedGeneration    uint64                   `json:"observedGeneration"`
	ControllerImageDigest string                   `json:"controllerImageDigest"`
	RequestDigest         string                   `json:"requestDigest"`
	SnapshotFingerprint   string                   `json:"snapshotFingerprint"`
	SnapshotCount         uint64                   `json:"snapshotCount"`
	ManifestDigest        string                   `json:"manifestDigest"`
	StaticReadinessDigest string                   `json:"staticReadinessDigest"`
	VerifiedCount         uint64                   `json:"verifiedCount"`
	Reason                agentspecbackfill.Reason `json:"reason,omitempty"`
	CompletedAt           time.Time                `json:"completedAt"`
}

func statusFromObject(object *unstructured.Unstructured) (agentspecbackfillcr.Status, bool, error) {
	if object == nil {
		return agentspecbackfillcr.Status{}, false, ErrInvalidObject
	}
	value, found, err := unstructured.NestedMap(object.Object, "status")
	if err != nil {
		return agentspecbackfillcr.Status{}, false, ErrInvalidObject
	}
	if !found {
		return agentspecbackfillcr.Status{}, false, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return agentspecbackfillcr.Status{}, false, ErrInvalidObject
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var decoded statusProjection
	if err := decoder.Decode(&decoded); err != nil {
		return agentspecbackfillcr.Status{}, false, errors.Wrap(ErrInvalidObject, "decode AgentSpecBackfill status")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return agentspecbackfillcr.Status{}, false, ErrInvalidObject
	}
	return agentspecbackfillcr.Status{Phase: decoded.Phase, RequestUID: decoded.RequestUID, ObservedGeneration: decoded.ObservedGeneration, ControllerImageDigest: decoded.ControllerImageDigest, RequestDigest: decoded.RequestDigest, SnapshotFingerprint: decoded.SnapshotFingerprint, SnapshotCount: decoded.SnapshotCount, ManifestDigest: decoded.ManifestDigest, StaticReadinessDigest: decoded.StaticReadinessDigest, VerifiedCount: decoded.VerifiedCount, Reason: decoded.Reason, CompletedAt: decoded.CompletedAt}, true, nil
}

func statusObject(request agentspecbackfillcr.Request, status agentspecbackfillcr.Status) (map[string]any, error) {
	encoded, err := status.CanonicalFor(request, status.CompletedAt)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := json.Unmarshal(encoded, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func sameStatus(left, right agentspecbackfillcr.Status) bool {
	return left.Phase == right.Phase && left.RequestUID == right.RequestUID && left.ObservedGeneration == right.ObservedGeneration && left.ControllerImageDigest == right.ControllerImageDigest && left.RequestDigest == right.RequestDigest && left.SnapshotFingerprint == right.SnapshotFingerprint && left.SnapshotCount == right.SnapshotCount && left.ManifestDigest == right.ManifestDigest && left.StaticReadinessDigest == right.StaticReadinessDigest && left.VerifiedCount == right.VerifiedCount && left.Reason == right.Reason && left.CompletedAt.Equal(right.CompletedAt)
}

func (adapter *Adapter) read(ctx context.Context, request agentspecbackfillcr.Request) (*unstructured.Unstructured, agentspecbackfillcr.Status, bool, error) {
	if ctx == nil {
		return nil, agentspecbackfillcr.Status{}, false, errors.New("read AgentSpecBackfill terminal status: context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, agentspecbackfillcr.Status{}, false, err
	}
	object, err := adapter.resource.Get(ctx, request.Metadata.Name, metav1.GetOptions{})
	if err != nil {
		if ctx.Err() != nil {
			return nil, agentspecbackfillcr.Status{}, false, ctx.Err()
		}
		return nil, agentspecbackfillcr.Status{}, false, classifyAPIError("read AgentSpecBackfill terminal status", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, agentspecbackfillcr.Status{}, false, err
	}
	actual, status, terminal, err := adapter.observe(request, object)
	if err != nil {
		return nil, agentspecbackfillcr.Status{}, false, err
	}
	return actual, status, terminal, nil
}

func (adapter *Adapter) observe(request agentspecbackfillcr.Request, object *unstructured.Unstructured) (*unstructured.Unstructured, agentspecbackfillcr.Status, bool, error) {
	actual, err := requestFromObject(adapter.namespace, object)
	if err != nil || request.ValidateImmutableMutation(actual) != nil {
		return nil, agentspecbackfillcr.Status{}, false, errors.Wrap(ErrInvalidObject, "observe AgentSpecBackfill request")
	}
	status, found, err := statusFromObject(object)
	if err != nil {
		return nil, agentspecbackfillcr.Status{}, false, errors.Wrap(err, "observe AgentSpecBackfill status")
	}
	terminal := found && (status.Phase == agentspecbackfill.PhaseVerified || status.Phase == agentspecbackfill.PhaseRefused)
	if found && !terminal && status.ValidateFor(request, time.Time{}) != nil {
		return nil, agentspecbackfillcr.Status{}, false, errors.Wrap(ErrInvalidObject, "observe AgentSpecBackfill nonterminal status")
	}
	if terminal {
		if _, err := status.CanonicalFor(request, status.CompletedAt); err != nil {
			return nil, agentspecbackfillcr.Status{}, false, errors.Wrap(ErrInvalidObject, "observe AgentSpecBackfill terminal status")
		}
	}
	return object, status, terminal, nil
}

func (config Config) validate() error {
	endpoint, err := url.Parse(config.APIServerURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" {
		return errors.New("AgentSpecBackfill Kubernetes API endpoint is invalid")
	}
	if len(validation.IsDNS1123Label(config.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(config.TLSServerName)) != 0 || !safeAbsolutePath(config.CAFile) || !safeAbsolutePath(config.TokenFile) || config.RequestTimeout <= 0 || config.RequestTimeout > maximumRequestTimeout {
		return errors.New("AgentSpecBackfill Kubernetes configuration is invalid")
	}
	return nil
}

func classifyAPIError(operation string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	switch {
	case apierrors.IsNotFound(err):
		return errors.Wrap(ErrRequestMissing, operation)
	case apierrors.IsConflict(err):
		return errors.Wrap(ErrConflict, operation)
	case apierrors.IsForbidden(err), apierrors.IsUnauthorized(err):
		return errors.Wrap(ErrPermissionDenied, operation)
	default:
		return errors.Wrap(ErrUnavailable, operation)
	}
}

func safeAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.Contains(path, "..")
}

type watchReader struct {
	stream    watch.Interface
	namespace string
}

type dynamicResource struct{ resource dynamic.ResourceInterface }

func (resource dynamicResource) List(ctx context.Context, options metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return resource.resource.List(ctx, options)
}

func (resource dynamicResource) Watch(ctx context.Context, options metav1.ListOptions) (watch.Interface, error) {
	return resource.resource.Watch(ctx, options)
}

func (resource dynamicResource) Get(ctx context.Context, name string, options metav1.GetOptions) (*unstructured.Unstructured, error) {
	return resource.resource.Get(ctx, name, options)
}

func (resource dynamicResource) UpdateStatus(ctx context.Context, object *unstructured.Unstructured, options metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	return resource.resource.UpdateStatus(ctx, object, options)
}

func (reader *watchReader) Next(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("read AgentSpecBackfill watch: context is required")
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case event, open := <-reader.stream.ResultChan():
			if !open {
				return nil, errors.Wrap(ErrUnavailable, "read AgentSpecBackfill watch: stream closed")
			}
			if event.Type == watch.Bookmark || event.Type == watch.Deleted {
				continue
			}
			if event.Type == watch.Error {
				return nil, classifyAPIError("read AgentSpecBackfill watch", apierrors.FromObject(event.Object))
			}
			if event.Type != watch.Added && event.Type != watch.Modified {
				return nil, errors.Wrap(ErrUnavailable, "read AgentSpecBackfill watch: unexpected event")
			}
			object, ok := event.Object.(*unstructured.Unstructured)
			if !ok {
				return nil, errors.Wrap(ErrInvalidObject, "read AgentSpecBackfill watch")
			}
			request, err := requestFromObject(reader.namespace, object)
			if err != nil {
				return nil, errors.Wrap(err, "read AgentSpecBackfill watch")
			}
			wire, err := request.Canonical()
			if err != nil {
				return nil, errors.Wrap(ErrInvalidObject, "read AgentSpecBackfill watch: canonical request")
			}
			return wire, nil
		}
	}
}

func (reader *watchReader) Close() error {
	if reader == nil || reader.stream == nil {
		return errors.New("close AgentSpecBackfill watch: stream is required")
	}
	reader.stream.Stop()
	return nil
}

type requestSpec struct {
	StackDigest              string    `json:"stackDigest"`
	MigrationVersion         uint32    `json:"migrationVersion"`
	MigrationArtifactDigest  string    `json:"migrationArtifactDigest"`
	ManifestDigest           string    `json:"manifestDigest"`
	ControllerImageDigest    string    `json:"controllerImageDigest"`
	SnapshotFingerprint      string    `json:"snapshotFingerprint"`
	SnapshotCount            uint64    `json:"snapshotCount"`
	FenceNonce               string    `json:"fenceNonce"`
	CreatedAt                time.Time `json:"createdAt"`
	StaticReadinessDigest    string    `json:"staticReadinessDigest"`
	DatabaseAuthorityDigest  string    `json:"databaseAuthorityDigest"`
	BlobReadCapabilityDigest string    `json:"blobReadCapabilityDigest"`
	RequestExpiresAt         time.Time `json:"requestExpiresAt"`
}

func requestFromObject(namespace string, object *unstructured.Unstructured) (agentspecbackfillcr.Request, error) {
	if object == nil || object.GetAPIVersion() != agentspecbackfillcr.APIVersion || object.GetKind() != agentspecbackfillcr.Kind || object.GetNamespace() != namespace || object.GetName() == "" || object.GetUID() == "" || object.GetGeneration() <= 0 {
		return agentspecbackfillcr.Request{}, ErrInvalidObject
	}
	specification, found, err := unstructured.NestedMap(object.Object, "spec")
	if err != nil || !found {
		return agentspecbackfillcr.Request{}, ErrInvalidObject
	}
	encoded, err := json.Marshal(specification)
	if err != nil {
		return agentspecbackfillcr.Request{}, ErrInvalidObject
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var decoded requestSpec
	if err := decoder.Decode(&decoded); err != nil {
		return agentspecbackfillcr.Request{}, errors.Wrap(ErrInvalidObject, "decode AgentSpecBackfill spec")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return agentspecbackfillcr.Request{}, ErrInvalidObject
	}
	request := agentspecbackfillcr.Request{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Metadata: agentspecbackfillcr.Metadata{Name: object.GetName(), UID: string(object.GetUID()), Generation: uint64(object.GetGeneration())}, Spec: agentspecbackfill.Request{StackDigest: decoded.StackDigest, MigrationVersion: decoded.MigrationVersion, MigrationArtifactDigest: decoded.MigrationArtifactDigest, ManifestDigest: decoded.ManifestDigest, ControllerImageDigest: decoded.ControllerImageDigest, SnapshotFingerprint: decoded.SnapshotFingerprint, SnapshotCount: decoded.SnapshotCount, FenceNonce: decoded.FenceNonce, CreatedAt: decoded.CreatedAt, StaticReadinessDigest: decoded.StaticReadinessDigest, DatabaseAuthorityDigest: decoded.DatabaseAuthorityDigest, BlobReadCapabilityDigest: decoded.BlobReadCapabilityDigest, ExpiresAt: decoded.RequestExpiresAt}}
	if _, err := request.Canonical(); err != nil {
		return agentspecbackfillcr.Request{}, errors.Wrap(ErrInvalidObject, "validate AgentSpecBackfill request")
	}
	return request, nil
}
