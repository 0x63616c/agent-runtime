package temporalpayload

import (
	"net/http"
	"slices"

	"github.com/cockroachdb/errors"
	"go.temporal.io/sdk/converter"
)

const authorizationExtrasHeader = "authorization-extras"

// UIHandlerOption configures the authenticated Temporal UI inspection handler.
type UIHandlerOption interface {
	applyUIHandler(*uiHandlerConfig) error
}

type uiHandlerOptionFunc func(*uiHandlerConfig) error

func (option uiHandlerOptionFunc) applyUIHandler(config *uiHandlerConfig) error {
	return option(config)
}

// WithTemporalUINamespaces limits the handler to the declared Temporal namespaces.
func WithTemporalUINamespaces(namespaces ...string) UIHandlerOption {
	return uiHandlerOptionFunc(func(config *uiHandlerConfig) error {
		if len(namespaces) == 0 {
			return errors.New("at least one Temporal UI namespace is required")
		}
		for _, namespace := range namespaces {
			if namespace == "" {
				return errors.New("Temporal UI namespace is empty")
			}
		}
		config.namespaces = slices.Clone(namespaces)
		return nil
	})
}

// WithTemporalUIOrigins limits browser access to the declared Temporal UI origins.
func WithTemporalUIOrigins(origins ...string) UIHandlerOption {
	return uiHandlerOptionFunc(func(config *uiHandlerConfig) error {
		for _, origin := range origins {
			if origin == "" {
				return errors.New("Temporal UI origin is empty")
			}
		}
		config.origins = slices.Clone(origins)
		return nil
	})
}

// WithTemporalUIRequestAuthorizer requires trusted authentication and namespace authorization.
func WithTemporalUIRequestAuthorizer(authorizer UIRequestAuthorizer) UIHandlerOption {
	return uiHandlerOptionFunc(func(config *uiHandlerConfig) error {
		if authorizer == nil {
			return errors.New("Temporal UI request authorizer is required")
		}
		config.authorizer = authorizer
		return nil
	})
}

type uiHandlerConfig struct {
	namespaces []string
	origins    []string
	authorizer UIRequestAuthorizer
}

// AuthorizationDecision reports the result of an authentication and namespace-authorization check.
//
// It deliberately contains no credential, header, token, or principal value so
// the payload package has nothing sensitive to log or retain.
type AuthorizationDecision struct {
	Authenticated bool
	Allowed       bool
}

// UIRequestAuthorizer authenticates a Temporal UI request and authorizes its
// requested namespace. Implementations must establish identity from a trusted
// boundary (for example verified OIDC middleware or an mTLS peer), rather than
// treating X-Namespace, Origin, or a network location as authentication.
//
// The handler passes the full request so an implementation can read trusted
// authentication context installed by its enclosing middleware. It must not
// retain or log request credentials.
type UIRequestAuthorizer interface {
	AuthorizeTemporalPayloadUI(request *http.Request, namespace string) (AuthorizationDecision, error)
}

// UIRequestAuthorizerFunc adapts a function into a UIRequestAuthorizer.
type UIRequestAuthorizerFunc func(request *http.Request, namespace string) (AuthorizationDecision, error)

// AuthorizeTemporalPayloadUI calls authorizer.
func (authorizer UIRequestAuthorizerFunc) AuthorizeTemporalPayloadUI(request *http.Request, namespace string) (AuthorizationDecision, error) {
	return authorizer(request, namespace)
}

// NewUIHandler creates the authenticated HTTP adapter used only by Temporal UI inspection.
func NewUIHandler(codec *Codec, options ...UIHandlerOption) (http.Handler, error) {
	if codec == nil {
		return nil, errors.New("temporal payload codec is required for UI handler")
	}
	config := uiHandlerConfig{}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("Temporal UI handler option is nil")
		}
		if err := option.applyUIHandler(&config); err != nil {
			return nil, errors.Wrap(err, "configure Temporal UI payload handler")
		}
	}
	if len(config.namespaces) == 0 {
		return nil, errors.New("at least one Temporal UI namespace is required")
	}
	if config.authorizer == nil {
		return nil, errors.New("Temporal UI request authorizer is required")
	}
	codecHandler := converter.NewPayloadCodecHTTPHandler(codec)
	return cors(config.origins, authorizationGuard(config.authorizer, namespaceGuard(config.namespaces, codecHandler))), nil
}

func authorizationGuard(authorizer UIRequestAuthorizer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		decision, err := authorizer.AuthorizeTemporalPayloadUI(request, request.Header.Get("X-Namespace"))
		if err != nil {
			http.Error(writer, "Temporal UI authorization failed", http.StatusInternalServerError)
			return
		}
		if !decision.Authenticated {
			http.Error(writer, "Temporal UI authentication is required", http.StatusUnauthorized)
			return
		}
		if !decision.Allowed {
			http.Error(writer, "Temporal UI request is not authorized", http.StatusForbidden)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func namespaceGuard(namespaces []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !slices.Contains(namespaces, request.Header.Get("X-Namespace")) {
			http.Error(writer, "Temporal namespace is not authorized", http.StatusForbidden)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func cors(origins []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		origin := request.Header.Get("Origin")
		if origin != "" {
			if !slices.Contains(origins, origin) {
				http.Error(writer, "Temporal UI origin is not authorized", http.StatusForbidden)
				return
			}
			writer.Header().Set("Access-Control-Allow-Origin", origin)
			writer.Header().Set("Access-Control-Allow-Methods", http.MethodPost)
			writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Namespace, Authorization, "+authorizationExtrasHeader)
			writer.Header().Set("Vary", "Origin")
			if request.Method == http.MethodOptions {
				writer.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(writer, request)
	})
}
