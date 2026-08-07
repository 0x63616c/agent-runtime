package temporalpayload

import (
	"net/http"
	"slices"

	"github.com/cockroachdb/errors"
	"go.temporal.io/sdk/converter"
)

// UIHandlerOptions restricts a codec endpoint to authenticated Temporal UI requests.
type UIHandlerOptions struct {
	AllowedNamespaces []string
	AllowedOrigins    []string
	Authorizer        UIRequestAuthorizer
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
func NewUIHandler(codec *Codec, options UIHandlerOptions) (http.Handler, error) {
	if codec == nil {
		return nil, errors.New("temporal payload codec is required for UI handler")
	}
	if len(options.AllowedNamespaces) == 0 {
		return nil, errors.New("at least one Temporal UI namespace is required")
	}
	if options.Authorizer == nil {
		return nil, errors.New("Temporal UI request authorizer is required")
	}
	for _, namespace := range options.AllowedNamespaces {
		if namespace == "" {
			return nil, errors.New("Temporal UI namespace is empty")
		}
	}
	for _, origin := range options.AllowedOrigins {
		if origin == "" {
			return nil, errors.New("Temporal UI origin is empty")
		}
	}
	codecHandler := converter.NewPayloadCodecHTTPHandler(codec)
	return cors(options.AllowedOrigins, authorizationGuard(options.Authorizer, namespaceGuard(options.AllowedNamespaces, codecHandler))), nil
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
			writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Namespace")
			writer.Header().Set("Vary", "Origin")
			if request.Method == http.MethodOptions {
				writer.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(writer, request)
	})
}
