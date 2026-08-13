// Package tooldispatch exposes the private trigger boundary for broker-owned
// tool dispatch. Callers never receive a descriptor, grant, lease, or result.
package tooldispatch

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/0x63616c/agent-runtime/internal/runtimetool"
)

const (
	Audience = "runtime-tool-dispatch/v1"
	Role     = "tool"
)

// Receipt intentionally reveals no work identity or output.
type Receipt struct {
	Attempted bool `json:"attempted"`
}

// ScanOnce drains already-authorized durable tool work. The implementation is
// broker-owned and retains every execution authority.
type ScanOnce func(context.Context) error

// Server authenticates a trigger-only role to request one bounded scan.
type Server struct {
	token string
	scan  ScanOnce
}

func NewServer(token string, scan ScanOnce) (*Server, error) {
	if token == "" || scan == nil {
		return nil, errors.New("create tool dispatch service: token and scan are required")
	}
	return &Server{token: token, scan: scan}, nil
}

// NewBrokerServer composes the dispatch service with the broker-owned worker.
// The worker, not the trigger client, retains the state/content/adapter
// authorities required to claim, reconcile, and finalize an operation.
func NewBrokerServer(token string, worker *runtimetool.Worker) (*Server, error) {
	if worker == nil {
		return nil, errors.New("create tool dispatch service: broker worker is required")
	}
	return NewServer(token, worker.ScanOnce)
}

func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if server == nil || request.Method != http.MethodPost || request.URL.Path != "/private/v1/tool-dispatch/scan" || request.Header.Get("X-Tool-Dispatch-Audience") != Audience || request.Header.Get("X-Tool-Dispatch-Role") != Role || !authorized(request.Header.Get("Authorization"), server.token) || !emptyBody(request) {
		http.Error(writer, "not found", http.StatusNotFound)
		return
	}
	if err := server.scan(request.Context()); err != nil {
		http.Error(writer, "dispatch unavailable", http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(Receipt{Attempted: true})
}

func emptyBody(request *http.Request) bool {
	if request.ContentLength > 0 {
		return false
	}
	if request.Body == nil {
		return true
	}
	value := make([]byte, 1)
	read, err := request.Body.Read(value)
	return read == 0 && errors.Is(err, io.EOF)
}

func authorized(value, token string) bool {
	prefix := "Bearer "
	if len(value) != len(prefix)+len(token) || value[:len(prefix)] != prefix {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(value[len(prefix):]), []byte(token)) == 1
}
