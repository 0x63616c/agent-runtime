package temporalpayloaduiprocess

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/0x63616c/agent-runtime/temporalpayload"
	"github.com/cockroachdb/errors"
)

const shutdownSchedulingAllowance = 5 * time.Second

// Serve runs the authenticated Temporal UI inspection handler on an already-owned listener.
func Serve(ctx context.Context, config Config, store temporalpayload.BlobStore, authorizer temporalpayload.UIRequestAuthorizer, listener net.Listener) error {
	if ctx == nil || store == nil || authorizer == nil || listener == nil {
		return errors.New("serve Temporal UI payload process: context, blob store, authorizer, and listener are required")
	}
	codec, err := temporalpayload.NewCodec(store,
		temporalpayload.WithBlobPrefix(config.blobPrefix),
		temporalpayload.WithMaximumBlobBytes(config.maximumBlobBytes),
		temporalpayload.WithIOTimeout(config.ioTimeout),
	)
	if err != nil {
		return errors.Wrap(err, "serve Temporal UI payload process: construct local codec")
	}
	handler, err := temporalpayload.NewUIHandler(codec,
		temporalpayload.WithTemporalUINamespaces(config.namespaces...),
		temporalpayload.WithTemporalUIOrigins(config.origins...),
		temporalpayload.WithTemporalUIRequestAuthorizer(authorizer),
	)
	if err != nil {
		return errors.Wrap(err, "serve Temporal UI payload process: construct handler")
	}
	boundedHandler := http.MaxBytesHandler(redactDiagnostics(handler), int64(config.maximumBlobBytes)*2)
	server := &http.Server{Handler: boundedHandler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.Wrap(err, "serve Temporal UI payload process")
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout(config.ioTimeout))
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			if closeErr := server.Close(); closeErr != nil && !errors.Is(closeErr, http.ErrServerClosed) {
				return errors.Join(errors.Wrap(err, "stop Temporal UI payload process"), errors.Wrap(closeErr, "force-close Temporal UI payload process"))
			}
			if serveErr := <-result; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				return errors.Join(errors.Wrap(err, "stop Temporal UI payload process"), errors.Wrap(serveErr, "force-close Temporal UI payload process"))
			}
			return errors.Wrap(err, "stop Temporal UI payload process")
		}
		if err := <-result; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errors.Wrap(err, "stop Temporal UI payload process")
		}
		return nil
	}
}

func shutdownTimeout(ioTimeout time.Duration) time.Duration {
	return ioTimeout + shutdownSchedulingAllowance
}

func redactDiagnostics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		response := &diagnosticResponseWriter{ResponseWriter: writer}
		next.ServeHTTP(response, request)
		response.finish()
	})
}

type diagnosticResponseWriter struct {
	http.ResponseWriter
	status    int
	committed bool
}

func (writer *diagnosticResponseWriter) WriteHeader(status int) {
	if writer.status != 0 {
		return
	}
	writer.status = status
	if redactsDiagnostics(status) {
		return
	}
	writer.ResponseWriter.WriteHeader(status)
	writer.committed = true
}

func (writer *diagnosticResponseWriter) Write(value []byte) (int, error) {
	if writer.status == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	if redactsDiagnostics(writer.status) {
		return len(value), nil
	}
	return writer.ResponseWriter.Write(value)
}

func (writer *diagnosticResponseWriter) finish() {
	if writer.status == 0 || writer.committed || !redactsDiagnostics(writer.status) {
		return
	}
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.ResponseWriter.WriteHeader(writer.status)
	writer.committed = true
	_, _ = writer.ResponseWriter.Write([]byte("Temporal UI payload transformation failed\n"))
}

func redactsDiagnostics(status int) bool {
	return status >= http.StatusBadRequest && status != http.StatusUnauthorized && status != http.StatusForbidden && status != http.StatusNotFound
}
