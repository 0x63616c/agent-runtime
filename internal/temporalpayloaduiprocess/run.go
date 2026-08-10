package temporalpayloaduiprocess

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"time"

	"github.com/0x63616c/agent-runtime/temporalpayload"
	"github.com/cockroachdb/errors"
)

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
		shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return errors.Wrap(err, "stop Temporal UI payload process")
		}
		if err := <-result; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errors.Wrap(err, "stop Temporal UI payload process")
		}
		return nil
	}
}

type bufferedResponseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{header: make(http.Header), status: http.StatusOK}
}

func (writer *bufferedResponseWriter) Header() http.Header { return writer.header }

func (writer *bufferedResponseWriter) WriteHeader(status int) {
	if writer.status != http.StatusOK || writer.body.Len() > 0 {
		return
	}
	writer.status = status
}

func (writer *bufferedResponseWriter) Write(value []byte) (int, error) {
	return writer.body.Write(value)
}

func redactDiagnostics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		buffered := newBufferedResponseWriter()
		next.ServeHTTP(buffered, request)
		for key, values := range buffered.header {
			writer.Header()[key] = append([]string(nil), values...)
		}
		if buffered.status >= http.StatusBadRequest && buffered.status != http.StatusUnauthorized && buffered.status != http.StatusForbidden && buffered.status != http.StatusNotFound {
			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			writer.WriteHeader(buffered.status)
			_, _ = writer.Write([]byte("Temporal UI payload transformation failed\n"))
			return
		}
		writer.WriteHeader(buffered.status)
		_, _ = writer.Write(buffered.body.Bytes())
	})
}
