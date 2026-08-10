package temporalpayloaduiprocess

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRedactDiagnosticsStreamsSuccessfulResponses(t *testing.T) {
	target := &recordingResponseWriter{header: make(http.Header)}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if _, err := writer.Write([]byte("first")); err != nil {
			t.Fatalf("write first: %v", err)
		}
		if target.writes != 1 {
			t.Fatalf("writes while handler is active = %d, want 1", target.writes)
		}
		if _, err := writer.Write([]byte("second")); err != nil {
			t.Fatalf("write second: %v", err)
		}
	})

	redactDiagnostics(handler).ServeHTTP(target, httptest.NewRequest(http.MethodPost, "/decode", nil))
	if got := target.body.String(); got != "firstsecond" {
		t.Fatalf("body = %q, want streamed response", got)
	}
}

func TestShutdownTimeoutCoversMaximumCodecIO(t *testing.T) {
	if got := shutdownTimeout(time.Minute); got < time.Minute {
		t.Fatalf("shutdown timeout = %s, want at least maximum codec I/O timeout", got)
	}
}

type recordingResponseWriter struct {
	header http.Header
	status int
	body   stringBuilder
	writes int
}

func (writer *recordingResponseWriter) Header() http.Header { return writer.header }

func (writer *recordingResponseWriter) WriteHeader(status int) {
	if writer.status == 0 {
		writer.status = status
	}
}

func (writer *recordingResponseWriter) Write(value []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	writer.writes++
	return writer.body.Write(value)
}

type stringBuilder struct{ value []byte }

func (builder *stringBuilder) Write(value []byte) (int, error) {
	builder.value = append(builder.value, value...)
	return len(value), nil
}

func (builder *stringBuilder) String() string { return string(builder.value) }
