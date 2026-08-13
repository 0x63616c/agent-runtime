package observabilityassets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// This validates the checked-in collector deployment input. It intentionally
// stops short of claiming that a collector image, a trace store, or a
// Prometheus server has been deployed in an environment.
func TestOpenTelemetryCollectorContractAcceptsBothSignalsAndDoesNotExportSecrets(t *testing.T) {
	bytes, err := os.ReadFile(filepath.Clean("../../deploy/observability/otelcol/collector.yaml"))
	if err != nil {
		t.Fatalf("read collector contract: %v", err)
	}
	var contract collectorContract
	if err := yaml.Unmarshal(bytes, &contract); err != nil {
		t.Fatalf("decode collector contract: %v", err)
	}
	if contract.Receivers.OTLP.Protocols.GRPC.Endpoint != "0.0.0.0:4317" || contract.Receivers.OTLP.Protocols.HTTP.Endpoint != "0.0.0.0:4318" {
		t.Fatalf("OTLP receiver endpoints = %#v, want declared gRPC and HTTP endpoints", contract.Receivers.OTLP.Protocols)
	}
	assertCollectorPipeline(t, contract.Service.Pipelines.Traces, "otlphttp/trace-store")
	assertCollectorPipeline(t, contract.Service.Pipelines.Metrics, "prometheus")
	if contract.Exporters.OTLPHTTPTraceStore.Endpoint != "http://trace-store.telemetry.svc.cluster.local:4318" {
		t.Fatalf("trace-store endpoint = %q, want in-cluster trace store", contract.Exporters.OTLPHTTPTraceStore.Endpoint)
	}
	if contract.Exporters.OTLPHTTPTraceStore.Compression != "gzip" || contract.Exporters.OTLPHTTPTraceStore.Timeout != "5s" {
		t.Fatalf("trace-store transport = %#v, want bounded compressed export", contract.Exporters.OTLPHTTPTraceStore)
	}
	if contract.Exporters.Prometheus.Endpoint != "0.0.0.0:8889" || contract.Exporters.Prometheus.ResourceToTelemetryConversion.Enabled {
		t.Fatalf("Prometheus exporter = %#v, want local scrape endpoint without resource labels", contract.Exporters.Prometheus)
	}
	if contract.Processors.MemoryLimiter.LimitMiB <= contract.Processors.MemoryLimiter.SpikeLimitMiB || contract.Processors.MemoryLimiter.CheckInterval == "" {
		t.Fatalf("memory limiter = %#v, want bounded headroom", contract.Processors.MemoryLimiter)
	}
	if contract.Processors.Batch.SendBatchSize <= 0 || contract.Processors.Batch.Timeout == "" {
		t.Fatalf("batch processor = %#v, want bounded delivery", contract.Processors.Batch)
	}
	unsafe := map[string]bool{}
	for _, action := range contract.Processors.DropUnsafe.Actions {
		if action.Action != "delete" {
			t.Fatalf("unsafe attribute action = %#v, want deletion", action)
		}
		unsafe[action.Key] = true
	}
	for _, key := range []string{"http.request.header.authorization", "http.request.body", "http.response.body", "gen_ai.prompt", "gen_ai.completion", "runtime.model.reasoning", "runtime.tool.output", "process.command_args"} {
		if !unsafe[key] {
			t.Fatalf("collector does not delete unsafe attribute %q", key)
		}
	}
	text := strings.ToLower(string(bytes))
	for _, forbidden := range []string{"bearer", "api_key", "basicauth", "headers:", "https://"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("collector contract contains forbidden credential or external-export configuration %q", forbidden)
		}
	}
}

func assertCollectorPipeline(t *testing.T, pipeline collectorPipeline, exporter string) {
	t.Helper()
	if len(pipeline.Receivers) != 1 || pipeline.Receivers[0] != "otlp" {
		t.Fatalf("pipeline receivers = %#v, want OTLP only", pipeline.Receivers)
	}
	if strings.Join(pipeline.Processors, ",") != "memory_limiter,attributes/drop-unsafe,batch" {
		t.Fatalf("pipeline processors = %#v, want bounded redaction pipeline", pipeline.Processors)
	}
	if len(pipeline.Exporters) != 1 || pipeline.Exporters[0] != exporter {
		t.Fatalf("pipeline exporters = %#v, want %q", pipeline.Exporters, exporter)
	}
}

type collectorContract struct {
	Receivers struct {
		OTLP struct {
			Protocols struct {
				GRPC collectorEndpoint `yaml:"grpc"`
				HTTP collectorEndpoint `yaml:"http"`
			} `yaml:"protocols"`
		} `yaml:"otlp"`
	} `yaml:"receivers"`
	Processors struct {
		MemoryLimiter struct {
			CheckInterval string `yaml:"check_interval"`
			LimitMiB      int    `yaml:"limit_mib"`
			SpikeLimitMiB int    `yaml:"spike_limit_mib"`
		} `yaml:"memory_limiter"`
		DropUnsafe struct {
			Actions []collectorAttributeAction `yaml:"actions"`
		} `yaml:"attributes/drop-unsafe"`
		Batch struct {
			SendBatchSize int    `yaml:"send_batch_size"`
			Timeout       string `yaml:"timeout"`
		} `yaml:"batch"`
	} `yaml:"processors"`
	Exporters struct {
		OTLPHTTPTraceStore struct {
			Endpoint    string `yaml:"endpoint"`
			Compression string `yaml:"compression"`
			Timeout     string `yaml:"timeout"`
		} `yaml:"otlphttp/trace-store"`
		Prometheus struct {
			Endpoint                      string `yaml:"endpoint"`
			ResourceToTelemetryConversion struct {
				Enabled bool `yaml:"enabled"`
			} `yaml:"resource_to_telemetry_conversion"`
		} `yaml:"prometheus"`
	} `yaml:"exporters"`
	Service struct {
		Pipelines struct {
			Traces  collectorPipeline `yaml:"traces"`
			Metrics collectorPipeline `yaml:"metrics"`
		} `yaml:"pipelines"`
	} `yaml:"service"`
}

type collectorEndpoint struct {
	Endpoint string `yaml:"endpoint"`
}

type collectorAttributeAction struct {
	Key    string `yaml:"key"`
	Action string `yaml:"action"`
}

type collectorPipeline struct {
	Receivers  []string `yaml:"receivers"`
	Processors []string `yaml:"processors"`
	Exporters  []string `yaml:"exporters"`
}
