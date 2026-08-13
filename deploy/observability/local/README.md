# Disposable OTLP lab

Run the API, the checked-in collector config, Jaeger trace store, and the
collector Prometheus endpoint locally without Kubernetes or a home server:

```sh
./deploy/observability/local/run-otlp-lab.sh
```

To retain a redacted, explicitly non-production report, pass a new absolute
path and the explicit lab authorization:

```sh
./deploy/observability/local/run-otlp-lab.sh \
  --report /absolute/new/otlp-lab.json \
  --execute-authorized-disposable-lab
```

The lab derives the API observability declaration from the local Stack profile,
then replaces only its durable storage with `memory-unsafe` so it can exercise
the API process without a database. It checks API-to-collector trace/metric
delivery, collector-to-Jaeger delivery, the Prometheus metric endpoint, and
the checked-in unsafe-attribute deletion list. It removes all containers,
network, temporary files, and locally built image on exit.

Its optional artifact is `agent-runtime.direct-lab-evidence/v1`; it is not
Kubernetes, home-server, protected-run, or production evidence.
