# Durable Chat

Durable Chat is a loopback web UI and terminal UI built only on the public Go
SDK/HTTP contract. It creates or resumes a Session, queues Inputs, reconnects
from a Product-event cursor, inspects durable state, and cancels a Turn.

It deliberately does not configure, inspect, or impersonate a model provider.
Codex subscription support remains blocked pending a production-supported
official model surface and a protected canary; this application is not a
subscription canary.

Start a local public API role first, then provide that user's public bearer
token only to this local example process:

```sh
export AGENT_RUNTIME_DEVELOPER_TOKEN='your-local-runtime-bearer'
go run ./examples/durable-chat/cmd/durable-chat \
  --mode=terminal \
  --runtime-url=http://127.0.0.1:8088
```

Use `new <agent-revision>` to create a Session. Then use `send`, `resume`,
`events`, and `cancel` as the terminal displays. To run the local web UI use
`--mode=web --listen=127.0.0.1:8090` and open that loopback address.

The Runtime bearer never reaches the browser: the loopback web server owns the
public SDK client. Do not bind the web mode to a non-loopback interface or use
it as a hosted multi-user frontend.
