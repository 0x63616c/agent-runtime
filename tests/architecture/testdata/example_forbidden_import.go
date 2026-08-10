package testdata

import (
	_ "github.com/0x63616c/agent-runtime/internal/runtimeapi"
	_ "github.com/0x63616c/agent-runtime/internal/sandboxcontrol"
	_ "github.com/0x63616c/agent-runtime/temporalpayload"
	_ "github.com/0x63616c/agent-runtime/tests/testroute"
	_ "github.com/minio/minio-go/v7"
	_ "go.temporal.io/sdk/client"
)
