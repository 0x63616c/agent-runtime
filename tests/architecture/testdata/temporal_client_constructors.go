package testdata

import (
	. "go.temporal.io/sdk/client"
	temporalclient "go.temporal.io/sdk/client"
	temporalworker "go.temporal.io/sdk/worker"
)

func rawTemporalClientConstructors() {
	dial := temporalclient.Dial
	dial()
	temporalclient.DialContext()
	newLazyClient := temporalclient.NewLazyClient
	newLazyClient()
	NewClient()
	temporalclient.NewClientFromExisting()
	newClientFromExistingWithContext := temporalclient.NewClientFromExistingWithContext
	newClientFromExistingWithContext()
	newNamespaceClient := temporalclient.NewNamespaceClient
	newNamespaceClient()
	newWorker := temporalworker.New
	newWorker()
}
