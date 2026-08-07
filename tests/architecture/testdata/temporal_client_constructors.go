package testdata

import (
	. "go.temporal.io/sdk/client"
	temporalclient "go.temporal.io/sdk/client"
	temporalworker "go.temporal.io/sdk/worker"
)

func rawTemporalClientConstructors() {
	temporalclient.Dial()
	temporalclient.DialContext()
	temporalclient.NewLazyClient()
	temporalclient.NewClient()
	temporalclient.NewClientFromExisting()
	temporalclient.NewClientFromExistingWithContext()
	Dial()
	temporalworker.New()
}
