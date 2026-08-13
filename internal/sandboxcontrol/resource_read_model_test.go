package sandboxcontrol

import "testing"

func TestOperationLedgerDoesNotImplyAResourceReadModel(t *testing.T) {
	// A target in an operation ledger is not enough evidence to construct a
	// public resource response. This guards sandbox.control/v1 from adding a
	// route that derives desired/actual resource state from operation metadata.
	var store DurableStore = NewMemoryLedger()
	if _, ok := store.(ResourceReadModel); ok {
		t.Fatal("memory operation ledger unexpectedly implements resource read model")
	}
}
