package main

import (
	"sync"
	"testing"
)

func TestRequestIDsRemainUniqueDuringConcurrentWebRequests(t *testing.T) {
	source := &requestIDs{}
	const requests = 128
	ids := make(chan string, requests)
	var group sync.WaitGroup
	for range requests {
		group.Add(1)
		go func() {
			defer group.Done()
			id, err := source.NextRequestID()
			if err != nil {
				t.Errorf("next request ID: %v", err)
				return
			}
			ids <- id.String()
		}()
	}
	group.Wait()
	close(ids)
	seen := make(map[string]struct{}, requests)
	for id := range ids {
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("duplicate request ID: %s", id)
		}
		seen[id] = struct{}{}
	}
	if len(seen) != requests {
		t.Fatalf("request IDs = %d, want %d", len(seen), requests)
	}
}
