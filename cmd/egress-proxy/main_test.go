package main

import (
	"context"
	"testing"
)

func TestRunValidatesAnExactProxyConfigurationWithoutListening(t *testing.T) {
	t.Parallel()
	if err := run(context.Background(), []string{"--listen", "127.0.0.1:8088", "--allowed-target", "models.example.invalid:443", "--check"}); err != nil {
		t.Fatalf("run check: %v", err)
	}
	if err := run(context.Background(), []string{"--listen", "127.0.0.1:8088", "--allowed-target", "*.example.invalid:443", "--check"}); err == nil {
		t.Fatal("expected wildcard target rejection")
	}
}
