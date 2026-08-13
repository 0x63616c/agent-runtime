// audit-sink is a disposable TLS endpoint for the local M5 rehearsal.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "TLS listen address")
	certificate := flag.String("certificate", "", "required PEM certificate path")
	key := flag.String("key", "", "required PEM private-key path")
	readyFile := flag.String("ready-file", "", "required file to receive the bound address")
	flag.Parse()
	if *certificate == "" || *key == "" || *readyFile == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "audit-sink: certificate, key, and ready-file are required")
		os.Exit(2)
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit-sink:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*readyFile, []byte(listener.Addr().String()), 0o600); err != nil {
		_ = listener.Close()
		fmt.Fprintln(os.Stderr, "audit-sink:", err)
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/audit", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("X-Agent-Runtime-Drill-Mode") == "" {
			http.Error(writer, "invalid local rehearsal request", http.StatusBadRequest)
			return
		}
		switch request.Header.Get("X-Agent-Runtime-Drill-Mode") {
		case "outage":
			http.Error(writer, "simulated local audit outage", http.StatusServiceUnavailable)
		case "recovery":
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.Error(writer, "unknown local rehearsal mode", http.StatusBadRequest)
		}
	})
	mux.HandleFunc("/retention", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{"schema_version": "agent-runtime.audit-sink-retention/v1", "retention_seconds": int64(86400)})
	})
	if err := http.ServeTLS(listener, mux, *certificate, *key); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "audit-sink:", err)
		os.Exit(1)
	}
}
