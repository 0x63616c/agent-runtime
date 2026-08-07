// Command dev-role is the deliberately minimal local composition image for the
// API, worker, and codec roles before their product implementations land.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

func main() {
	role := flag.String("role", "", "declared local role")
	port := flag.Int("port", 0, "HTTP listen port")
	check := flag.Bool("check", false, "validate this image can start")
	flag.Parse()
	if *check {
		if *role != "" || *port != 0 {
			fmt.Fprintln(os.Stderr, "dev role check does not accept role or port")
			os.Exit(2)
		}
		return
	}
	if *role == "" || *port < 1 || *port > 65535 {
		fmt.Fprintln(os.Stderr, "dev role requires a role and valid port")
		os.Exit(2)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("role", *role)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write([]byte("ok\n")) })
	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write([]byte("ready\n")) })
	mux.HandleFunc("/", func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("agent-runtime local " + *role + " role\n"))
	})
	logger.Info("serve local role", "port", *port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", *port), mux); err != nil {
		logger.Error("serve local role", "error", err)
		os.Exit(1)
	}
}
