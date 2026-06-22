// Command proxy is the Warden egress guardrail entry point. It wires the
// concrete phase-1 implementations (local YAML config, ENV secrets, SQLite
// analytics) behind their interfaces and constructs the proxy. Connection
// handling (TCP accept, TLS termination, forwarding) is implemented in
// milestone 1; this entry point stays deliberately thin — no business logic.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "warden: %v\n", err)
		os.Exit(1)
	}
}
