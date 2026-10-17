package main

import (
	"fmt"
	"net/http"
)

// Every route the fake upstream serves is registered here (rule X9: one
// place to read a server's whole surface).

// newApp builds the TLS:443 mux: recorder middleware + host routing.
func newApp(rec *recorder) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", handleEcho)
	mux.HandleFunc("/ws", handleWS)
	mux.HandleFunc("/v1/chat/completions", handleChat)
	mux.HandleFunc("/e2e.Echo/", handleGRPCEcho)
	// The MCP handler checks the Host itself (mcp.example.test only); other
	// hosts fall through to the default handler.
	mux.Handle("/", hostAwareDefault())
	return rec.middleware(mux)
}

// newControl builds the control mux: health, recorder read/reset, and the DNS
// rebind switch. Plain HTTP on the control port; compose keeps it off the
// host loopback except where the scenario runner needs it.
func newControl(rec *recorder, rb *rebinds) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/_health", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/_recorded", func(w http.ResponseWriter, _ *http.Request) {
		// Envelope, not a bare array: "dropped" is the running count of records
		// evicted by the recorder cap, so a runner that stayed longer than the
		// ring can tell it lost the head of its recording.
		writeJSON(w, http.StatusOK, map[string]any{"records": rec.snapshot(), "dropped": rec.droppedCount()})
	})
	mux.HandleFunc("/_reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		rec.reset()
		rb.clear()
		writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
	})
	mux.HandleFunc("/_rebind", func(w http.ResponseWriter, r *http.Request) {
		host := hostRoot(r.URL.Query().Get("host"))
		switch r.Method {
		case http.MethodPost:
			if host == "" {
				http.Error(w, "missing host query parameter", http.StatusBadRequest)
				return
			}
			rb.arm(host)
			writeJSON(w, http.StatusOK, map[string]any{"status": "armed", "host": host})
		case http.MethodDelete:
			if host == "" {
				http.Error(w, "missing host query parameter", http.StatusBadRequest)
				return
			}
			rb.disarm(host)
			writeJSON(w, http.StatusOK, map[string]any{"status": "disarmed", "host": host})
		case http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]any{"armed": rb.armedNames()})
		default:
			http.Error(w, "GET/POST/DELETE only", http.StatusMethodNotAllowed)
		}
	})
	return mux
}
