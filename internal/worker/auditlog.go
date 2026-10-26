package worker

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"time"

	"github.com/ethosagent/warden/internal/auditlog"
	"github.com/ethosagent/warden/internal/config"
)

// jsonLogCloseTimeout bounds how long shutdown waits for the JSON decision
// stream to drain; the stream is best effort, so a stuck output never holds
// the worker up.
const jsonLogCloseTimeout = 5 * time.Second

// jsonLogOutput is the effective output of the JSON decision stream (the
// config default is stdout).
func jsonLogOutput(c config.JSONLogConfig) string {
	if c.Output == "" {
		return config.JSONLogOutputStdout
	}
	return c.Output
}

// errOut is where operational logs go when stdout is reserved for the JSON
// decision stream: Params.ErrOut, else os.Stderr.
func errOut(p Params) io.Writer {
	if p.ErrOut != nil {
		return p.ErrOut
	}
	return os.Stderr
}

// newAuditMeta builds the per-process context stamped on every decision line:
// the configured central proxyID (env-expanded) when set, else the hostname;
// the worker's agent id; and a fresh 16-byte boot id.
func newAuditMeta(pol config.Policy, agentID string) auditlog.Meta {
	m := auditlog.Meta{AgentID: agentID, BootID: randomBootID()}
	if id := expandEnv(pol.Central.ProxyID); id != "" {
		m.ProxyID, m.ProxyIDSource = id, "config"
		return m
	}
	host, _ := os.Hostname()
	m.ProxyID, m.ProxyIDSource = host, "hostname"
	return m
}

func randomBootID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}
