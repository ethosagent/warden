package harness

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// judgeKeyEnv is the env var the unreachable-judge option points the worker's
// LLM client at; its value is a dummy, the endpoint is never called.
const judgeKeyEnv = "WARDEN_HARNESS_JUDGE_KEY"

// WithAuditLogs boots every worker with the JSON decision stream (audit.jsonLog,
// file output, mode 0600), compliance tagging and signed receipts on, both under the harness root,
// so a scenario can compare the stream with the SQLite rows and the receipts
// (DecisionLines, ReceiptLines). The block is node-local worker config, so it
// applies to a managed worker exactly as to a standalone one.
func WithAuditLogs() Option {
	return func(h *H) { h.auditLogs = true }
}

// WithUnreachableJudge enables the inline LLM judge against an endpoint that is
// never reached. With the judge on, a destination matching no allowlist rule is
// admitted at CONNECT and judged inside the tunnel; a tunnel that carries no
// TLS ClientHello then fails closed with the no_tls reason before the judge
// would run.
func WithUnreachableJudge() Option {
	return func(h *H) {
		h.tb.Setenv(judgeKeyEnv, "harness-judge-key-not-a-secret")
		h.unreachableJudge = true
	}
}

func (h *H) decisionLogPath(i int) string {
	return filepath.Join(h.root, fmt.Sprintf("worker-%d-decisions.jsonl", i))
}

// applyAuditLogs sets the node-local audit and judge blocks on worker i's policy.
func (h *H) applyAuditLogs(i int, p *config.Policy) {
	if h.auditLogs {
		p.Audit.JSONLog = config.JSONLogConfig{
			Enabled:    true,
			Output:     config.JSONLogOutputFile,
			Path:       h.decisionLogPath(i),
			MaxSizeMB:  100,
			MaxBackups: 2,
			MaxAgeDays: 1,
			FileMode:   0o600,
			Query:      config.JSONLogQueryDrop,
		}
		p.Audit.Compliance = config.ComplianceConfig{Enabled: true}
		p.Audit.SignedReceipts = config.SignedReceiptsConfig{
			Enabled: true,
			KeyFile: filepath.Join(h.root, fmt.Sprintf("worker-%d-receipt.key", i)),
			Log:     h.receiptLogPath(i),
		}
	}
	if h.unreachableJudge {
		p.Judge = config.JudgeConfig{
			Enabled:   true,
			Model:     "harness-judge",
			BaseURL:   "http://127.0.0.1:1",
			APIKeyEnv: judgeKeyEnv,
			Timeout:   time.Second,
		}
	}
}

// readLines returns the non-empty lines of path ("" and nil when absent).
func readLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, ln := range strings.Split(string(data), "\n") {
		if ln != "" {
			out = append(out, ln)
		}
	}
	return out
}

// DecisionLines returns worker 1's JSON decision stream, one entry per line.
// It first reads Events (which waits for in-flight scopes and drains the async
// analytics writer, the stream's source), then waits until the sink's writer has
// produced a line for every stored event; a stream that stays short fails the
// test rather than reading short. It requires WithAuditLogs.
func (h *H) DecisionLines() []string {
	h.tb.Helper()
	if !h.auditLogs {
		h.tb.Fatal("harness: DecisionLines needs the WithAuditLogs option")
	}
	want := len(h.Events())
	var got []string
	h.Eventually(fmt.Sprintf("%d decision lines (one per stored event)", want), func() bool {
		got = readLines(h.decisionLogPath(1))
		return len(got) >= want
	})
	return got
}

// ReceiptLines returns worker 1's signed-receipt log, one entry per line.
// It requires WithAuditLogs.
func (h *H) ReceiptLines() []string {
	h.tb.Helper()
	if !h.auditLogs {
		h.tb.Fatal("harness: ReceiptLines needs the WithAuditLogs option")
	}
	_ = h.Events()
	return readLines(h.receiptLogPath(1))
}
