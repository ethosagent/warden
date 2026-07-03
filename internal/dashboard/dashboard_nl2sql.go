package dashboard

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/ethosagent/warden/internal/analytics"
)

// SQLGenerator is the minimal LLM surface NL→SQL needs. It is satisfied by
// *llm.Client (its Evaluate method). Depending on the capability rather than the
// concrete client keeps the dashboard decoupled from the LLM implementation and
// lets tests inject a fake without a real provider.
type SQLGenerator interface {
	// Evaluate sends a single prompt and returns the model's completion text.
	Evaluate(prompt string) (string, error)
}

// SetSQLGenerator attaches the LLM used to translate plain-English questions into
// read-only SQL for the Explore tab. It reuses the SAME provider/model/key the
// judge uses (wired from the effective judge config). Passing nil (or never
// calling it — no LLM configured, or the node's key env is empty) makes
// POST /dashboard/api/query/generate report "llm_not_configured", which the UI
// turns into a prompt to add an LLM provider in Settings.
//
// It is safe to call at runtime: a provider/Explore selection edit RE-INJECTS the
// generator (the control plane recomputes the Explore client and calls this again,
// passing nil to clear it), so the write is guarded by sqlGenMu against a concurrent
// handleQueryGenerate read.
func (s *Server) SetSQLGenerator(g SQLGenerator) {
	s.sqlGenMu.Lock()
	s.sqlGen = g
	s.sqlGenMu.Unlock()
}

// currentSQLGen returns the live NL→SQL generator under the read lock, so a request
// reads a consistent generator even while a reload re-injects a new one.
func (s *Server) currentSQLGen() SQLGenerator {
	s.sqlGenMu.RLock()
	defer s.sqlGenMu.RUnlock()
	return s.sqlGen
}

// generateRequest is the body of POST /dashboard/api/query/generate.
type generateRequest struct {
	Question string `json:"question"`
}

// writeJSONStatus writes v as JSON with an explicit status code (writeJSON always
// uses 200; writeError only carries a single "error" string). NL→SQL error
// responses carry both a machine key and a human message, so they need this.
func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// handleQueryGenerate serves POST /dashboard/api/query/generate: translate a
// plain-English question into ONE read-only SQL SELECT using the configured LLM,
// then return it for the user to review before running it via the existing
// read-only /query engine. This endpoint never executes SQL.
//
// Response shapes (the frontend keys on the "error" field):
//   - 405 {"error": "..."}                      non-POST
//   - 404 {"error": "..."}                       no query engine (non-SQL store)
//   - 409 {"error":"llm_not_configured", ...}    no LLM wired on this node
//   - 400 {"error": "..."}                       bad JSON / blank question
//   - 502 {"error":"llm_error", ...}             the LLM request failed
//   - 422 {"error":"not_readonly", ...}          model returned a non-SELECT
//   - 200 {"sql":"SELECT ..."}                   success
func (s *Server) handleQueryGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Mirror handleQuerySchema: without a query engine there is no schema to ground
	// the model on and nowhere to run the result, so the feature is unavailable.
	if s.queryEngine == nil {
		writeError(w, http.StatusNotFound, "query builder unavailable: the analytics store is not SQL-backed")
		return
	}
	// The distinct, machine-checkable "LLM not set up" path: 409 + a stable key.
	// Read the generator once under the lock so a concurrent re-inject (a provider/
	// Explore edit) can never flip it between the nil-check and Evaluate.
	gen := s.currentSQLGen()
	if gen == nil {
		writeJSONStatus(w, http.StatusConflict, map[string]string{
			"error":   "llm_not_configured",
			"message": "Add an LLM provider in Settings → Guardrails → Judge to use plain-English queries.",
		})
		return
	}

	var req generateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	question := strings.TrimSpace(req.Question)
	if question == "" {
		writeError(w, http.StatusBadRequest, "question is required")
		return
	}

	prompt := buildNL2SQLPrompt(s.queryEngine.Schema(), question)
	out, err := gen.Evaluate(prompt)
	if err != nil {
		// The llm client keeps the API key and raw upstream body out of its errors;
		// still, return a bounded, generic message rather than echoing err verbatim.
		writeJSONStatus(w, http.StatusBadGateway, map[string]string{
			"error":   "llm_error",
			"message": "the language model request failed",
		})
		return
	}

	sql, ok := extractReadOnlySQL(out)
	if !ok {
		writeJSONStatus(w, http.StatusUnprocessableEntity, map[string]string{
			"error":   "not_readonly",
			"message": "The model did not return a read-only SELECT.",
		})
		return
	}
	writeJSON(w, map[string]string{"sql": sql})
}

// buildNL2SQLPrompt assembles a compact, bounded prompt: a short instruction, the
// REAL schema (dialect + each table's name and columns), and the user's question.
// It instructs the model to emit exactly one read-only SELECT and nothing else.
func buildNL2SQLPrompt(schema analytics.SchemaInfo, question string) string {
	dialect := strings.TrimSpace(schema.Dialect)
	if dialect == "" {
		dialect = "sqlite"
	}
	var b strings.Builder
	b.WriteString("You convert a plain-English question into ONE read-only SQL query.\n")
	b.WriteString("Rules:\n")
	b.WriteString("- SQL dialect: ")
	b.WriteString(dialect)
	b.WriteString("\n")
	b.WriteString("- Return EXACTLY one statement. It MUST start with SELECT (or WITH). Never INSERT/UPDATE/DELETE/DROP/ALTER/CREATE/REPLACE/PRAGMA/ATTACH.\n")
	b.WriteString("- Output ONLY the SQL — no prose, no explanation, no markdown code fences, no multiple statements.\n")
	b.WriteString("- Use only the tables and columns listed below.\n")
	b.WriteString("\nSchema:\n")
	for _, t := range schema.Tables {
		b.WriteString("- ")
		b.WriteString(t.Name)
		b.WriteString("(")
		for i, c := range t.Columns {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(c.Name)
		}
		b.WriteString(")\n")
	}
	b.WriteString("\nQuestion: ")
	b.WriteString(question)
	b.WriteString("\nSQL:")
	return b.String()
}

// forbiddenSQLKeyword matches any write/DDL/side-effecting keyword the generated
// SQL must not contain. It is defense in depth: the /query engine is already
// read-only, but a clean 422 beats a runtime rejection. The list mirrors the
// brief exactly (INSERT/UPDATE/DELETE/DROP/ALTER/CREATE/REPLACE/PRAGMA/ATTACH);
// word boundaries keep it from tripping on column names like created_at.
var forbiddenSQLKeyword = regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|PRAGMA|ATTACH)\b`)

// extractReadOnlySQL post-processes a model completion into a single read-only
// SELECT: it strips surrounding markdown fences, trims, takes the first statement
// (rejecting a second one), and validates that it starts with SELECT/WITH and
// contains no write/DDL keyword. It returns (sql, true) on success or ("", false)
// when the output is not a clean read-only query.
func extractReadOnlySQL(raw string) (string, bool) {
	s := stripCodeFences(raw)
	if s == "" {
		return "", false
	}
	// Take the first statement only. A single trailing semicolon is fine; anything
	// non-empty after it is a second statement and is rejected.
	if idx := strings.IndexByte(s, ';'); idx >= 0 {
		if strings.TrimSpace(s[idx+1:]) != "" {
			return "", false
		}
		s = strings.TrimSpace(s[:idx])
	}
	if s == "" {
		return "", false
	}
	upper := strings.ToUpper(s)
	if !strings.HasPrefix(upper, "SELECT") && !strings.HasPrefix(upper, "WITH") {
		return "", false
	}
	if forbiddenSQLKeyword.MatchString(s) {
		return "", false
	}
	return s, true
}

// stripCodeFences removes a surrounding ```...``` / ```sql...``` markdown block
// and trims the result. Input without a leading fence is returned trimmed.
func stripCodeFences(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	// Drop the opening fence line (``` or ```sql).
	if nl := strings.IndexByte(s, '\n'); nl >= 0 {
		s = s[nl+1:]
	} else {
		s = strings.TrimPrefix(s, "```")
	}
	// Drop the trailing closing fence, if any.
	if idx := strings.LastIndex(s, "```"); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}
