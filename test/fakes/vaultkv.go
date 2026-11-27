package fakes

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// VaultRequest is one request FakeVaultKV served: the method and the decoded
// URL path (e.g. "/v1/secret/data/app/openai"), plus the namespace header.
type VaultRequest struct {
	Method    string
	Path      string
	Namespace string
}

// vaultKVEntry is one KV v2 secret: its live versions and metadata.
type vaultKVEntry struct {
	current     int64
	versions    map[int64]string // version -> value
	maxVersions int
}

// FakeVaultKV is an httptest Vault server speaking the KV v2 subset that
// secrets.NewVaultSecretStore uses: data GET/POST (with options.cas), metadata
// POST (max_versions), metadata DELETE (every version) and metadata LIST
// (method LIST or GET ?list=true). It requires X-Vault-Token to equal the token
// it was built with (else 403), records every request, and models version
// pruning so tests can check that older versions are gone.
type FakeVaultKV struct {
	srv   *httptest.Server
	token string
	mount string

	mu       sync.Mutex
	entries  map[string]*vaultKVEntry // path inside the mount -> entry
	requests []VaultRequest
	force    map[string]int // "METHOD /v1/..." -> status to answer instead
}

// fakeVaultDefaultMaxVersions mirrors Vault's KV v2 mount default.
const fakeVaultDefaultMaxVersions = 10

// NewFakeVaultKV starts a fake Vault serving the KV v2 mount "secret" that
// accepts token; it is closed when tb ends.
func NewFakeVaultKV(tb testing.TB, token string) *FakeVaultKV {
	tb.Helper()
	f := &FakeVaultKV{
		token:   token,
		mount:   "secret",
		entries: map[string]*vaultKVEntry{},
		force:   map[string]int{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	tb.Cleanup(f.srv.Close)
	return f
}

// URL is the fake's base address (VaultStoreConfig.Addr).
func (f *FakeVaultKV) URL() string { return f.srv.URL }

// Client is an http.Client for the fake.
func (f *FakeVaultKV) Client() *http.Client { return f.srv.Client() }

// Requests returns a copy of every request served so far.
func (f *FakeVaultKV) Requests() []VaultRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]VaultRequest(nil), f.requests...)
}

// ForceStatus makes the fake answer method on path (e.g.
// "/v1/secret/metadata/app/k") with status and an empty JSON body.
func (f *FakeVaultKV) ForceStatus(method, path string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.force[method+" "+path] = status
}

// Value returns the current value at path inside the mount, if any.
func (f *FakeVaultKV) Value(path string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.entries[path]
	if !ok || e.current == 0 {
		return "", false
	}
	v, ok := e.versions[e.current]
	return v, ok
}

// Version returns the current version at path (0 when absent).
func (f *FakeVaultKV) Version(path string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.entries[path]; ok {
		return e.current
	}
	return 0
}

// StoredVersions returns how many versions of path are still recoverable.
func (f *FakeVaultKV) StoredVersions(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.entries[path]; ok {
		return len(e.versions)
	}
	return 0
}

// MaxVersions returns path's max_versions metadata (0 when absent).
func (f *FakeVaultKV) MaxVersions(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.entries[path]; ok {
		return e.maxVersions
	}
	return 0
}

func (f *FakeVaultKV) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, VaultRequest{Method: r.Method, Path: r.URL.Path, Namespace: r.Header.Get("X-Vault-Namespace")})

	if st, ok := f.force[r.Method+" "+r.URL.Path]; ok {
		writeVaultJSON(w, st, map[string]any{})
		return
	}
	if r.Header.Get("X-Vault-Token") != f.token {
		writeVaultJSON(w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
		return
	}
	base := "/v1/" + f.mount + "/"
	rest, ok := strings.CutPrefix(r.URL.Path, base)
	if !ok {
		writeVaultJSON(w, http.StatusNotFound, map[string]any{"errors": []string{"no handler for route"}})
		return
	}
	kind, path, _ := strings.Cut(rest, "/")
	path = strings.TrimSuffix(path, "/")
	list := r.Method == "LIST" || (r.Method == http.MethodGet && r.URL.Query().Get("list") == "true")

	switch {
	case kind == "data" && r.Method == http.MethodGet:
		f.readData(w, path)
	case kind == "data" && (r.Method == http.MethodPost || r.Method == http.MethodPut):
		f.writeData(w, r, path)
	case kind == "metadata" && list:
		f.list(w, path)
	case kind == "metadata" && (r.Method == http.MethodPost || r.Method == http.MethodPut):
		f.writeMetadata(w, r, path)
	case kind == "metadata" && r.Method == http.MethodDelete:
		delete(f.entries, path)
		w.WriteHeader(http.StatusNoContent)
	default:
		writeVaultJSON(w, http.StatusMethodNotAllowed, map[string]any{"errors": []string{"unsupported operation"}})
	}
}

func (f *FakeVaultKV) readData(w http.ResponseWriter, path string) {
	e, ok := f.entries[path]
	if !ok || e.current == 0 {
		writeVaultJSON(w, http.StatusNotFound, map[string]any{"errors": []string{}})
		return
	}
	writeVaultJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"data":     map[string]string{"value": e.versions[e.current]},
		"metadata": map[string]any{"version": e.current},
	}})
}

func (f *FakeVaultKV) writeData(w http.ResponseWriter, r *http.Request, path string) {
	var req struct {
		Data    map[string]string `json:"data"`
		Options *struct {
			CAS *int64 `json:"cas"`
		} `json:"options"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeVaultJSON(w, http.StatusBadRequest, map[string]any{"errors": []string{"bad json"}})
		return
	}
	e, ok := f.entries[path]
	if !ok {
		e = &vaultKVEntry{versions: map[int64]string{}, maxVersions: 0}
	}
	if req.Options != nil && req.Options.CAS != nil && *req.Options.CAS != e.current {
		writeVaultJSON(w, http.StatusBadRequest, map[string]any{"errors": []string{"check-and-set parameter did not match the current version"}})
		return
	}
	f.entries[path] = e
	e.current++
	e.versions[e.current] = req.Data["value"]
	e.prune()
	writeVaultJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"version": e.current}})
}

func (f *FakeVaultKV) writeMetadata(w http.ResponseWriter, r *http.Request, path string) {
	var req struct {
		MaxVersions int `json:"max_versions"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeVaultJSON(w, http.StatusBadRequest, map[string]any{"errors": []string{"bad json"}})
		return
	}
	e, ok := f.entries[path]
	if !ok {
		e = &vaultKVEntry{versions: map[int64]string{}}
		f.entries[path] = e
	}
	e.maxVersions = req.MaxVersions
	e.prune()
	w.WriteHeader(http.StatusNoContent)
}

func (f *FakeVaultKV) list(w http.ResponseWriter, dir string) {
	prefix := dir
	if prefix != "" {
		prefix += "/"
	}
	seen := map[string]bool{}
	for p, e := range f.entries {
		if e.current == 0 && len(e.versions) == 0 {
			continue
		}
		rest, ok := strings.CutPrefix(p, prefix)
		if !ok || rest == "" {
			continue
		}
		if head, _, nested := strings.Cut(rest, "/"); nested {
			seen[head+"/"] = true
		} else {
			seen[rest] = true
		}
	}
	if len(seen) == 0 {
		writeVaultJSON(w, http.StatusNotFound, map[string]any{"errors": []string{}})
		return
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeVaultJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"keys": keys}})
}

// prune drops versions older than max_versions (Vault's default when unset).
func (e *vaultKVEntry) prune() {
	maxV := e.maxVersions
	if maxV <= 0 {
		maxV = fakeVaultDefaultMaxVersions
	}
	for v := range e.versions {
		if v <= e.current-int64(maxV) {
			delete(e.versions, v)
		}
	}
}

func writeVaultJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
