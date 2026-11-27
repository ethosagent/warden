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
	deleted     bool // the current version is soft-deleted (DELETE data/)
}

// vaultForced is a one-shot canned answer for one method and path.
type vaultForced struct {
	status int
	body   string
}

// FakeVaultKV is an httptest Vault server speaking the KV v2 subset that
// secrets.NewVaultSecretStore uses: the mount preflight
// (sys/internal/ui/mounts/<mount>), data GET/POST (with options.cas), data
// DELETE (soft delete), metadata POST (max_versions), metadata DELETE (every
// version) and metadata LIST (method LIST or GET ?list=true). It requires
// X-Vault-Token to equal the token it was built with (else 403), records every
// request, and models version pruning so tests can check that older versions
// are gone. NewFakeVaultKV1 builds one that answers like a KV v1 mount.
type FakeVaultKV struct {
	srv   *httptest.Server
	token string
	mount string

	// kv1 makes the mount behave like KV v1: every path is a flat secret.
	kv1 bool
	// reportVersion is the KV version the mount preflight reports.
	reportVersion string

	mu       sync.Mutex
	entries  map[string]*vaultKVEntry   // path inside the mount -> entry
	flat     map[string]json.RawMessage // KV v1 mode: path -> stored body
	requests []VaultRequest
	force    map[string]vaultForced // "METHOD /v1/..." -> one-shot answer
	hooks    map[string]func()      // "METHOD /v1/..." -> one-shot hook
}

// fakeVaultDefaultMaxVersions mirrors Vault's KV v2 mount default.
const fakeVaultDefaultMaxVersions = 10

// NewFakeVaultKV starts a fake Vault serving the KV v2 mount "secret" that
// accepts token; it is closed when tb ends.
func NewFakeVaultKV(tb testing.TB, token string) *FakeVaultKV {
	tb.Helper()
	return newFakeVault(tb, token, false)
}

// NewFakeVaultKV1 starts a fake whose "secret" mount behaves like KV v1: the
// preflight reports version 1, writes answer 204 with no version, data/ and
// metadata/ are ordinary secret paths, and options.cas is ignored.
func NewFakeVaultKV1(tb testing.TB, token string) *FakeVaultKV {
	tb.Helper()
	return newFakeVault(tb, token, true)
}

func newFakeVault(tb testing.TB, token string, kv1 bool) *FakeVaultKV {
	f := &FakeVaultKV{
		token:         token,
		mount:         "secret",
		kv1:           kv1,
		reportVersion: "2",
		entries:       map[string]*vaultKVEntry{},
		flat:          map[string]json.RawMessage{},
		force:         map[string]vaultForced{},
		hooks:         map[string]func(){},
	}
	if kv1 {
		f.reportVersion = "1"
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	tb.Cleanup(f.srv.Close)
	return f
}

// ReportMountVersion overrides the KV version the mount preflight reports, to
// test a store against a mount that lies about its type.
func (f *FakeVaultKV) ReportMountVersion(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reportVersion = v
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

// ForceStatus makes the fake answer the NEXT request for method on path (e.g.
// "/v1/secret/metadata/app/k") with status and the body {"errors":[]}.
func (f *FakeVaultKV) ForceStatus(method, path string, status int) {
	f.ForceResponse(method, path, status, `{"errors":[]}`)
}

// ForceResponse is ForceStatus with a chosen JSON body. It is one-shot.
func (f *FakeVaultKV) ForceResponse(method, path string, status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.force[method+" "+path] = vaultForced{status: status, body: body}
}

// OnRequest runs fn once, when the next request for method on path arrives and
// before it is answered (after any forced answer is chosen). fn may issue its
// own requests to the fake, e.g. to model a second writer racing in.
func (f *FakeVaultKV) OnRequest(method, path string, fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hooks[method+" "+path] = fn
}

// SoftDelete marks path's current version deleted, as DELETE data/ does.
func (f *FakeVaultKV) SoftDelete(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.entries[path]; ok && e.current > 0 {
		e.deleted = true
	}
}

// FlatPaths returns the stored paths of a KV v1 fake, sorted.
func (f *FakeVaultKV) FlatPaths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.flat))
	for p := range f.flat {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Value returns the current value at path inside the mount, if any.
func (f *FakeVaultKV) Value(path string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.entries[path]
	if !ok || e.current == 0 || e.deleted {
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
	id := r.Method + " " + r.URL.Path
	f.mu.Lock()
	f.requests = append(f.requests, VaultRequest{Method: r.Method, Path: r.URL.Path, Namespace: r.Header.Get("X-Vault-Namespace")})
	forced, isForced := f.force[id]
	delete(f.force, id)
	hook := f.hooks[id]
	delete(f.hooks, id)
	f.mu.Unlock()

	if hook != nil {
		hook()
	}
	if isForced {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(forced.status)
		_, _ = io.WriteString(w, forced.body)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("X-Vault-Token") != f.token {
		writeVaultJSON(w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
		return
	}
	if probe, ok := strings.CutPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts/"); r.Method == http.MethodGet && ok &&
		(probe == f.mount || strings.HasPrefix(probe, f.mount+"/")) {
		// Like Vault, a probe of any path inside the mount reports the mount.
		writeVaultJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
			"type": "kv", "path": f.mount + "/", "options": map[string]string{"version": f.reportVersion},
		}})
		return
	}
	base := "/v1/" + f.mount + "/"
	rest, ok := strings.CutPrefix(r.URL.Path, base)
	if !ok {
		writeVaultJSON(w, http.StatusNotFound, map[string]any{"errors": []string{"no handler for route"}})
		return
	}
	list := r.Method == "LIST" || (r.Method == http.MethodGet && r.URL.Query().Get("list") == "true")
	if f.kv1 {
		f.serveKV1(w, r, strings.TrimSuffix(rest, "/"), list)
		return
	}
	kind, path, _ := strings.Cut(rest, "/")
	path = strings.TrimSuffix(path, "/")

	switch {
	case kind == "data" && r.Method == http.MethodGet:
		f.readData(w, path)
	case kind == "data" && (r.Method == http.MethodPost || r.Method == http.MethodPut):
		f.writeData(w, r, path)
	case kind == "metadata" && list:
		f.list(w, path)
	case kind == "metadata" && (r.Method == http.MethodPost || r.Method == http.MethodPut):
		f.writeMetadata(w, r, path)
	case kind == "data" && r.Method == http.MethodDelete:
		if e, ok := f.entries[path]; ok && e.current > 0 {
			e.deleted = true
		}
		w.WriteHeader(http.StatusNoContent)
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
	if e.deleted {
		writeVaultJSON(w, http.StatusNotFound, map[string]any{"errors": []string{}, "data": map[string]any{
			"data":     nil,
			"metadata": map[string]any{"version": e.current, "deletion_time": "2026-01-01T00:00:00Z"},
		}})
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
	e.deleted = false
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

// serveKV1 answers like a KV v1 mount: path (relative to the mount, data/ and
// metadata/ included) is a flat secret; writes return 204 with no version.
func (f *FakeVaultKV) serveKV1(w http.ResponseWriter, r *http.Request, path string, list bool) {
	switch {
	case list:
		prefix := path
		if prefix != "" {
			prefix += "/"
		}
		seen := map[string]bool{}
		for p := range f.flat {
			if rest, ok := strings.CutPrefix(p, prefix); ok && rest != "" {
				if head, _, nested := strings.Cut(rest, "/"); nested {
					seen[head+"/"] = true
				} else {
					seen[rest] = true
				}
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
	case r.Method == http.MethodGet:
		raw, ok := f.flat[path]
		if !ok {
			writeVaultJSON(w, http.StatusNotFound, map[string]any{"errors": []string{}})
			return
		}
		writeVaultJSON(w, http.StatusOK, map[string]any{"data": raw})
	case r.Method == http.MethodPost || r.Method == http.MethodPut:
		b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil || !json.Valid(b) {
			writeVaultJSON(w, http.StatusBadRequest, map[string]any{"errors": []string{"bad json"}})
			return
		}
		f.flat[path] = json.RawMessage(b)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete:
		delete(f.flat, path)
		w.WriteHeader(http.StatusNoContent)
	default:
		writeVaultJSON(w, http.StatusMethodNotAllowed, map[string]any{"errors": []string{"unsupported operation"}})
	}
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
