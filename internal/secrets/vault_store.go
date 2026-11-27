// vault_store.go — the HashiCorp Vault KV v2 SecretStore.
//
// vaultSecretStore implements SecretStore and the optional VersionedStore over
// the Vault KV v2 HTTP API with net/http only (no Vault SDK). It is a pure
// pass-through: values live only in Vault, and nothing here logs. Errors carry
// only the key, mount, version and HTTP status — never the token, a value or a
// response body.
//
// Layout for a logical key K under mount M and name prefix P:
//
//	Get/GetVersion  GET    /v1/M/data/P K       (.data.data.value, .data.metadata.version)
//	Put/PutIfVersion POST  /v1/M/data/P K       {"data":{"value":...},"options":{"cas":N}}
//	                 POST  /v1/M/metadata/P K   {"max_versions":1} (new keys only)
//	Delete           DELETE /v1/M/metadata/P K  (every version; 404 is success)
//	List             LIST  /v1/M/metadata/P...  (recursive; never a data/ path)
//
// VaultFetcher in vault.go is the older read-only placeholder fetcher and is
// unrelated to this store.
package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	// defaultVaultMount is the KV v2 mount used when VaultStoreConfig.Mount is
	// empty (Vault's dev-server default).
	defaultVaultMount = "secret"
	// vaultHTTPTimeout bounds every Vault request end to end.
	vaultHTTPTimeout = 5 * time.Second
	// vaultMaxBody caps how much of a Vault response is read.
	vaultMaxBody = 1 << 20
	// vaultListCap bounds List: at most this many keys, and at most this many
	// LIST requests while walking directories.
	vaultListCap = 10000
)

// ErrInvalidKey is returned before any HTTP call for a key (or configured
// mount or prefix) that could escape its path: one containing "..", starting
// with '/', holding an empty segment, or holding a control character.
var ErrInvalidKey = errors.New("secrets: invalid key")

// ErrListLimit is returned by the Vault store's List when the prefix holds more
// than 10,000 keys. List fails closed instead of returning a partial listing.
var ErrListLimit = errors.New("secrets: vault list exceeds the key limit")

// VaultStoreConfig configures NewVaultSecretStore.
type VaultStoreConfig struct {
	// Addr is the Vault server base URL, e.g. "https://vault.internal:8200".
	Addr string
	// Mount is the KV v2 mount path; empty means "secret".
	Mount string
	// NamePrefix is prepended to every key inside the mount. It is empty or
	// ends with '/', so List can walk it as a directory.
	NamePrefix string
	// Token is sent as X-Vault-Token. It never appears in an error or log.
	Token string
	// Namespace, when set, is sent as X-Vault-Namespace (Vault Enterprise/HCP).
	Namespace string
}

// vaultSecretStore is the KV v2 SecretStore. Build it with NewVaultSecretStore.
type vaultSecretStore struct {
	client    *http.Client
	base      string // Addr without a trailing slash
	mount     string // validated, unescaped
	prefix    string // validated, unescaped; "" or ends with "/"
	token     string
	namespace string
}

var (
	_ SecretStore    = (*vaultSecretStore)(nil)
	_ VersionedStore = (*vaultSecretStore)(nil)
)

// NewVaultSecretStore builds a SecretStore over the Vault KV v2 HTTP API. The
// returned store also implements VersionedStore (type-assert to use it).
//
// client may be nil. The store uses a copy of it with a 5s timeout (or the
// caller's, when shorter) and with redirects disabled, because net/http
// forwards the custom X-Vault-Token header to a redirect target. The caller
// owns the transport (TLS roots, proxy, dialer).
func NewVaultSecretStore(cfg VaultStoreConfig, client *http.Client) (SecretStore, error) {
	u, err := url.Parse(cfg.Addr)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, errors.New("secrets: vault addr must be an http or https URL with a host and no query, fragment or userinfo")
	}
	if cfg.Token == "" {
		return nil, errors.New("secrets: vault token is required")
	}
	mount := cfg.Mount
	if mount == "" {
		mount = defaultVaultMount
	}
	if err := validateVaultPath(mount); err != nil {
		return nil, fmt.Errorf("secrets: vault mount %q: %w", mount, err)
	}
	if p := cfg.NamePrefix; p != "" {
		if !strings.HasSuffix(p, "/") {
			return nil, fmt.Errorf("secrets: vault namePrefix %q must end with '/'", p)
		}
		if err := validateVaultPath(strings.TrimSuffix(p, "/")); err != nil {
			return nil, fmt.Errorf("secrets: vault namePrefix %q: %w", p, err)
		}
	}

	c := &http.Client{}
	if client != nil {
		*c = *client
	}
	if c.Timeout <= 0 || c.Timeout > vaultHTTPTimeout {
		c.Timeout = vaultHTTPTimeout
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &vaultSecretStore{
		client:    c,
		base:      strings.TrimRight(cfg.Addr, "/"),
		mount:     mount,
		prefix:    cfg.NamePrefix,
		token:     cfg.Token,
		namespace: cfg.Namespace,
	}, nil
}

// validateVaultKey rejects keys that could escape the configured prefix, before
// any request is built.
func validateVaultKey(key string) error {
	if key == "" {
		return ErrEmptyKey
	}
	return validateVaultPath(key)
}

// validateVaultPath rejects a path containing "..", a leading '/', an empty
// segment (so also a trailing '/'), a "." segment or a control character.
func validateVaultPath(p string) error {
	if strings.Contains(p, "..") || strings.HasPrefix(p, "/") {
		return ErrInvalidKey
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." {
			return ErrInvalidKey
		}
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return ErrInvalidKey
		}
	}
	return nil
}

// escapeVaultPath escapes each '/'-separated segment with url.PathEscape.
func escapeVaultPath(p string) string {
	if p == "" {
		return ""
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// apiURL builds /v1/<mount>/<kind>/<prefix><rel>, every segment escaped.
func (s *vaultSecretStore) apiURL(kind, rel string) string {
	return s.base + "/v1/" + escapeVaultPath(s.mount) + "/" + kind + "/" + escapeVaultPath(strings.TrimSuffix(s.prefix+rel, "/"))
}

// do sends one request and returns the status and at most 1 MiB of body. The
// body is for parsing only; it never reaches an error or a log.
func (s *vaultSecretStore) do(ctx context.Context, method, target string, payload any) (int, []byte, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return 0, nil, errors.New("build request failed")
	}
	req.Header.Set("X-Vault-Token", s.token)
	if s.namespace != "" {
		req.Header.Set("X-Vault-Namespace", s.namespace)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, vaultMaxBody+1))
	if err != nil {
		return resp.StatusCode, nil, errors.New("read response failed")
	}
	if len(b) > vaultMaxBody {
		return resp.StatusCode, nil, errors.New("response exceeds 1 MiB")
	}
	return resp.StatusCode, b, nil
}

// opError formats a failure with only the operation, key, mount and detail.
func (s *vaultSecretStore) opError(op, key string, detail any) error {
	if err, ok := detail.(error); ok {
		return fmt.Errorf("secrets: vault %s %q (mount %q): %w", op, key, s.mount, err)
	}
	return fmt.Errorf("secrets: vault %s %q (mount %q): %v", op, key, s.mount, detail)
}

// statusError reports an unexpected HTTP status (never the body).
func (s *vaultSecretStore) statusError(op, key string, status int) error {
	return s.opError(op, key, fmt.Sprintf("unexpected status %d", status))
}

// Get returns key's current value; an absent key wraps ErrNotFound.
func (s *vaultSecretStore) Get(ctx context.Context, key string) (string, error) {
	v, _, err := s.GetVersion(ctx, key)
	return v, err
}

// kvReadResponse is the subset of a KV v2 data read this store parses.
type kvReadResponse struct {
	Data *struct {
		Data     map[string]any `json:"data"`
		Metadata struct {
			Version int64 `json:"version"`
		} `json:"metadata"`
	} `json:"data"`
}

// GetVersion returns key's current value and KV v2 version. An absent,
// deleted or destroyed key wraps ErrNotFound.
func (s *vaultSecretStore) GetVersion(ctx context.Context, key string) (string, int64, error) {
	if err := validateVaultKey(key); err != nil {
		return "", 0, err
	}
	status, body, err := s.do(ctx, http.MethodGet, s.apiURL("data", key), nil)
	if err != nil {
		return "", 0, s.opError("get", key, err)
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", 0, s.opError("get", key, ErrNotFound)
	default:
		return "", 0, s.statusError("get", key, status)
	}
	var r kvReadResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return "", 0, s.opError("get", key, "malformed response")
	}
	if r.Data == nil || r.Data.Data == nil {
		return "", 0, s.opError("get", key, ErrNotFound)
	}
	v, ok := r.Data.Data["value"].(string)
	if !ok {
		return "", 0, s.opError("get", key, "record has no string value field")
	}
	return v, r.Data.Metadata.Version, nil
}

// Put upserts key=value. A key's first version also sets max_versions=1 so an
// overwritten value is not recoverable from an older version.
func (s *vaultSecretStore) Put(ctx context.Context, key, value string) error {
	return s.write(ctx, "put", key, value, nil)
}

// PutIfVersion writes value only when key's current version is version, using
// KV v2 options.cas (0 means create-only). A mismatch wraps ErrVersionConflict.
func (s *vaultSecretStore) PutIfVersion(ctx context.Context, key, value string, version int64) error {
	if version < 0 {
		return s.opError("put", key, "negative version")
	}
	return s.write(ctx, "put", key, value, &version)
}

// kvWriteResponse is the subset of a KV v2 data write this store parses.
type kvWriteResponse struct {
	Data struct {
		Version int64 `json:"version"`
	} `json:"data"`
}

// write posts the value, with options.cas when cas is set, then applies
// max_versions=1 to a newly created key.
func (s *vaultSecretStore) write(ctx context.Context, op, key, value string, cas *int64) error {
	if err := validateVaultKey(key); err != nil {
		return err
	}
	if value == "" {
		return ErrEmptyValue
	}
	payload := map[string]any{"data": map[string]string{"value": value}}
	if cas != nil {
		payload["options"] = map[string]int64{"cas": *cas}
	}
	status, body, err := s.do(ctx, http.MethodPost, s.apiURL("data", key), payload)
	if err != nil {
		return s.opError(op, key, err)
	}
	switch {
	case status == http.StatusOK || status == http.StatusNoContent:
	case status == http.StatusBadRequest && cas != nil && bytes.Contains(body, []byte("check-and-set")):
		return fmt.Errorf("secrets: vault %s %q (mount %q) at version %d: %w", op, key, s.mount, *cas, ErrVersionConflict)
	default:
		return s.statusError(op, key, status)
	}
	var r kvWriteResponse
	_ = json.Unmarshal(body, &r) // an unparseable version is treated as new below
	if r.Data.Version > 1 {
		return nil
	}
	// A new key: keep only the latest version from now on. If that fails, remove
	// the key again so no key exists without the single-version guarantee.
	if err := s.setMaxVersions(ctx, key); err != nil {
		_ = s.Delete(ctx, key)
		return s.opError(op, key, err)
	}
	return nil
}

// setMaxVersions sets the key's metadata to keep a single version.
func (s *vaultSecretStore) setMaxVersions(ctx context.Context, key string) error {
	status, _, err := s.do(ctx, http.MethodPost, s.apiURL("metadata", key), map[string]int{"max_versions": 1})
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("set max_versions: unexpected status %d", status)
	}
	return nil
}

// Delete removes key and every version of it (metadata delete). An absent key
// is success.
func (s *vaultSecretStore) Delete(ctx context.Context, key string) error {
	if err := validateVaultKey(key); err != nil {
		return err
	}
	status, _, err := s.do(ctx, http.MethodDelete, s.apiURL("metadata", key), nil)
	if err != nil {
		return s.opError("delete", key, err)
	}
	switch status {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	default:
		return s.statusError("delete", key, status)
	}
}

// kvListResponse is a KV v2 metadata LIST response.
type kvListResponse struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
}

// List walks the prefix with LIST on metadata/ paths only, recursively, and
// returns value-free SecretMeta (Key only: KV v2 LIST carries no version or
// time, and reading them would cost a request per key). It never calls a
// data/ path. More than 10,000 keys is ErrListLimit. Names that fail key
// validation are skipped, so a hostile listing cannot steer the walk outside
// the prefix.
func (s *vaultSecretStore) List(ctx context.Context) ([]SecretMeta, error) {
	var out []SecretMeta
	requests := 0
	dirs := []string{""}
	for len(dirs) > 0 {
		dir := dirs[0]
		dirs = dirs[1:]
		requests++
		if requests > vaultListCap {
			return nil, s.opError("list", s.prefix+dir, ErrListLimit)
		}
		status, body, err := s.do(ctx, "LIST", s.apiURL("metadata", dir), nil)
		if err != nil {
			return nil, s.opError("list", s.prefix+dir, err)
		}
		switch status {
		case http.StatusOK:
		case http.StatusNotFound:
			continue // empty directory
		default:
			return nil, s.statusError("list", s.prefix+dir, status)
		}
		var r kvListResponse
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, s.opError("list", s.prefix+dir, "malformed response")
		}
		for _, name := range r.Data.Keys {
			isDir := strings.HasSuffix(name, "/")
			rel := dir + strings.TrimSuffix(name, "/")
			if validateVaultPath(rel) != nil {
				continue
			}
			if isDir {
				dirs = append(dirs, rel+"/")
				continue
			}
			if len(out) >= vaultListCap {
				return nil, s.opError("list", s.prefix, ErrListLimit)
			}
			out = append(out, SecretMeta{Key: rel})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}
