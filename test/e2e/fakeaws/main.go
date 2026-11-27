// Command fakeaws is a hermetic AWS Secrets Manager stand-in for the L2
// identity e2e stack (deploy/compose/docker-compose.e2e-identity.yml). The
// control plane's consent.store (backend aws) talks to it exactly as it talks
// to AWS: warden's own SigV4 JSON client POSTs to
// https://secretsmanager.<region>.amazonaws.com/. The stack points that name
// at this container with a cp-net network alias, and the CP trusts its leaf
// (test/e2e/certs/fakeaws-server.crt, signed by the lab upstream CA) through
// SSL_CERT_FILE. No warden code has a test-only endpoint override.
//
// It implements the five actions secrets.AWSSecretsClient uses
// (GetSecretValue, PutSecretValue, CreateSecret, DeleteSecret, ListSecrets)
// over an in-memory map that lives as long as the container: persistent across
// control-plane restarts, which is what the portal IdP link needs
// (Persists() is true for the aws backend). It checks that each request is
// SigV4-shaped (an AWS4-HMAC-SHA256 Authorization header) and that the access
// key id in its Credential= scope equals FAKEAWS_ACCESS_KEY_ID (the CP's fake
// key; any other key is 403), but does not verify the signature. Only the CP
// is given that key, so a request from anything else is refused.
//
// The access key id is not a secret; it is still never logged.
//
// A second, plain-HTTP control listener (loopback inside the container by
// default) lets the e2e test read what the CP stored:
//
//	GET /_health          200 "ok"
//	GET /_names           JSON array of the stored secret names
//	GET /_secret?name=N   the SecretString of N (404 when absent)
//
// Nothing is logged but the listen addresses: never a name, a value or a
// request body.
package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxBody caps a request body; a refresh token is a few hundred bytes.
const maxBody = 1 << 20

// store is the in-memory secret map.
type store struct {
	// accessKeyID is the only access key id the API accepts.
	accessKeyID string

	mu      sync.Mutex
	secrets map[string]secret
	version int
	now     func() time.Time
}

type secret struct {
	value   string
	version string
	changed time.Time
}

func newStore(accessKeyID string, now func() time.Time) *store {
	return &store{accessKeyID: accessKeyID, secrets: map[string]secret{}, now: now}
}

// credentialKeyID returns the access key id of a SigV4 Authorization header
// ("AWS4-HMAC-SHA256 Credential=<id>/<date>/<region>/<service>/aws4_request, ..."),
// or "" when the header is not SigV4-shaped.
func credentialKeyID(authz string) string {
	rest, ok := strings.CutPrefix(authz, "AWS4-HMAC-SHA256 ")
	if !ok {
		return ""
	}
	for _, part := range strings.Split(rest, ",") {
		if scope, ok := strings.CutPrefix(strings.TrimSpace(part), "Credential="); ok {
			id, _, _ := strings.Cut(scope, "/")
			return id
		}
	}
	return ""
}

// awsErr writes an AWS JSON 1.1 error: the client maps the __type.
func awsErr(w http.ResponseWriter, status int, typ, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("X-Amzn-Errortype", typ)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": typ, "message": msg})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(v)
}

// nextVersion returns a fresh version id. Caller holds s.mu.
func (s *store) nextVersion() string {
	s.version++
	return "v" + strconv.Itoa(s.version)
}

// apiHandler serves the Secrets Manager JSON protocol on POST /.
func (s *store) apiHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/" {
			awsErr(w, http.StatusNotFound, "UnknownOperationException", "POST / only")
			return
		}
		id := credentialKeyID(r.Header.Get("Authorization"))
		if id == "" {
			awsErr(w, http.StatusBadRequest, "MissingAuthenticationTokenException", "request is not SigV4-signed")
			return
		}
		if s.accessKeyID == "" || id != s.accessKeyID {
			awsErr(w, http.StatusForbidden, "UnrecognizedClientException", "the access key id is not the one this store accepts")
			return
		}
		action, ok := strings.CutPrefix(r.Header.Get("X-Amz-Target"), "secretsmanager.")
		if !ok {
			awsErr(w, http.StatusBadRequest, "UnknownOperationException", "missing secretsmanager X-Amz-Target")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || len(body) > maxBody {
			awsErr(w, http.StatusBadRequest, "InvalidRequestException", "unreadable or oversized body")
			return
		}
		var in struct {
			SecretID           string `json:"SecretId"`
			Name               string `json:"Name"`
			SecretString       string `json:"SecretString"`
			ClientRequestToken string `json:"ClientRequestToken"`
			Filters            []struct {
				Key    string   `json:"Key"`
				Values []string `json:"Values"`
			} `json:"Filters"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			awsErr(w, http.StatusBadRequest, "SerializationException", "body is not JSON")
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		switch action {
		case "GetSecretValue":
			sec, ok := s.secrets[in.SecretID]
			if !ok {
				awsErr(w, http.StatusBadRequest, "ResourceNotFoundException", "secret not found")
				return
			}
			writeJSON(w, map[string]string{"Name": in.SecretID, "SecretString": sec.value, "VersionId": sec.version})
		case "PutSecretValue":
			if in.ClientRequestToken == "" {
				awsErr(w, http.StatusBadRequest, "InvalidRequestException", "ClientRequestToken is required")
				return
			}
			if _, ok := s.secrets[in.SecretID]; !ok {
				awsErr(w, http.StatusBadRequest, "ResourceNotFoundException", "secret not found")
				return
			}
			v := s.nextVersion()
			s.secrets[in.SecretID] = secret{value: in.SecretString, version: v, changed: s.now()}
			writeJSON(w, map[string]string{"Name": in.SecretID, "VersionId": v})
		case "CreateSecret":
			if in.ClientRequestToken == "" || in.Name == "" {
				awsErr(w, http.StatusBadRequest, "InvalidRequestException", "Name and ClientRequestToken are required")
				return
			}
			if _, ok := s.secrets[in.Name]; ok {
				awsErr(w, http.StatusBadRequest, "ResourceExistsException", "secret already exists")
				return
			}
			v := s.nextVersion()
			s.secrets[in.Name] = secret{value: in.SecretString, version: v, changed: s.now()}
			writeJSON(w, map[string]string{"Name": in.Name, "VersionId": v})
		case "DeleteSecret":
			if _, ok := s.secrets[in.SecretID]; !ok {
				awsErr(w, http.StatusBadRequest, "ResourceNotFoundException", "secret not found")
				return
			}
			delete(s.secrets, in.SecretID)
			writeJSON(w, map[string]string{"Name": in.SecretID})
		case "ListSecrets":
			var prefixes []string
			for _, f := range in.Filters {
				if f.Key == "name" {
					prefixes = append(prefixes, f.Values...)
				}
			}
			type entry struct {
				Name            string  `json:"Name"`
				LastChangedDate float64 `json:"LastChangedDate"`
			}
			list := []entry{}
			for _, name := range s.namesLocked() {
				if matchesAny(name, prefixes) {
					list = append(list, entry{Name: name, LastChangedDate: float64(s.secrets[name].changed.UnixMilli()) / 1000})
				}
			}
			writeJSON(w, map[string]any{"SecretList": list})
		default:
			awsErr(w, http.StatusBadRequest, "UnknownOperationException", "unsupported action")
		}
	})
}

// matchesAny is the AWS name filter: a prefix match on any value (no filter
// matches everything).
func matchesAny(name string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// namesLocked returns the stored names, sorted. Caller holds s.mu.
func (s *store) namesLocked() []string {
	names := make([]string, 0, len(s.secrets))
	for n := range s.secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// controlHandler serves the test-only read surface.
func (s *store) controlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("GET /_names", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		names := s.namesLocked()
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(names)
	})
	mux.HandleFunc("GET /_secret", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		sec, ok := s.secrets[r.URL.Query().Get("name")]
		s.mu.Unlock()
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, sec.value)
	})
	return mux
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("fakeaws: %v", err)
	}
}

func run() error {
	certFile, keyFile := os.Getenv("FAKEAWS_CERT"), os.Getenv("FAKEAWS_KEY")
	accessKeyID := os.Getenv("FAKEAWS_ACCESS_KEY_ID")
	if certFile == "" || keyFile == "" || accessKeyID == "" {
		return errors.New("FAKEAWS_CERT, FAKEAWS_KEY and FAKEAWS_ACCESS_KEY_ID are required")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	s := newStore(accessKeyID, time.Now)
	addr, ctl := env("FAKEAWS_ADDR", ":443"), env("FAKEAWS_CONTROL", "127.0.0.1:8082")
	api := &http.Server{
		Addr: addr, Handler: s.apiHandler(), ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ErrorLog:  log.New(io.Discard, "", 0),
	}
	control := &http.Server{Addr: ctl, Handler: s.controlHandler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 2)
	go func() { errc <- api.ListenAndServeTLS("", "") }()
	go func() { errc <- control.ListenAndServe() }()
	log.Printf("fakeaws: secrets manager on %s (TLS), control on %s", addr, ctl)
	return <-errc
}
