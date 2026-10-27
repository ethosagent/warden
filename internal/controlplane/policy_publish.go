package controlplane

// policy_publish.go is the versioned publish path (W-P1-PVER-02): in
// --policy-store=versioned the writers of wire-carried blocks (WritePolicy,
// WriteSettings, WriteLLMProviders) create a policy version from head instead
// of rewriting the served YAML, so every edit reaches workers through the
// store. File mode never reaches this file.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// Authors of a versioned dashboard write without a signed-in user.
const (
	// anonymousAuthorSub authors writes in console.auth none: the CP admin
	// bearer proves possession of the shared token, not an identity.
	anonymousAuthorSub  = "anonymous"
	breakglassSubPrefix = "breakglass:"
)

// settingsFieldCarried marks a SettingsWire field no versioned writer owns:
// every publish copies it from head.
const settingsFieldCarried = ""

// settingsFieldOwners maps each config.SettingsWire field to the versioned
// writer that owns it (its version source) or settingsFieldCarried. A publish
// takes the fields its writer owns from the edit and every other field from
// head; a field missing here is carried, and TestSettingsFieldOwnership fails
// until it is listed. WritePolicy owns no settings field.
var settingsFieldOwners = map[string]string{
	"MCP":             SourceSettings,
	"Judge":           SourceSettings,
	"Agents":          SourceSettings,
	"Observability":   SourceSettings,
	"Compliance":      SourceSettings,
	"CacheTTLSeconds": SourceSettings,
	"Logging":         SourceSettings,
	"Secrets":         SourceSettings,
	"Explore":         SourceSettings,
	"Identity":        SourceSettings,
	"LLMProviders":    SourceLLMProviders,
	// The settings form does not edit these (WriteSettings never renders
	// them), so a settings save keeps head's.
	"Advisory": settingsFieldCarried,
	"DLP":      settingsFieldCarried,
}

// composeSettings returns head with the fields owner owns replaced by cand's.
// Neither input is modified. All-empty settings are nil, as the loader returns
// for a config with no settings blocks, so the "settings" key stays absent.
func composeSettings(head, cand *config.SettingsWire, owner string) *config.SettingsWire {
	var out, c config.SettingsWire
	if head != nil {
		out = *head
	}
	if cand != nil {
		c = *cand
	}
	ov, cv := reflect.ValueOf(&out).Elem(), reflect.ValueOf(c)
	for i := range ov.NumField() {
		if settingsFieldOwners[ov.Type().Field(i).Name] == owner {
			ov.Field(i).Set(cv.Field(i))
		}
	}
	if ov.IsZero() {
		return nil
	}
	return &out
}

// writeAuthor is the author of a versioned write, from the request's
// Principal. Without one, console.auth none records anonymous; oidc mode
// refuses (its routes always carry a Principal, so this is a wiring bug).
func (s *Server) writeAuthor(ctx context.Context) (PolicyAuthor, error) {
	p, ok := PrincipalFrom(ctx)
	if !ok {
		if s.cfg.Console.Auth == config.ConsoleAuthOIDC {
			return PolicyAuthor{}, errors.New("controlplane: versioned write without a signed-in user in console.auth oidc")
		}
		return PolicyAuthor{Sub: anonymousAuthorSub, Kind: AuthorKindNone}, nil
	}
	if p.Sub == "" {
		return PolicyAuthor{}, errors.New("controlplane: versioned write by a principal without a subject")
	}
	switch {
	case p.Kind == PrincipalBreakglass || p.AuthMethod == AuthorKindBreakglass:
		return PolicyAuthor{Sub: breakglassSubPrefix + strings.TrimPrefix(p.Sub, breakglassSubPrefix), Email: p.Email, Kind: AuthorKindBreakglass}, nil
	case p.Kind == PrincipalSession:
		return PolicyAuthor{Sub: p.Sub, Email: p.Email, Kind: AuthorKindOIDC}, nil
	default:
		return PolicyAuthor{}, fmt.Errorf("controlplane: versioned write by an unsupported principal kind %q", p.Kind)
	}
}

// headDoc returns the head version and its doc. An empty store (head 0, only
// before the initial import) starts from the served YAML with its credential
// redacted, as the import stores it.
func (s *Server) headDoc(ctx context.Context) (int64, policyWire, error) {
	head, err := s.versions.Head(ctx)
	if err != nil {
		return 0, policyWire{}, err
	}
	if head == 0 {
		doc, err := s.policy.loadFile()
		if err != nil {
			return 0, policyWire{}, err
		}
		return 0, RedactCredentials(doc), nil
	}
	v, err := s.versions.Get(ctx, head)
	if err != nil {
		return 0, policyWire{}, err
	}
	return head, v.Doc, nil
}

// publish creates a policy version: under writeMu it reads head, applies
// mutate, validates the result with validateDoc (a validation error leaves
// head unchanged), and calls Create with meta.ExpectedHead, or the head it
// read when that is zero. A moved head is a *dashboard.ConflictError naming
// the current head and its author (it unwraps to ErrConflict). A new credential value
// in the doc is written to the served YAML secretStore first and only its
// fingerprint is stored; the YAML is put back if no version is created. A
// new version is mirrored into the served YAML (mirrorHead), whose failure
// never fails the save. The one log line on success is Create's. A validation
// error is a *dashboard.InvalidPolicyError (its text is the loader's).
func (s *Server) publish(ctx context.Context, mutate func(*policyWire) error, meta dashboard.WriteMeta, source string) error {
	_, _, err := s.publishVersion(ctx, mutate, meta, source)
	return err
}

// publishVersion is publish that also returns the head after the write and
// whether a version was created (false when the result equals head).
func (s *Server) publishVersion(ctx context.Context, mutate func(*policyWire) error, meta dashboard.WriteMeta, source string) (int64, bool, error) {
	author, err := s.writeAuthor(ctx)
	if err != nil {
		return 0, false, err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	head, doc, err := s.headDoc(ctx)
	if err != nil {
		return 0, false, fmt.Errorf("controlplane: read policy head: %w", err)
	}
	headKey := credentialOf(doc)
	if err := mutate(&doc); err != nil {
		return 0, false, err
	}
	if err := s.validateDoc(doc); err != nil {
		return 0, false, &dashboard.InvalidPolicyError{Err: err}
	}
	var restore func()
	if key := credentialOf(doc); key != "" && !isRedactedCredential(key) {
		if redactCredential(key) != headKey {
			if restore, err = s.writeCredential(*doc.Settings.Secrets); err != nil {
				return 0, false, err
			}
		}
		doc = RedactCredentials(doc)
	}
	expected := meta.ExpectedHead
	if expected == 0 {
		expected = head
	}
	version, changed, err := s.versions.Create(ctx, doc, author, meta.Message, source, expected)
	if err != nil {
		if restore != nil {
			restore()
			s.refresh()
		}
		if errors.Is(err, ErrConflict) {
			return 0, false, s.conflictError(ctx, err)
		}
		return 0, false, err
	}
	if changed {
		s.mirrorHead(ctx, version)
	}
	s.refresh()
	s.reinjectExploreLLM()
	return version, changed, nil
}

// credentialOf is the doc's AWS secretAccessKey ("" when absent).
func credentialOf(doc policyWire) string {
	if doc.Settings == nil || doc.Settings.Secrets == nil {
		return ""
	}
	return doc.Settings.Secrets.SecretAccessKey
}

// writeCredential writes sec, carrying a new raw secretAccessKey, as the
// served YAML's secretStore block: the credential lives only there, and the
// credential overlay serves it. In versioned mode the served YAML is also the
// only home of the CP-local blocks, so an unreadable or malformed file refuses
// the save instead of being replaced. It returns a func that puts the previous
// file back. The caller holds writeMu.
func (s *Server) writeCredential(sec config.SecretsSettings) (func(), error) {
	prev, err := os.ReadFile(s.cfg.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("controlplane: read the served config for the new credential: %w", err)
	}
	root := map[string]yaml.Node{}
	if err := yaml.Unmarshal(prev, &root); err != nil {
		return nil, fmt.Errorf("controlplane: parse the served config for the new credential: %w", err)
	}
	node, err := config.EncodeSecretStoreNode(config.SecretStoreConfigFromSettings(&sec))
	if err != nil {
		return nil, fmt.Errorf("controlplane: encode secretStore settings: %w", err)
	}
	root["secretStore"] = node
	if err := s.atomicWriteConfig(root); err != nil {
		return nil, err
	}
	return func() {
		if err := s.restoreServedFile(prev); err != nil {
			s.cfg.Logger.Error("control plane: cannot restore the served config after a failed publish; the new credential stays in it", "error", err)
		}
	}, nil
}

// restoreServedFile atomically replaces the served file with data.
func (s *Server) restoreServedFile(data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(s.cfg.PolicyPath), ".warden-policy-*.yaml")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.cfg.PolicyPath)
}

// candidateWire renders head into a copy of the served YAML root, applies a
// writer's block renderer and loads the result with the full config loader.
// The wire it returns is what file mode would serve after that edit, so a
// version holds the loader's normal form (defaults applied, disabled blocks
// dropped) and an unchanged re-save creates no version. A loader error is the
// invalid-policy error the file-mode writers return.
func (s *Server) candidateWire(head policyWire, render func(root map[string]yaml.Node) error) (policyWire, error) {
	root := s.readServedRoot()
	if err := renderDocToRoot(root, head); err != nil {
		return policyWire{}, err
	}
	if err := render(root); err != nil {
		return policyWire{}, err
	}
	tmpName, p, err := s.writeCheckedTemp(root)
	if err != nil {
		return policyWire{}, err
	}
	_ = os.Remove(tmpName)
	return policyWire{Allowlist: p.Allowlist, Denylist: p.Denylist, Settings: config.SettingsWireFromPolicy(p)}, nil
}

// publishPolicy is WritePolicy in versioned mode: allow/deny from the edit,
// settings from head.
func (s *Server) publishPolicy(ctx context.Context, p config.Policy, meta dashboard.WriteMeta) error {
	return s.publish(ctx, func(w *policyWire) error {
		cand, err := s.candidateWire(*w, func(root map[string]yaml.Node) error {
			return renderPolicyBlock(root, p.Allowlist, p.Denylist)
		})
		if err != nil {
			return err
		}
		w.Allowlist, w.Denylist = cand.Allowlist, cand.Denylist
		return nil
	}, meta, SourcePolicy)
}

// publishSettings is WriteSettings in versioned mode: the settings form's
// fields from the edit, everything else from head. check, when set, runs
// against head's settings first.
func (s *Server) publishSettings(ctx context.Context, in config.SettingsWire, meta dashboard.WriteMeta, check func(live *config.SettingsWire) error) error {
	return s.publish(ctx, func(w *policyWire) error {
		if check != nil {
			if err := check(w.Settings); err != nil {
				return err
			}
		}
		cand, err := s.candidateWire(*w, func(root map[string]yaml.Node) error {
			return renderSettingsBlocks(root, in)
		})
		if err != nil {
			return err
		}
		w.Settings = composeSettings(w.Settings, cand.Settings, SourceSettings)
		return nil
	}, meta, SourceSettings)
}

// publishLLMProviders is WriteLLMProviders in versioned mode: the registry
// from the edit, everything else from head.
func (s *Server) publishLLMProviders(ctx context.Context, ps []config.LLMProvider, meta dashboard.WriteMeta) error {
	return s.publish(ctx, func(w *policyWire) error {
		cand, err := s.candidateWire(*w, func(root map[string]yaml.Node) error {
			return renderLLMProvidersBlock(root, ps)
		})
		if err != nil {
			return err
		}
		w.Settings = composeSettings(w.Settings, cand.Settings, SourceLLMProviders)
		return nil
	}, meta, SourceLLMProviders)
}

// conflictError is the dashboard-visible form of a Create conflict: the
// current head and its author, so the 409 can say who saved first. The
// author's sub and email are those the version stores; dashboard writes are
// always authenticated (bearer or session), so only console users see them.
// If the head cannot be read the error still maps to 409, without an author.
func (s *Server) conflictError(ctx context.Context, err error) error {
	ce := &dashboard.ConflictError{Err: err}
	head, herr := s.versions.Head(ctx)
	if herr != nil {
		return ce
	}
	ce.Head = head
	if v, gerr := s.versions.Get(ctx, head); gerr == nil {
		ce.Author = dashboard.ConflictAuthor{Sub: v.Author.Sub, Email: v.Author.Email}
	}
	return ce
}

// policyVersionHead is the dashboard's policy version source: the head
// version in versioned mode, 0 in file mode.
func (s *Server) policyVersionHead(ctx context.Context) (int64, error) {
	if s.versions == nil {
		return 0, nil
	}
	return s.versions.Head(ctx)
}

// versionedPolicyHash is the admin audit state hasher for target policy in
// versioned mode: "v<head>:<doc_sha256>", the same form as the initial
// import's after_hash, so consecutive rows chain by version. doc_sha256 is
// the stored digest of the credential-redacted doc, never the doc itself. An
// empty store hashes to "".
func (s *Server) versionedPolicyHash(ctx context.Context) (string, error) {
	head, err := s.versions.Head(ctx)
	if err != nil || head == 0 {
		return "", err
	}
	v, err := s.versions.Get(ctx, head)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("v%d:%s", v.Version, v.DocSHA256), nil
}
