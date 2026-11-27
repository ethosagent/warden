package controlplane

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/portal"
	idplinksqlite "github.com/ethosagent/warden/internal/portal/adapters/sqlite"
	"github.com/ethosagent/warden/internal/secrets"
)

// The IdP link (W-P3-CSIG-03): with consent.idpLink enabled, the portal
// callback stores the user's refresh token in the CP-only consent.store
// (Config.UserStore) at secrets.IdPLinkKey(secrets.UserKey(iss, sub)) =
// idp/<userKey>, and records only its Reference in idp_links. No worker holds
// a credential for that store (NewUserStore refuses an overlap with the
// distributed secretStore), and Run refuses to start without a persistent one
// (checkUserStorePersistent). Logout and session expiry never touch the link.

// idpLinkKeys are the secrets helpers the portal domain builds per-user keys
// with; nothing else derives them.
func idpLinkKeys() portal.LinkKeys {
	return portal.LinkKeys{
		UserKey:   secrets.UserKey,
		SecretKey: secrets.IdPLinkKey,
		Ref:       func(token string) string { return secrets.Ref(token).String() },
	}
}

// initIdPLinks builds the portal's LinkStore over idp_links and consent.store.
// Without a user store (only a hand-built Server; Run refuses to start so)
// links stays nil and every login fails closed.
func (s *Server) initIdPLinks(p *portalService) {
	if s.cfg.UserStore == nil {
		s.cfg.Logger.Error("control plane: consent.idpLink is enabled but no consent.store is configured; portal logins will fail")
		return
	}
	now := s.cfg.Now
	if now == nil {
		now = time.Now
	}
	ls, err := portal.NewLinkStore(portal.LinkStoreConfig{
		Repo:            idplinksqlite.New(s.cfg.State),
		Secrets:         s.cfg.UserStore,
		Keys:            idpLinkKeys(),
		RefreshLifetime: p.cfg.IdPLink.RefreshLifetime,
		Now:             now,
		Logger:          s.cfg.Logger,
	})
	if err != nil {
		s.cfg.Logger.Error("control plane: idp link store unavailable; portal logins will fail", "error", err)
		return
	}
	p.links, p.linkStore, p.linkStatus = ls, ls, ls
}

// IdPLinks returns the portal's LinkStore (W-P3-OFFB-02 rotates through it),
// or nil when the IdP link is off.
func (s *Server) IdPLinks() *portal.LinkStore {
	if s.portal == nil {
		return nil
	}
	return s.portal.linkStore
}

// portalLinkView is what the stub page shows of the user's IdP link.
type portalLinkView struct {
	Status      string
	Generation  int64
	RelinkDueAt string
}

// linkView reads the link of (iss, sub) for the stub page. It never carries
// the token or its Reference.
func (p *portalService) linkView(ctx context.Context, iss, sub string) portalLinkView {
	if !p.cfg.IdPLink.Enabled {
		return portalLinkView{Status: portal.LinkDisabled}
	}
	if p.linkStore == nil {
		return portalLinkView{Status: portal.LinkUnknown}
	}
	l, err := p.linkStore.Get(ctx, iss, sub)
	switch {
	case errors.Is(err, portal.ErrLinkNotFound):
		return portalLinkView{Status: portal.LinkMissing}
	case err != nil:
		p.logger.Warn("portal: idp link read failed", "error", err)
		return portalLinkView{Status: portal.LinkUnknown}
	}
	return portalLinkView{Status: portal.LinkLinked, Generation: l.Generation, RelinkDueAt: l.RelinkDueAt.UTC().Format(time.RFC3339)}
}

const (
	actionIdPLinked = "user.idp_linked"
	targetIdPLink   = "idp_link"
)

// recordIdPLinked records user.idp_linked for a stored link. The target ref is
// the user key; neither the token nor its Reference is recorded.
func (s *Server) recordIdPLinked(r *http.Request, iss, sub, email string) {
	uk, err := secrets.UserKey(iss, sub)
	if err != nil {
		return
	}
	s.recordAuth(r.Context(), adminaudit.Input{
		Actor: adminaudit.Actor{Sub: sub, Email: email}, AuthMethod: adminaudit.AuthMethodOIDC,
		Action: actionIdPLinked, Outcome: adminaudit.OutcomeOK,
		Target: targetIdPLink, TargetRef: uk, HTTPStatus: http.StatusFound,
		ClientIP: clientIP(r, s.audit.trusted), RequestID: RequestIDFrom(r.Context()),
	})
}

// idpLinkFailureReason classifies a LinkWriter error for the log line without
// its text: the secret write, or anything after it (the idp_links row).
func idpLinkFailureReason(err error) string {
	if errors.Is(err, portal.ErrLinkSecretStore) {
		return "idp_link_secret_put_failed"
	}
	return "idp_link_row_failed"
}
