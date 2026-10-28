package controlplane

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/integration"
)

// Break-glass startup guards (W-P1-OPS1-09): enabling the emergency login must
// fail closed at boot when it would be unsafe, and warn when its alerts would
// go nowhere. Nothing here runs with break-glass disabled.

// breakGlassSessionWarnEvery is how often an active break-glass session is
// reported.
const breakGlassSessionWarnEvery = 5 * time.Minute

// ValidateBreakGlassStartup refuses to start with an unsafe break-glass
// setup: no --state-dir, a hash that does not load or is out of bounds, or
// plain HTTP on a non-loopback address without allowBehindTLSTerminator.
// listen is the address the CP will bind. Errors name the key or flag and
// never carry the hash.
func ValidateBreakGlassStartup(cc config.ConsoleConfig, p Params, listen string) error {
	bg := cc.BreakGlass
	if !bg.Enabled {
		return nil
	}
	if p.StateDir == "" {
		return errors.New("control-plane: console.breakGlass.enabled needs --state-dir (break-glass sessions are stored there)")
	}
	if _, err := LoadBreakGlassHash(bg); err != nil {
		return errors.New("control-plane: " + err.Error())
	}
	if (p.CACert == "" || p.CAKey == "") && !bg.AllowBehindTLSTerminator && !isLoopbackListen(listen) {
		return errors.New("control-plane: console.breakGlass.enabled sends a password, but the control plane would serve plain HTTP on " + listen +
			" (a non-loopback address): provide --ca-cert/--ca-key, listen on a loopback address, or set console.breakGlass.allowBehindTLSTerminator: true when TLS ends at a proxy in front")
	}
	return nil
}

// isLoopbackListen reports whether a listen address binds only to loopback:
// 127.0.0.0/8, ::1 or localhost. An empty host (":7070"), 0.0.0.0, :: and any
// other host or an address that does not parse are not loopback.
func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// warnBreakGlassSetup logs the two advisory startup WARNs: no alert route for
// a critical breakglass_login Finding, and admin audit off. It is called once,
// after the alert pipeline has been built.
func (s *Server) warnBreakGlassSetup(integrations []integration.InstanceConfig) {
	cc := s.cfg.Console
	if !cc.BreakGlass.Enabled {
		return
	}
	probe := integration.Finding{
		RuleID: findingBreakGlass, Category: "security", Severity: integration.SevCritical,
		Subject:  integration.Subject{Tool: "breakglass"},
		DedupKey: findingBreakGlass + ":success",
	}
	routed := false
	for _, in := range integrations {
		if integration.RoutesFinding(in.Match, probe) {
			routed = true
			break
		}
	}
	switch {
	case s.pipeline == nil:
		s.cfg.Logger.Warn("control-plane: break-glass is enabled but there is no alert pipeline; a break-glass login will not alert anyone",
			"hint", "configure integrations with an alerts.match that routes rule breakglass_login at severity critical")
	case !routed:
		s.cfg.Logger.Warn("control-plane: break-glass is enabled but no integration's alerts.match routes a critical breakglass_login Finding; a break-glass login will not alert anyone",
			"hint", "add a match such as {rule: breakglass_login} or {severity: critical} to an integration")
	}
	if !cc.AdminAudit.Enabled {
		s.cfg.Logger.Warn("control-plane: break-glass is enabled while console.adminAudit.enabled is false; break-glass logins will not be written to the signed audit log")
	}
}

// runBreakGlassSessionWarn logs breakglass_session_active every
// breakGlassSessionWarnEvery on the CP's clock until ctx is done.
func (s *Server) runBreakGlassSessionWarn(ctx context.Context) {
	t := s.cfg.Clock.NewTimer(breakGlassSessionWarnEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
			s.warnBreakGlassSessions(ctx)
			t.Reset(breakGlassSessionWarnEvery)
		}
	}
}

// warnBreakGlassSessions logs one WARN with the number of live break-glass
// sessions and the earliest expiry, or nothing when there is none. It never
// logs a session id.
func (s *Server) warnBreakGlassSessions(ctx context.Context) {
	list, err := s.sessions.List(ctx)
	if err != nil {
		s.cfg.Logger.Warn("control plane: break-glass session check failed", "error", err)
		return
	}
	n := 0
	var earliest time.Time
	for _, sess := range list {
		if sess.AuthMethod != AuthMethodBreakglass {
			continue
		}
		if n == 0 || sess.ExpiresAt.Before(earliest) {
			earliest = sess.ExpiresAt
		}
		n++
	}
	if n == 0 {
		return
	}
	s.cfg.Logger.LogAttrs(ctx, slog.LevelWarn, "breakglass_session_active",
		slog.Int("count", n), slog.String("earliest_expiry", earliest.UTC().Format(time.RFC3339)))
}
