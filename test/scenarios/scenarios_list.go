package scenarios

import (
	"slices"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/test/harness"
)

// All is the catalog: every scenario #350's harness runs in-process and #351
// runs on compose. One literal, no init() registration: adding a scenario means
// adding a line here, where a reviewer sees it.
var All = slices.Concat(
	[]Scenario{
		// The four ported integration tests (test/integration, pre-harness).
		{Name: "allowlisted_https_succeeds", Run: allowlistedHTTPSSucceeds},
		{Name: "non_allowlisted_blocked", Run: nonAllowlistedBlocked},
		{Name: "secret_swapped", Opts: swapOpts(), Run: secretSwapped},
		{Name: "decision_logging", Opts: swapOpts(), Run: decisionLogging},

		// The manual testing guide, automated (steps 6 is folded into the canary
		// sweep each of these ends with).
		{Name: "allow_with_swap", L2: true, Opts: swapOpts(), Run: allowWithSwap},
		{Name: "default_deny", L2: true, Run: defaultDeny},
		{Name: "swap_in_body", Opts: swapOpts(), Run: swapInBody},
		{Name: "dashboard_traffic_api", Run: dashboardTrafficAPI},
		{Name: "events_recorded", Opts: swapOpts(), Run: eventsRecorded},
		{Name: "refresh_secrets", Opts: swapOpts(), Run: refreshSecrets},
		{Name: "healthz", Run: healthz},
		{Name: "user_filter_api", Opts: []harness.Option{harness.Fleet(1)}, Run: userFilterAPI},
		{Name: "top_users_api", Opts: []harness.Option{harness.Fleet(1)}, Run: topUsersAPI},

		// Fail closed: the control plane is down when the worker boots.
		{Name: "fail_closed_at_boot", Opts: []harness.Option{harness.Fleet(1), harness.ControlPlaneDownAtBoot()}, Run: failClosedAtBoot},

		// Transparent interception (#376): the same decisions without any proxy
		// configuration — SNI/Host-gated listeners running the one pipeline.
		// In-process only: the levers (TransparentAgent, loopback port-0
		// interception listeners) are assembly-only; compose proves the mode on
		// real networks in the e2e suite.
		{Name: "transparent_tls_allow_with_swap", Opts: append(swapOpts(), harness.TransparentIntercept()), Run: transparentTLSServeAllowWithSwap},
		{Name: "transparent_tls_deny_parity", Opts: []harness.Option{harness.TransparentIntercept()}, Run: transparentTLSServeDeny},
		{Name: "transparent_plain_http_allow_with_swap", Opts: append(swapOpts(), harness.TransparentIntercept()), Run: transparentPlainHTTPAllowWithSwap},

		// Identity attribution (W-P1-VRFY-05): user tokens verified against the
		// in-process OIDC issuer fake, recorded on events, receipts and decision
		// logs. In-process only (the issuer fake and the settings write are).
		{Name: "identity_connect_h1", Opts: identityOpts(), Run: identityMatrix(idTransports[0])},
		{Name: "identity_connect_h2", Opts: identityOpts(), Run: identityMatrix(idTransports[1])},
		{Name: "identity_header_h1", Opts: identityOpts(), Run: identityMatrix(idTransports[2])},
		{Name: "identity_header_h2", Opts: identityOpts(), Run: identityMatrix(idTransports[3])},
		{Name: "identity_raw_tunnel", Opts: identityOpts(), Run: identityRawTunnel},
		{Name: "identity_websocket", Opts: identityOpts(), Run: identityWebSocket},
		{Name: "identity_conflict", Opts: identityOpts(), Run: identityConflict},
		{Name: "identity_deny_attributed", Opts: identityOpts(), Run: identityDenyAttributed},
		{Name: "identity_mode_off", Opts: []harness.Option{harness.WithIdentity(config.IdentityModeOff)}, Run: identityOff},
		{Name: "identity_issuer_down", Opts: identityOpts(), Run: identityIssuerDown},
		{Name: "identity_transparent", Opts: append(identityOpts(), harness.TransparentIntercept()), Run: identityTransparent},
		{Name: "identity_hot_reload", Opts: identityOpts(), Run: identityHotReload},

		// Console OIDC login (W-P1-SSO-03): a real login through the issuer fake
		// creates a session with the right cookie flags, and the session expires
		// by the control plane's clock. In-process only (issuer fake, fake clock).
		{Name: "console_oidc_login", Opts: consoleOpts(), Run: consoleOIDCLogin},
		// Console enforcement (W-P1-SSO-06): oidc starts, the shared bearer opens no
		// human route, and workers keep pulling /policy with it.
		{Name: "console_oidc_bearer_rejected", Opts: consoleOpts(), Run: consoleOIDCBearerRejected},
		// Admin audit gate (W-P1-AAUD-05): enabled, the control plane writes the
		// genesis entry and logs its key_id before serving. In-process only (it
		// reads the CP state dir).
		{Name: "admin_audit_enabled_genesis", Opts: adminAuditOpts(), Run: adminAuditEnabledGenesis},
	},
	// Canary across protocols x allow/deny; see canary.go.
	canaryScenarios(),
)
