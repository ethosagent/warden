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

		// Versioned policy store (W-P1-PVER-01): the first start imports the YAML
		// as version 1; a head written out of process reaches workers. In-process
		// only (it writes the control plane's state database).
		{Name: "policy_store_versioned", Opts: policyStoreOpts(), Run: policyStoreVersioned},
		// Initial import (W-P1-PVER-07): version 1 by system:import plus one
		// audit row, enforcement unchanged, nothing more after a restart.
		// In-process only (it reads the CP state dir).
		{Name: "policy_store_initial_import", Opts: policyImportOpts(), Run: policyStoreInitialImport},
		// Block-list store (W-P1-BLOCK-03): a block written through BlockStore by
		// another process reaches the served policy (sub/email only) and leaves on
		// removal. In-process only (it writes the CP state dir).
		{Name: "block_list_served", Opts: blockListOpts(), Run: blockListServed},
		// Versioned publish (W-P1-PVER-02): dashboard policy and llmProviders
		// saves create versions authored anonymous that workers enforce.
		// In-process only (it reads the CP state dir).
		{Name: "policy_store_dashboard_publish", Opts: policyStorePublishOpts(), Run: policyStoreDashboardPublish},
		// Version contract (W-P1-PVER-08): GET reports the head, If-Match names
		// it, a stale save is a 409 naming the author and is audited rejected.
		// In-process only (it reads the CP state dir).
		{Name: "policy_if_match_conflict", Opts: policyContractOpts(), Run: policyIfMatchConflict},
		// Policy history (W-P1-PVER-03): list, diff and a rollback that creates
		// a new version workers enforce, audited as policy.rollback. In-process
		// only (it reads the CP state dir).
		{Name: "policy_history_rollback", Opts: policyHistoryOpts(), Run: policyHistoryRollback},
		// Mirror and drift (W-P1-PVER-05): a save is mirrored into the served
		// YAML; a hand edit is never served, shows as drift and is audited once.
		// In-process only (it edits the CP's file and reads its state dir).
		{Name: "policy_store_mirror_drift", Opts: policyMirrorOpts(), Run: policyStoreMirrorDrift},
		// Import/export CLI (W-P1-PVER-06): an exported version, edited and
		// imported while the control plane runs, reaches workers and is audited
		// as cli. In-process only (it writes the CP state dir).
		{Name: "policy_import_export", Opts: policyImportOpts(), Run: policyImportExport},
		// Fleet policy version (W-P1-PVER-10): a served-ETag change without a
		// Create is logged, and workers on head show its version.
		{Name: "policy_store_fleet_version", Opts: policyStoreOpts(), Run: policyStoreFleetVersion},
		// History panel (W-P1-PVER-04): a versioned save without If-Match is a
		// 428; one naming the head carries its message into the history.
		// In-process only (versioned store).
		{Name: "policy_save_if_match_required", Opts: policySaveIfMatchOpts(), Run: policySaveIfMatchRequired},
		// File mode saves without If-Match as before.
		{Name: "policy_file_mode_save_without_if_match", Run: policyFileModeSaveWithoutIfMatch},

		// Admin audit gate (W-P1-AAUD-05): enabled, the control plane writes the
		// genesis entry and logs its key_id before serving. In-process only (it
		// reads the CP state dir).
		{Name: "admin_audit_enabled_genesis", Opts: adminAuditOpts(), Run: adminAuditEnabledGenesis},
		{Name: "admin_audit_offline_verify", Opts: adminAuditOpts(), Run: adminAuditOfflineVerify},
		// Admin audit middleware (W-P1-AAUD-02): an admin-bearer write in
		// console.auth none is one row for cp-admin-token; wrong bearers and worker
		// traffic write none. In-process only (it reads the CP state dir).
		{Name: "admin_audit_records_bearer_write", Opts: adminAuditBearerOpts(), Run: adminAuditRecordsBearerWrite},
		// In oidc mode a viewer's refused write is one denied row; no session, no row.
		{Name: "admin_audit_records_viewer_denied", Opts: adminAuditOIDCOpts(), Run: adminAuditRecordsViewerDenied},
		// CP admin bearer (W-P1-WTOK-07): --admin-token-env opens dashboard writes,
		// the shared worker token does not, and the admin token opens no worker
		// route. In-process only (the compose stack sets no admin token yet).
		{Name: "cp_admin_token_separates_writes", Opts: cpAdminOpts(), Run: cpAdminTokenSeparatesWrites},
		// File-mode external edits (W-P1-AAUD-08): a hand edit of the served YAML
		// is served and recorded once as config.external_change; a dashboard save
		// is not. In-process only (it edits the CP's file and reads its state dir).
		{Name: "admin_audit_external_edit", Opts: adminAuditOpts(), Run: adminAuditExternalEdit},
		// Admin audit anchor (W-P1-AAUD-06): the chain head is logged as a
		// warden.admin.v1 checkpoint at startup and every 5 minutes of the CP's
		// clock. In-process only (fake clock, CP state dir).
		{Name: "admin_audit_checkpoint", Opts: adminAuditOpts(), Run: adminAuditCheckpoint},
	},
	// Canary across protocols x allow/deny; see canary.go.
	canaryScenarios(),
)
