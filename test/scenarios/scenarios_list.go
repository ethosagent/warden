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

		// Identity challenge mode (#558): a CONNECT with no valid identity gets a
		// 407 with a sign-in URL from the issuer fake's device endpoint.
		{Name: "challenge_no_token", Opts: challengeOpts(), Run: challengeNoToken},
		{Name: "challenge_valid_token", Opts: challengeOpts(), Run: challengeValidToken},
		{Name: "challenge_expired_token", Opts: challengeOpts(), Run: challengeExpiredToken},
		{Name: "challenge_invalid_token", Opts: challengeOpts(), Run: challengeInvalidToken},
		{Name: "challenge_unverified", Opts: challengeOpts(), Run: challengeUnverified},
		{Name: "challenge_issuer_down", Opts: challengeOpts(), Run: challengeIssuerDown},
		{Name: "challenge_singleflight", Opts: challengeOpts(), Run: challengeSingleflight},
		{Name: "challenge_rate_limit", Opts: challengeOpts(harness.WithSignIn(config.SignInSettings{StartsPerMinute: 1})), Run: challengeRateLimit},
		{Name: "challenge_foreign_url", Opts: challengeOpts(), Run: challengeForeignURL},
		{Name: "challenge_signed_in_next", Opts: challengeOpts(), Run: challengeSignedInNext},
		// The challenge inside the tunnel (#621): the agent's own chat shows the
		// link. In-process only: the forwarder and the issuer fake are.
		{Name: "challenge_in_tunnel", Opts: challengeOpts(), Run: challengeInTunnel},
		{Name: "attribute_unchanged", Opts: identityOpts(), Run: attributeUnchanged},
		{Name: "challenge_hot_reload", Opts: identityOpts(), Run: challengeHotReload},
		// Fail-open guard: only a worker without identity/challenge-v1 is flagged
		// while challenge mode is served.
		{Name: "challenge_fleet_flag", Opts: challengeOpts(harness.Fleet(1)), Run: challengeFleetFlag},

		// Console OIDC login (W-P1-SSO-03): a real login through the issuer fake
		// creates a session with the right cookie flags, and the session expires
		// by the control plane's clock. In-process only (issuer fake, fake clock).
		{Name: "console_oidc_login", Opts: consoleOpts(), Run: consoleOIDCLogin},
		// Console enforcement (W-P1-SSO-06): oidc starts, the shared bearer opens no
		// human route, and workers keep pulling /policy with it.
		{Name: "console_oidc_bearer_rejected", Opts: consoleOpts(), Run: consoleOIDCBearerRejected},

		// Break-glass login (W-P1-OPS1-08): a real argon2id login opens a Secure
		// admin session with a signed row, an ERROR line and a Finding per
		// attempt; five failures lock an address out; disabled it is a 404.
		// In-process only (fake clock, state db).
		{Name: "breakglass_login", Opts: breakGlassOpts(), Run: breakGlassLogin},
		{Name: "breakglass_rate_limit", Opts: breakGlassOpts(), Run: breakGlassRateLimit},
		{Name: "breakglass_disabled", Opts: adminAuditOIDCOpts(), Run: breakGlassDisabled},
		// Degraded mode (W-P1-OPS1-09): with the issuer down at start the control
		// plane still serves workers, sign-in is 503 idp_unavailable and the
		// break-glass login works, loudly, with no integration configured.
		{Name: "breakglass_idp_down", Opts: append(breakGlassOpts(), harness.WithOIDCIssuerDown()), Run: breakGlassIdPDown},

		// Versioned policy store (W-P1-PVER-01): the first start imports the YAML
		// as version 1; a head written out of process reaches workers. In-process
		// only (it writes the control plane's state database).
		// Scheduled backups (W-P1-OPS1-06): a startup set, the next one past the
		// interval on the fake clock, pruning, no key files. In-process only.
		{Name: "backup_scheduled", Opts: backupOpts(), Run: backupScheduled},
		// Backup health (W-P1-OPS1-07): a failing runner raises backup_failed and
		// backup_stale Findings in the alert store while /policy keeps serving, and
		// /dashboard/api/setup shows the status to admins only.
		{Name: "backup_failure_findings", Opts: []harness.Option{harness.WithBackupUnwritable()}, Run: backupFailureFindings},
		{Name: "backup_status_admin_only", Opts: []harness.Option{harness.WithConsoleOIDC(), harness.WithBackup()}, Run: backupStatusAdminOnly},
		{Name: "backup_status_disabled", Opts: consoleOpts(), Run: backupStatusDisabled},
		// On-demand backup (W-P1-OPS1-11): POST /dashboard/api/backup is an
		// audited admin action; 404 without --backup-dir. In-process only.
		{Name: "backup_trigger_admin", Opts: backupTriggerOpts(), Run: backupTriggerAdmin},
		{Name: "backup_trigger_disabled", Opts: backupTriggerDisabledOpts(), Run: backupTriggerDisabled},
		// Verified restore (W-P1-OPS1-04): the control plane's own backup set
		// restores into an empty state dir; a running control plane's state dir
		// and a tampered set are refused. In-process only.
		{Name: "restore_verified", Opts: restoreOpts(), Run: restoreVerified},

		{Name: "policy_store_versioned", Opts: policyStoreOpts(), Run: policyStoreVersioned},
		// Initial import (W-P1-PVER-07): version 1 by system:import plus one
		// audit row, enforcement unchanged, nothing more after a restart.
		// In-process only (it reads the CP state dir).
		{Name: "policy_store_initial_import", Opts: policyImportOpts(), Run: policyStoreInitialImport},
		// Block-list store (W-P1-BLOCK-03): a block written through BlockStore by
		// another process reaches the served policy (sub/email only) and leaves on
		// removal. In-process only (it writes the CP state dir).
		{Name: "block_list_served", Opts: blockListOpts(), Run: blockListServed},
		// Block-list worker path (W-P1-BLOCK-09): a block made over the CP API
		// denies new CONNECTs on both workers, cuts open sessions and raises one
		// Finding per user. In-process only (issuer fake, fake clock).
		{Name: "block_list_connect", Opts: blockListFleetOpts(), Run: blockListConnect},
		{Name: "block_list_sessions", Opts: blockListSessionsOpts(), Run: blockListSessions},
		{Name: "block_list_finding", Opts: blockListFindingOpts(), Run: blockListFinding},
		// Block survival (W-P1-BLOCK-12): a block outlives a policy rollback, a
		// worker restart and a control-plane outage; an offline block lands once
		// the control plane returns; unblocking restores the pre-block ETag.
		// In-process only (state dir, issuer fake, fake clock, worker restart).
		{Name: "block_list_survives_rollback", Opts: blockSurvivalOpts(), Run: blockListSurvivesRollback},
		{Name: "block_list_survives_restart", Opts: blockSurvivalOpts(), Run: blockListSurvivesRestart},
		{Name: "block_list_survives_cp_outage", Opts: blockSurvivalOpts(), Run: blockListSurvivesCPOutage},
		{Name: "block_list_unblock_restores", Opts: blockSurvivalOpts(), Run: blockListUnblockRestores},
		// Block-list admin API (W-P1-BLOCK-11).
		{Name: "block_api_bearer", Opts: blockAPIBearerOpts(), Run: blockAPIBearer},
		{Name: "block_api_roles", Opts: blockAPIOIDCOpts(), Run: blockAPIRoles},
		// Console denial for blocked principals (W-P1-BLOCK-07): a block ends the
		// admin's session and refuses their next login (403, one audit row);
		// break-glass still opens the console. In-process only (it writes the CP
		// state dir and reads the session table).
		{Name: "blocked_principal_denied", Opts: breakGlassOpts(), Run: blockedPrincipalDenied},
		// Versioned publish (W-P1-PVER-02): dashboard policy and llmProviders
		// saves create versions authored anonymous that workers enforce.
		// In-process only (it reads the CP state dir).
		{Name: "policy_store_dashboard_publish", Opts: policyStorePublishOpts(), Run: policyStoreDashboardPublish},
		// Scoped policy (W-P1-GPOL-10): with identity off a scoped entry loads
		// but allows nobody (identity_required); an unscoped entry still applies.
		{Name: "scoped_policy_fail_closed", Run: scopedPolicyFailClosed},
		// Per-request scoped decisions (W-P1-GPOL-10): each request, on h1 and
		// every h2 stream, is decided with its own verified subject; members are
		// forwarded, non-members and anonymous callers are denied.
		{Name: "scoped_policy_deferred_identity", Opts: identityOpts(), Run: scopedPolicyDeferredIdentity},
		// Replay of recorded identities (W-P1-GPOL-05): a candidate narrowing a
		// scoped rule names the affected user and counts anonymous apart.
		// Fleet flag (W-P1-GPOL-07): workers of this build advertise
		// grouppolicy/v1; only a legacy worker is flagged noGroupPolicy while
		// scoped rules are served.
		{Name: "scoped_policy_fleet_flag", Opts: []harness.Option{harness.Fleet(1)}, Run: scopedPolicyFleetFlag},
		{Name: "scoped_policy_replay_affected_users", Opts: identityOpts(), Run: scopedPolicyReplayAffectedUsers},
		// MCP subject seam (W-P1-GPOL-04): the verified subject reaches the MCP
		// gateway through RequestMeta without changing any verdict.
		{Name: "mcp_subject_seam_unchanged", Opts: mcpSubjectOpts(), Run: mcpSubjectSeamUnchanged},
		// Group-gated MCP tools (W-P1-GPOL-11): allowWhen.groups is decided with
		// the request's verified subject; non-members are denied mcp_tool_condition.
		{Name: "mcp_group_condition", Opts: mcpGroupOpts(), Run: mcpGroupCondition},
		// Dashboard editor round trip (W-P1-GPOL-08): groups/users saved through
		// /dashboard/api/policy come back normalized and scoped, an empty chip is a
		// 400, the worker enforces the rule and the GET lints a shadowing entry.
		{Name: "scoped_policy_dashboard_editor", Opts: identityOpts(), Run: scopedPolicyDashboardEditor},
		// Group-aware policy on the L1 harness (W-P1-GPOL-09): a {domain, groups}
		// entry and a group-gated MCP tool, served by the control plane and
		// decided per request. Every deny leaves the judge fake and the upstream
		// untouched; no allow lets an identity header reach the upstream.
		{Name: "groups_member_allowed", Opts: groupsOpts(), Run: groupsMemberAllowed},
		{Name: "groups_nonmember_denied", Opts: groupsOpts(), Run: groupsNonMemberDenied},
		{Name: "groups_anonymous_denied", Opts: groupsOpts(), Run: groupsAnonymousDenied},
		{Name: "groups_expired_denied", Opts: groupsOpts(), Run: groupsExpiredDenied},
		{Name: "groups_keepalive_mixed_users", Opts: groupsOpts(), Run: groupsKeepaliveMixedUsers},
		{Name: "groups_h2_per_stream", Opts: groupsOpts(), Run: groupsH2PerStream},
		{Name: "groups_no_ca_conditional", Opts: append(groupsOpts(), harness.WithoutProxyCA()), Run: groupsNoCAConditional},
		{Name: "groups_raw_bytes_conditional", Opts: groupsOpts(), Run: groupsRawBytesConditional},
		{Name: "groups_truncated", Opts: groupsOpts(), Run: groupsTruncated},
		{Name: "groups_mcp_tool_gated", Opts: groupsMCPOpts(), Run: groupsMCPToolGated},
		{Name: "groups_old_worker_denies", Opts: groupsMCPOpts(), Run: groupsOldWorkerDenies},
		{Name: "groups_policy_eval_affected_users", Opts: groupsOpts(), Run: groupsPolicyEvalAffectedUsers},
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

		// Per-worker tokens (W-P1-WTOK-02): a bound token authenticates /policy,
		// heartbeat and ingest, its bound id is what the CP records, an
		// out-of-process revoke takes effect, and it opens no human route.
		// In-process only (it writes the CP state dir, fake clock).
		{Name: "worker_token_auth", Opts: workerTokenOpts(), Run: workerTokenAuth},
		// Worker token admin API (W-P1-WTOK-03): an admin mints (shown once),
		// lists and revokes tokens from the console; the fleet view shows how each
		// worker authenticates; create and revoke are audited. In-process only.
		{Name: "worker_token_admin_api", Opts: workerTokenAdminOpts(), Run: workerTokenAdminAPI},
		// Without console sign-in the API is read-only: writes answer use_cli.
		{Name: "worker_token_admin_use_cli", Opts: workerTokenOpts(), Run: workerTokenAdminUseCLI},
		// Strict worker auth (W-P1-WTOK-04): --require-worker-tokens refuses the
		// shared token on the worker routes while the admin token keeps dashboard
		// and secret writes working; with no admin token both fail closed. Mixed
		// mode marks shared-token workers legacy and warns once per proxy id.
		// In-process only (state dir, fake clock).
		{Name: "strict_worker_auth", Opts: strictAuthOpts(), Run: strictWorkerAuth},
		{Name: "strict_worker_auth_no_admin_token", Opts: strictNoAdminOpts(), Run: strictNoAdminTokenFailsClosed},
		{Name: "legacy_worker_token_warning", Run: legacyWorkerWarning},
		// Held long-poll (W-P1-WTOK-09): a revoke out of process returns that
		// token's held /policy with 401 while another token's stays parked.
		{Name: "worker_token_longpoll_revoke", Opts: workerTokenOpts(), Run: workerTokenLongPollRevoke},

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
		// JSON admin stream (W-P1-JAUD-03): the checkpoint and an admin write are
		// warden.admin.v1 lines equal to the stored row. In-process only.
		{Name: "admin_audit_json_log_writes_lines", Opts: adminAuditJSONLogOpts(), Run: adminAuditJSONLogWritesLines},
		{Name: "admin_audit_records_viewer_denied", Opts: adminAuditOIDCOpts(), Run: adminAuditRecordsViewerDenied},
		// Login and logout events (W-P1-AAUD-07): a sign-in, a no-role sign-in and a
		// logout are one row each, for the verified user. In-process only (issuer
		// fake, CP state dir).
		{Name: "admin_audit_records_login_logout", Opts: adminAuditOIDCOpts(), Run: adminAuditRecordsLoginLogout},
		// Admin audit dashboard API (W-P1-AAUD-03): list, verify and pubkey over the
		// real chain, read-only (no row added); verify needs the admin bearer in none
		// mode and admin in oidc, where a viewer may read only the keys; with admin
		// audit off all three are 404. In-process only (they read the CP state dir).
		{Name: "admin_audit_dashboard_bearer", Opts: adminAuditBearerOpts(), Run: adminAuditDashboardBearer},
		{Name: "admin_audit_dashboard_roles", Opts: adminAuditOIDCOpts(), Run: adminAuditDashboardRoles},
		{Name: "admin_audit_dashboard_disabled", Opts: []harness.Option{harness.WithControlPlaneAdminToken()}, Run: adminAuditDashboardDisabled},
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
		// Signing keys (W-P2-KEYS-02): keys.enabled creates an active and a next
		// key per purpose in the file store and keeps them across a restart; a
		// key store that is down at startup never stops the control plane and
		// signing recovers with the store; a control plane without keys keeps no
		// key table. Rotation (W-P2-KEYS-03): a token key past its interval is
		// retired and replaced without a verify gap, and a restart after a
		// downtime catches up on the missed rotation. In-process only (they stop
		// and start the CP and read its state dir).
		{Name: "keys_file_store_restart", Opts: keysOpts(), Run: keysFileStoreRestart},
		{Name: "keys_backend_down_recovers", Opts: keysFlakyOpts(), Run: keysBackendDownRecovers},
		{Name: "keys_rotate_on_schedule", Opts: keysRotationOpts(), Run: keysRotateOnSchedule},
		{Name: "keys_rotate_after_downtime", Opts: keysRotationOpts(), Run: keysRotateAfterDowntime},
		{Name: "keys_jwks_served_and_rotates", Opts: keysRotationOpts(), Run: keysJWKSServedAndRotates},
		{Name: "keys_jwks_unavailable_until_loaded", Opts: keysFlakyOpts(), Run: keysJWKSUnavailableUntilLoaded},
		{Name: "keys_disabled_creates_nothing", Opts: []harness.Option{harness.WithBackup()}, Run: keysDisabledCreatesNothing},
	},
	// Canary across protocols x allow/deny; see canary.go.
	canaryScenarios(),
)
