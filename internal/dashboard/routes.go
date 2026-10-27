package dashboard

// registerRoutes mounts the dashboard routes added since the routes.go
// migration began (rule X9: new registrations live here; the older ones in
// Handler are baselined until they move). Every path must be in Routes(), and
// the control plane's authz table gives it a role (the per-route role
// annotation X9 plans arrives with the routes.go migration).
//
//	GET  /dashboard/api/admin-audit                     admin   (W-P1-AAUD-03)
//	POST /dashboard/api/admin-audit/verify              admin
//	GET  /dashboard/api/admin-audit/pubkey              any role
//	GET  /dashboard/api/policy/versions                 viewer  (W-P1-PVER-03)
//	GET  /dashboard/api/policy/versions/{v}             viewer
//	GET  /dashboard/api/policy/versions/{v}/diff        viewer
//	POST /dashboard/api/policy/versions/{v}/rollback    editor, audited policy.rollback
//
//	GET  /dashboard/api/worker-tokens                   viewer  (W-P1-WTOK-03)
//	POST /dashboard/api/worker-tokens                   admin, audited worker_token.create
//	DELETE /dashboard/api/worker-tokens/{id}            admin, audited worker_token.revoke
//
// The admin audit log routes are distinct from the receipts
// /dashboard/api/audit routes and answer 404 unless the control plane set an
// AdminAuditSource. The worker token routes answer 404 unless SetWorkerTokens
// was called, and refuse a mint or revoke outside console.auth oidc (use_cli).
// The policy history routes answer 404 unless SetPolicyHistory was called
// (a control plane in --policy-store=versioned).
func (s *Server) registerRoutes(mux *routeMux) {
	mux.HandleFunc("/dashboard/api/admin-audit", s.handleAdminAudit)
	mux.HandleFunc("/dashboard/api/admin-audit/verify", s.handleAdminAuditVerify)
	mux.HandleFunc("/dashboard/api/admin-audit/pubkey", s.handleAdminAuditPubKey)
	mux.HandleFunc("/dashboard/api/policy/versions", s.handlePolicyVersions)
	mux.HandleFunc("/dashboard/api/policy/versions/", s.handlePolicyVersion)
	mux.HandleFunc("/dashboard/api/worker-tokens", s.handleWorkerTokens)
	mux.HandleFunc("/dashboard/api/worker-tokens/", s.handleWorkerTokenByID)
}
