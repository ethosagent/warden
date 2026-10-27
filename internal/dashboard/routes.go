package dashboard

// registerRoutes mounts the dashboard routes added since rule X9 (routes are
// registered only in routes.go); Handler calls it next to the older,
// baselined registrations in dashboard.go. Each path must also be listed in
// Routes(), and the control plane's authz table gives it a role.
func (s *Server) registerRoutes(mux *routeMux) {
	// The admin audit log (W-P1-AAUD-03), distinct from the receipts
	// /dashboard/api/audit routes: 404 unless the control plane set an
	// AdminAuditSource. List and verify are admin, pubkey any role.
	mux.HandleFunc("/dashboard/api/admin-audit", s.handleAdminAudit)
	mux.HandleFunc("/dashboard/api/admin-audit/verify", s.handleAdminAuditVerify)
	mux.HandleFunc("/dashboard/api/admin-audit/pubkey", s.handleAdminAuditPubKey)
}
