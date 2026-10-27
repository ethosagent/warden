package dashboard

// registerRoutes mounts dashboard routes that are not in rule X9's baseline.
// X9 allows a registration only in routes.go, and the baseline's allow list
// names each pre-migration path in dashboard.go, so a new path cannot be
// registered there without growing the baseline. Handler calls this beside the
// baselined registrations. Each path must also be listed in Routes(), and the
// control plane's authz table gives it a role (the per-route role annotation
// X9 plans arrives with the routes.go migration).
func (s *Server) registerRoutes(mux *routeMux) {
	// The admin audit log (W-P1-AAUD-03), distinct from the receipts
	// /dashboard/api/audit routes: 404 unless the control plane set an
	// AdminAuditSource. List and verify are admin, pubkey any role.
	mux.HandleFunc("/dashboard/api/admin-audit", s.handleAdminAudit)
	mux.HandleFunc("/dashboard/api/admin-audit/verify", s.handleAdminAuditVerify)
	mux.HandleFunc("/dashboard/api/admin-audit/pubkey", s.handleAdminAuditPubKey)
}
