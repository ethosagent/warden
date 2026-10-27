package dashboard

// registerRoutes mounts the dashboard routes added since the routes.go
// migration began (rule X9: new registrations live here; the older ones in
// Handler are baselined until they move). Every path must be in Routes().
//
//	GET  /dashboard/api/policy/versions                 viewer  (W-P1-PVER-03)
//	GET  /dashboard/api/policy/versions/{v}             viewer
//	GET  /dashboard/api/policy/versions/{v}/diff        viewer
//	POST /dashboard/api/policy/versions/{v}/rollback    editor, audited policy.rollback
//
// The policy history routes answer 404 unless SetPolicyHistory was called
// (a control plane in --policy-store=versioned).
func (s *Server) registerRoutes(mux *routeMux) {
	mux.HandleFunc("/dashboard/api/policy/versions", s.handlePolicyVersions)
	mux.HandleFunc("/dashboard/api/policy/versions/", s.handlePolicyVersion)
}
