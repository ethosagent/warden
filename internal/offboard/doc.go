// Package offboard is the offboarding domain (P3 "Act as the user"). This
// ticket (W-P3-OFFB-02) adds the IdP refresh job: Job refreshes each portal
// user's stored IdP refresh token against the IdP's token endpoint as the
// warden-portal client, verifies the returned ID token, writes the rotated
// token back through the portal's LinkStore (a generation compare-and-swap
// under the per-user lock the portal callback shares), and records the link's
// state. In this ticket the job only observes: it records link_state and
// publishes Findings, and it has no Offboarder seam, so nothing it decides can
// offboard anyone. W-P3-OFFB-01 adds the Offboarder and W-P3-OFFB-05 the
// enforcement on a confirmed upstream refusal.
//
// The package does no I/O: the token endpoint call is the TokenClient port
// (internal/offboard/adapters/oidcrefresh), the links are the LinkStore port
// (portal.LinkStore), the time source is clock.Clock, and Findings leave
// through FindingPublisher. No token, Reference, email or IdP error text is
// ever logged; log lines carry a sha256(sub) prefix and a class only.
package offboard
