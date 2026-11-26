package security

// allCases lists every case the suite declares, for the enum-completeness test.
// A ticket that adds cases declares them as a package-level slice and appends it
// here (one line), then deletes the lines it covers from pending.go. There is no
// registration at init time: the list is plain data, so a case that is not here
// is not counted as covered.
func allCases() []Case {
	var out []Case
	for _, group := range [][]Case{
		smokeWorker, smokeToken, smokeRoute,
		crossAgentCases, unboundWorkerCases, rotatedKeyCases,
		blockedUserCases, disabledAgentCases, revokedKeyCases, issuanceCases, expiredTokenCases,
		certCases(), {serverCertCase, revokedCase}, bundleCases(),
		wardenForgeries, wardenTimeBounds, idpCases, idpVerifiedCases, requireInTunnel(), rawDexRefused,
		exchangeCases, requestRefusals, {replayedJTI()}, forgedNonceCases, signerCases, rateCases,
		enrollCases(nil), renewCases(nil), routeCases(&routeFixtures{}, "", "", true),
		storeOutageCases(), {idpUnavailable, jwksUnavailable},
	} {
		out = append(out, group...)
	}
	return out
}
