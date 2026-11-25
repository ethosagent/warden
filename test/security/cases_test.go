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
		certCases(), {serverCertCase, revokedCase}, bundleCases(),
		wardenForgeries, wardenTimeBounds, idpCases, rawDexRefused,
		exchangeCases, requestRefusals, {replayedJTI()}, forgedNonceCases, signerCases, rateCases,
	} {
		out = append(out, group...)
	}
	return out
}
