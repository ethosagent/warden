package identityclient

import "time"

// Test-only views of the forwarder limits, so a test can pin them to the
// worker's numbers without a production knob.
const (
	TestMaxConnectLineBytes   = maxConnectLineBytes
	TestMaxConnectHeaderBytes = maxConnectHeaderBytes
	TestConnectPreamble       = connectPreambleTimeout
	TestWorkerDialTimeout     = workerDialTimeout

	TestChallengeAskHeader = challengeAskHeader
	TestChallengeAskValue  = challengeAskValue
	TestSignInHeader       = signInHeader
)

// SetPreambleTimeout shortens the preamble deadline for a timeout test.
func (f *Forwarder) SetPreambleTimeout(d time.Duration) { f.preambleTimeout = d }
