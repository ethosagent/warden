package tokensvc

// SetDummyHook installs a counter hook called after every dummy verification
// and returns a restore function.
func SetDummyHook(f func()) (restore func()) {
	old := dummyHook
	dummyHook = f
	return func() { dummyHook = old }
}
