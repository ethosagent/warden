package secrets

// NewFakeAWSClientForTest exposes the in-package AWS client fake to the
// external secrets_test package (conformance_test.go).
func NewFakeAWSClientForTest() AWSSecretsClient { return newFakeAWSClient() }
