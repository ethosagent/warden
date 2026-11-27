package harness

import (
	"strings"
	"testing"
)

// TestPerUserVaultRejectsConsentCombination: WithPerUserSecretsVault renders
// its own consent block, so combining it with WithConsent or WithOAuthBroker
// fails loudly instead of silently dropping one side's configuration.
func TestPerUserVaultRejectsConsentCombination(t *testing.T) {
	for name, opts := range map[string][]Option{
		"consent first": {WithConsent(), WithPerUserSecretsVault()},
		"consent last":  {WithPerUserSecretsVault(), WithConsent()},
		"broker first":  {WithOAuthBroker(), WithPerUserSecretsVault()},
		"broker last":   {WithPerUserSecretsVault(), WithOAuthBroker()},
	} {
		t.Run(name, func(t *testing.T) {
			recCh := make(chan *recordingTB, 1)
			go func() {
				rec := &recordingTB{T: t, goexitFatal: true}
				defer func() { recCh <- rec }()
				New(rec, opts...)
			}()
			rec := <-recCh
			if !rec.Failed() || !strings.Contains(rec.failureMessage(), "cannot combine") {
				t.Fatalf("New accepted the combination: failed=%v msg=%q", rec.Failed(), rec.failureMessage())
			}
		})
	}
}
