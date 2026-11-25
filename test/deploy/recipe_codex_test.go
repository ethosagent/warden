package deploy

import "testing"

var codexRecipe = recipeSpec{
	name:        "codex",
	keyEnv:      "OPENAI_API_KEY",
	placeholder: "openai_secret_001",
	keyPrefix:   "sk-",
	host:        "api.openai.com",
	workerToken: "WARDEN_CODEX_WORKER_TOKEN",
	wantEnv: map[string]string{
		"NO_PROXY":             "localhost,127.0.0.1,::1",
		"CODEX_CA_CERTIFICATE": "/etc/warden/certs/proxy-ca.crt",
		"SSL_CERT_FILE":        "/etc/warden/certs/proxy-ca.crt",
	},
}

// TestCodexRecipe pins the isolation shape of docker-compose.codex.yml: the same
// assertions as the Claude Code recipe (internal-only agent, volume allowlist, no
// privilege or side doors, sentinel key on the worker only, digest-pinned images).
func TestCodexRecipe(t *testing.T) { checkRecipe(t, codexRecipe) }

// TestCodexRecipePolicy pins the served policy (api.openai.com:443 only, agent
// codex in require mode) and the worker's placeholder swap.
func TestCodexRecipePolicy(t *testing.T) { checkRecipePolicy(t, codexRecipe) }
