package deploy

import "testing"

var claudeCodeRecipe = recipeSpec{
	name:        "claude-code",
	keyEnv:      "ANTHROPIC_API_KEY",
	placeholder: "anthropic_secret_001",
	keyPrefix:   "sk-ant-",
	host:        "api.anthropic.com",
	workerToken: "WARDEN_CLAUDE_CODE_WORKER_TOKEN",
	wantEnv: map[string]string{
		"NO_PROXY":            "localhost,127.0.0.1,::1",
		"NODE_EXTRA_CA_CERTS": "/etc/warden/certs/proxy-ca.crt",
		"NODE_USE_ENV_PROXY":  "1",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
		"DISABLE_AUTOUPDATER":                      "1",
	},
}

// TestClaudeCodeRecipe pins the isolation shape of docker-compose.claude-code.yml
// (assertions shared with the Codex recipe live in recipe_common_test.go).
func TestClaudeCodeRecipe(t *testing.T) { checkRecipe(t, claudeCodeRecipe) }

// TestClaudeCodeRecipePolicy pins the served policy and the worker mapping.
func TestClaudeCodeRecipePolicy(t *testing.T) { checkRecipePolicy(t, claudeCodeRecipe) }
