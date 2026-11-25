package worker

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// TestRun_Managed_AppliesBootSettings: the identity settings in the boot pull
// are in force on the first CONNECT, with no policy change after boot. The
// stub control plane answers every long-poll with 304, so nothing but the boot
// apply can move the worker off its local identity config (none: mode off).
func TestRun_Managed_AppliesBootSettings(t *testing.T) {
	for _, tc := range []struct {
		name     string
		settings config.SettingsWire
	}{
		{"identity defaultMode", config.SettingsWire{
			Identity: &config.IdentitySettings{DefaultMode: config.IdentityModeChallenge, Issuer: "https://127.0.0.1:1", Audience: "warden"},
		}},
		{"agents entry", config.SettingsWire{
			Identity: &config.IdentitySettings{DefaultMode: config.IdentityModeAttribute, Issuer: "https://127.0.0.1:1", Audience: "warden"},
			Agents:   []config.AgentSettings{{ID: "boot-agent", Identity: config.IdentityModeChallenge}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := json.Marshal(map[string]any{
				"allowlist": []map[string]string{{"domain": "api.example.test"}},
				"settings":  tc.settings,
			})
			if err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			mux.HandleFunc("/policy", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("wait") != "" && r.Header.Get("If-None-Match") == `"v1"` {
					w.WriteHeader(http.StatusNotModified)
					return
				}
				w.Header().Set("ETag", `"v1"`)
				_, _ = w.Write(wire)
			})
			mux.HandleFunc("/control/heartbeat", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			cp := httptest.NewTLSServer(mux)
			defer cp.Close()
			caPath := filepath.Join(t.TempDir(), "cp-ca.pem")
			if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cp.Certificate().Raw}), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("WARDEN_CP_TOKEN", "test-token")
			cfg := `
controlPlane:
  endpoint: ` + cp.URL + `/policy
  tokenEnv: WARDEN_CP_TOKEN
  caCert: ` + caPath + `
  longPollWait: 50ms
  heartbeatInterval: 1s
logging:
  level: error
  format: text
`
			p := runParams(t, writeConfig(t, cfg))
			p.AgentID = "boot-agent"
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			p.ProxyListener = ln
			ready := make(chan string, 1)
			p.OnReady = func(proxyAddr, _ string) { ready <- proxyAddr }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() { runErr <- Run(ctx, &syncBuffer{}, p) }()
			var addr string
			select {
			case addr = <-ready:
			case err := <-runErr:
				t.Fatalf("Run returned before ready: %v", err)
			case <-time.After(10 * time.Second):
				t.Fatal("the worker never became ready")
			}
			if got := anonymousConnect(t, addr, "api.example.test:443"); got != http.StatusProxyAuthRequired {
				t.Fatalf("first anonymous CONNECT = %d, want 407: the boot pull's identity settings are not in force", got)
			}
			cancel()
			select {
			case err := <-runErr:
				if err != nil {
					t.Fatalf("Run returned error on clean shutdown: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not return after ctx cancel")
			}
		})
	}
}

// anonymousConnect sends one CONNECT with no Proxy-Authorization and returns
// the reply's status.
func anonymousConnect(t *testing.T, addr, hostPort string) int {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostPort, hostPort); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read the CONNECT reply: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}
