package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

func TestAgentReportHandlerTenantKeySources(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HEARTDESK_CONFIG_DIR", dir)
	t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
	config.ReloadConfigCache()
	t.Cleanup(config.ReloadConfigCache)
	writeConfig := func(name, body string) {
		t.Helper()
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig("config.toml", `
[agent_report]
strict_license = false
timestamp_skew_sec = 120

[agent."default-vps-demo"]
agent_type = "vps"
[agent."t101-vps-demo"]
agent_type = "vps"
[agent."t102-vps-demo"]
agent_type = "vps"
[agent."t103-vps-demo"]
agent_type = "vps"

[agent_allowed_ips]
"default-vps-demo" = ["192.0.2.10"]
"t101-vps-demo" = ["192.0.2.10"]
"t102-vps-demo" = ["192.0.2.10"]
"t103-vps-demo" = ["192.0.2.10"]
`)
	writeConfig("tenants/default/config.toml", `
[agent_report]
strict_license = true
[agent_allowed_ips]
"t101-vps-demo" = ["203.0.113.10"]
`)
	writeConfig("tenants/default/secrets.toml", `
[agent_keys]
"default-vps-demo" = "test-local-000"
[aggregator_agent_keys]
"t101-vps-demo" = "test-agg-101"
"t102-vps-demo" = "test-agg-102"
`)
	writeConfig("tenants/t101/secrets.toml", `
[agent_keys]
"t101-vps-demo" = "test-local-101"
[aggregator_agent_keys]
"t101-vps-demo" = "test-other-101"
`)
	writeConfig("tenants/t102/secrets.toml", `
[agent_keys]
"t102-vps-demo" = "test-local-102"
`)
	t.Cleanup(func() {
		agentLastSeenMu.Lock()
		defer agentLastSeenMu.Unlock()
		for _, id := range []string{"default-vps-demo", "t101-vps-demo", "t102-vps-demo", "t103-vps-demo"} {
			delete(agentLastSeen, id)
			delete(agentLatestCollectors, id)
		}
	})

	cases := []struct {
		name           string
		agentID        string
		key            string
		age            time.Duration
		remoteIP       string
		missingHeaders bool
		wantStatus     int
	}{
		{name: "first remote tenant aggregator key", agentID: "t101-vps-demo", key: "test-agg-101", wantStatus: http.StatusOK},
		{name: "second remote tenant aggregator key", agentID: "t102-vps-demo", key: "test-agg-102", wantStatus: http.StatusOK},
		{name: "first tenant local key preserved", agentID: "t101-vps-demo", key: "test-local-101", wantStatus: http.StatusOK},
		{name: "second tenant local key preserved", agentID: "t102-vps-demo", key: "test-local-102", wantStatus: http.StatusOK},
		{name: "reporting tenant cannot supply aggregator key", agentID: "t101-vps-demo", key: "test-other-101", wantStatus: http.StatusUnauthorized},
		{name: "another agent aggregator key rejected", agentID: "t101-vps-demo", key: "test-agg-102", wantStatus: http.StatusUnauthorized},
		{name: "wrong key rejected", agentID: "t101-vps-demo", key: "test-wrong", wantStatus: http.StatusUnauthorized},
		{name: "missing key rejected", agentID: "t103-vps-demo", key: "test-missing", wantStatus: http.StatusUnauthorized},
		{name: "stale timestamp rejected", agentID: "t101-vps-demo", key: "test-agg-101", age: 10 * time.Minute, wantStatus: http.StatusUnauthorized},
		{name: "IP allowlist preserved", agentID: "t101-vps-demo", key: "test-agg-101", remoteIP: "192.0.2.11", wantStatus: http.StatusForbidden},
		{name: "missing headers rejected", agentID: "t101-vps-demo", missingHeaders: true, wantStatus: http.StatusUnauthorized},
		{name: "default tenant still requires bearer", agentID: "default-vps-demo", key: "test-local-000", wantStatus: http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(AgentReport{
				AgentID: tc.agentID, AgentType: "vps", ReportedAt: time.Now().Format(time.RFC3339),
				Collectors: map[string]json.RawMessage{},
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/agent/report", bytes.NewReader(body))
			remoteIP := tc.remoteIP
			if remoteIP == "" {
				remoteIP = "192.0.2.10"
			}
			req.RemoteAddr = remoteIP + ":12345"
			if !tc.missingHeaders {
				req.Header = signedAgentHeaders(tc.agentID, tc.key, body, time.Now().Add(-tc.age).Unix())
			}
			req.Header.Set("X-Agent-Id", tc.agentID)
			res := httptest.NewRecorder()
			AgentReportHandler(res, req)
			if res.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", res.Code, tc.wantStatus, res.Body.String())
			}
			if tc.wantStatus == http.StatusOK {
				files, err := filepath.Glob(filepath.Join(os.Getenv("HEARTDESK_BASE_DIR"), "data", "json", "agent_reports", fmt.Sprintf("report_%s_*.jsonl", tc.agentID)))
				if err != nil || len(files) != 1 {
					t.Fatalf("accepted report was not saved: files=%d, err=%v", len(files), err)
				}
			}
		})
	}

	// The request must not rewrite the shared tenant cache while selecting keys.
	tenantCfg, err := config.CachedAppConfigForTenant("t101")
	if err != nil {
		t.Fatal(err)
	}
	if tenantCfg.AggregatorAgentKeys["t101-vps-demo"] != "test-other-101" {
		t.Fatal("report handler changed the cached reporting tenant's key map")
	}
}

func TestAgentReportConfigDefaultAndAggregateLoadError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HEARTDESK_CONFIG_DIR", dir)
	t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
	config.ReloadConfigCache()
	t.Cleanup(config.ReloadConfigCache)
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[agent_report]\nstrict_license = false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	defaultCfg, err := config.CachedAppConfigForTenant(config.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := agentReportConfigForTenant("")
	if err != nil || got != defaultCfg {
		t.Fatal("default tenant path must retain its cached config without substituting another tenant")
	}
	config.ReloadConfigCache()
	reporter, err := config.CachedAppConfigForTenant("t101")
	if err != nil {
		t.Fatal(err)
	}
	defaultDir := filepath.Join(dir, "tenants", config.DefaultTenantID)
	if err := os.MkdirAll(defaultDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(defaultDir, "config.toml"), []byte("[invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := agentReportConfigForTenant("t101"); err == nil || cfg != nil {
		t.Fatal("aggregate config load error must not fall back to reporter aggregate keys")
	}
	if cfg, err := config.CachedAppConfigForTenant("t101"); err != nil || cfg != reporter {
		t.Fatal("aggregate config error must not replace the cached reporting config")
	}
}
