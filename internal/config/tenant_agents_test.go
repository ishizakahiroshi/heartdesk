package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAppConfigForTenantUsesTenantAgentFilesAsScope(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SAB_CONFIG_DIR", dir)

	writeTestFile(t, filepath.Join(dir, "config.toml"), `
[agent."alpha-rental-host1"]
agent_id = "alpha-rental-host1"
agent_type = "rental"
agent_label = "host-1.example.com"

[agent."beta-vps-host2"]
agent_id = "beta-vps-host2"
agent_type = "vps"
agent_label = "host-2.example.com (common)"
`)
	writeTestFile(t, filepath.Join(dir, "tenants", "beta", "config.toml"), `
[ui]
default_agent = "beta-vps-host2"
`)
	writeTestFile(t, filepath.Join(dir, "tenants", "beta", "vps", "host2.agent.toml"), `
[agent]
id = "beta-vps-host2"
label = "host-2.example.com (tenant)"
type = "vps"

[deploy]
agent_ip = "203.0.113.40"
`)

	cfg, err := LoadAppConfigForTenant("beta")
	if err != nil {
		t.Fatalf("LoadAppConfigForTenant failed: %v", err)
	}
	if _, ok := cfg.Agents["alpha-rental-host1"]; ok {
		t.Fatal("agent from another tenant must not remain in tenant-scoped config")
	}
	agent, ok := cfg.Agents["beta-vps-host2"]
	if !ok {
		t.Fatal("tenant agent should be loaded")
	}
	if agent.AgentLabel != "host-2.example.com (common)" {
		t.Fatalf("existing common metadata for same agent should be preserved, got %q", agent.AgentLabel)
	}
	if agent.AgentIP != "203.0.113.40" {
		t.Fatalf("tenant agent deploy IP should be merged, got %q", agent.AgentIP)
	}
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", path, err)
	}
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}
