package config

import (
	"path/filepath"
	"testing"
)

// TestRejectOrphanAgentSecrets は孤児 agent secrets entry の再現テスト。
// テナント alpha の secrets に同テナント prefix の agent_id (`alpha-vps-host2`) が残存しつつ
// config.toml の [agent.*] に同 ID 定義が無い状態を「孤児 entry」として扱う。
//
// 期待: LoadAppConfigForTenant 後に [agent_keys] / [agent_allowed_ips] から
//
//	削除されていること（reject）。aggregator_agent_keys や他テナント prefix の
//	allowlist entry は除外対象外で残ること。
func TestRejectOrphanAgentSecrets_RemovesSameTenantOrphans(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SAB_CONFIG_DIR", dir)

	// インフラ共通 config.toml に alpha-vps-host1 のみを定義（alpha-vps-host2 は意図的に未登録）。
	writeTestFile(t, filepath.Join(dir, "config.toml"), `
[agent."alpha-vps-host1"]
agent_id = "alpha-vps-host1"
agent_type = "vps"
agent_label = "host-1.example.com (VPS)"

[agent."gamma-vps-host2"]
agent_id = "gamma-vps-host2"
agent_type = "vps"
agent_label = "host-2.example.com (VPS)"
`)

	// テナント alpha secrets に孤児 entry + クロステナント aggregator + クロステナント IP allowlist を含む
	writeTestFile(t, filepath.Join(dir, "tenants", "alpha", "secrets.toml"), `
[agent_keys]
"alpha-vps-host1"  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"alpha-vps-host2"  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[agent_allowed_ips]
"alpha-vps-host1" = ["127.0.0.1"]
"alpha-vps-host2" = ["203.0.113.20"]
"gamma-vps-host2" = ["203.0.113.20"]

[aggregator_agent_keys]
"gamma-vps-host2" = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
`)

	cfg, err := LoadAppConfigForTenant("alpha")
	if err != nil {
		t.Fatalf("LoadAppConfigForTenant failed: %v", err)
	}

	// 孤児 entry が削除されていること。
	if _, ok := cfg.AgentKeys["alpha-vps-host2"]; ok {
		t.Errorf("[agent_keys][\"alpha-vps-host2\"] should be rejected as orphan (no [agent.*] definition)")
	}
	if _, ok := cfg.AgentAllowedIPs["alpha-vps-host2"]; ok {
		t.Errorf("[agent_allowed_ips][\"alpha-vps-host2\"] should be rejected as orphan")
	}

	// 正当な entry は残っていること。
	if _, ok := cfg.AgentKeys["alpha-vps-host1"]; !ok {
		t.Errorf("[agent_keys][\"alpha-vps-host1\"] must remain (defined in config.toml)")
	}
	if _, ok := cfg.AgentAllowedIPs["alpha-vps-host1"]; !ok {
		t.Errorf("[agent_allowed_ips][\"alpha-vps-host1\"] must remain")
	}

	// クロステナント (`gamma-` prefix) の IP allowlist は当該テナント alpha の検証対象外で残ること。
	if _, ok := cfg.AgentAllowedIPs["gamma-vps-host2"]; !ok {
		t.Errorf("[agent_allowed_ips][\"gamma-vps-host2\"] (cross-tenant aggregator) must remain")
	}
	// aggregator_agent_keys は検証対象外。
	if _, ok := cfg.AggregatorAgentKeys["gamma-vps-host2"]; !ok {
		t.Errorf("[aggregator_agent_keys][\"gamma-vps-host2\"] must remain (out of scope for orphan check)")
	}
}

// TestRejectOrphanAgentSecrets_AggregatorAndCrossTenantNotChecked は
// 集約 Monitor 経路（他テナント prefix）が誤って reject されないことを確認する。
func TestRejectOrphanAgentSecrets_AggregatorAndCrossTenantNotChecked(t *testing.T) {
	cfg := &AppConfig{
		AgentKeys: map[string]string{
			"beta-vps-host1": "k1", // cross-tenant: beta prefix だが loaded tenant は alpha
		},
		AgentAllowedIPs: map[string][]string{
			"beta-vps-host1": {"203.0.113.30"},
		},
		AggregatorAgentKeys: map[string]string{
			"beta-vps-host1": "ak1",
		},
		Agents: map[string]AgentConfig{
			// beta-vps-host1 は当該テナント (alpha) 視点では定義されていない
		},
	}
	removed := rejectOrphanAgentSecrets("alpha", cfg)
	if len(removed) != 0 {
		t.Fatalf("cross-tenant entries should not be rejected by tenant alpha check, got: %v", removed)
	}
	if _, ok := cfg.AgentKeys["beta-vps-host1"]; !ok {
		t.Error("cross-tenant agent_keys entry must be preserved (handled at aggregator path)")
	}
}

// TestRejectOrphanAgentSecrets_HandlesNilGracefully は防御的に nil 入力を捌けることを確認。
func TestRejectOrphanAgentSecrets_HandlesNilGracefully(t *testing.T) {
	if got := rejectOrphanAgentSecrets("", nil); got != nil {
		t.Errorf("rejectOrphanAgentSecrets(\"\", nil) = %v, want nil", got)
	}
	if got := rejectOrphanAgentSecrets("alpha", nil); got != nil {
		t.Errorf("rejectOrphanAgentSecrets(\"alpha\", nil) = %v, want nil", got)
	}
	cfg := &AppConfig{}
	if got := rejectOrphanAgentSecrets("alpha", cfg); got != nil {
		t.Errorf("empty cfg should yield no orphans, got: %v", got)
	}
}
