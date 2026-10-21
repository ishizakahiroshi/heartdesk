package target

import (
	"strings"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// newTestCfg は target.Resolve 用の最小 AppConfig を組み立てる。
func newTestCfg(defaultAgent string, agents map[string]config.AgentConfig) *config.AppConfig {
	cfg := &config.AppConfig{}
	cfg.UI.DefaultAgent = defaultAgent
	cfg.Agents = agents
	return cfg
}

func TestResolve_LocalWhenEmpty(t *testing.T) {
	cfg := newTestCfg("", nil)
	ctx, err := Resolve("", "", cfg)
	if err != nil {
		t.Fatalf("expected no error for empty agentID with empty default, got %v", err)
	}
	if ctx.Mode != ModeLocal || ctx.AgentID != "" {
		t.Fatalf("expected ModeLocal with empty AgentID, got mode=%q agent=%q", ctx.Mode, ctx.AgentID)
	}
}

func TestResolve_UnknownAgent(t *testing.T) {
	cfg := newTestCfg("", map[string]config.AgentConfig{
		"alpha-vps-host1": {AgentID: "alpha-vps-host1", AgentType: "vps"},
	})
	_, err := Resolve("gamma-vps-ghost", "", cfg)
	if err == nil {
		t.Fatalf("expected error for unknown agent")
	}
	if !strings.Contains(err.Error(), "unknown agent") {
		t.Fatalf("expected 'unknown agent' error, got %v", err)
	}
}

func TestResolve_TenantBoundary_Match(t *testing.T) {
	cfg := newTestCfg("", map[string]config.AgentConfig{
		"alpha-vps-host1": {AgentID: "alpha-vps-host1", AgentType: "vps", IsPrimary: true},
	})
	ctx, err := Resolve("alpha-vps-host1", "alpha", cfg)
	if err != nil {
		t.Fatalf("expected no error for matching tenant, got %v", err)
	}
	if ctx.Mode != ModePrimary {
		t.Fatalf("expected ModePrimary, got %q", ctx.Mode)
	}
}

// 回帰テスト: 他テナントの agent_id を渡したらエラーになること。
func TestResolve_TenantBoundary_Mismatch(t *testing.T) {
	cfg := newTestCfg("", map[string]config.AgentConfig{
		"beta-vps-host2": {AgentID: "beta-vps-host2", AgentType: "vps"},
	})
	_, err := Resolve("beta-vps-host2", "alpha", cfg)
	if err == nil {
		t.Fatalf("expected error for cross-tenant agent_id, got nil")
	}
	if !strings.Contains(err.Error(), "tenant mismatch") {
		t.Fatalf("expected 'tenant mismatch' error, got %v", err)
	}
}

// 回帰テスト: tenant プレフィックスのない agent_id は明確に拒否すること。
func TestResolve_TenantBoundary_NoPrefix(t *testing.T) {
	cfg := newTestCfg("", map[string]config.AgentConfig{
		"localagent": {AgentID: "localagent", AgentType: "vps"},
	})
	_, err := Resolve("localagent", "alpha", cfg)
	if err == nil {
		t.Fatalf("expected error for agent_id without tenant prefix")
	}
	if !strings.Contains(err.Error(), "no tenant prefix") {
		t.Fatalf("expected 'no tenant prefix' error, got %v", err)
	}
}

// expectedTenantID が空文字なら境界チェックをスキップする（boot context 用）。
func TestResolve_NoExpectedTenant_SkipsCheck(t *testing.T) {
	cfg := newTestCfg("", map[string]config.AgentConfig{
		"beta-rental-host3": {AgentID: "beta-rental-host3", AgentType: "rental"},
	})
	ctx, err := Resolve("beta-rental-host3", "", cfg)
	if err != nil {
		t.Fatalf("expected no error when expectedTenantID is empty, got %v", err)
	}
	if ctx.Mode != ModeSnapshot {
		t.Fatalf("expected ModeSnapshot for rental, got %q", ctx.Mode)
	}
}

func TestResolve_DefaultAgentFallback(t *testing.T) {
	cfg := newTestCfg("alpha-vps-host1", map[string]config.AgentConfig{
		"alpha-vps-host1": {AgentID: "alpha-vps-host1", AgentType: "vps", IsPrimary: true},
	})
	ctx, err := Resolve("default_agent", "alpha", cfg)
	if err != nil {
		t.Fatalf("expected no error on default_agent fallback, got %v", err)
	}
	if ctx.AgentID != "alpha-vps-host1" || ctx.Mode != ModePrimary {
		t.Fatalf("unexpected ctx: %+v", ctx)
	}
}

// テナント ID は最初のハイフンまで。アンダースコアを含む ID や heartdesk 形式（t101）も同じ規則で読む。
func TestTenantIDFromAgentID(t *testing.T) {
	cases := map[string]string{
		"alpha-vps-host1":        "alpha",
		"t101-vps-host1":         "t101",
		"tenant_b-rental-host-2": "tenant_b",
		"localagent":             "",
		"-vps-host1":             "",
		"":                       "",
	}
	for in, want := range cases {
		if got := tenantIDFromAgentID(in); got != want {
			t.Errorf("tenantIDFromAgentID(%q) = %q, want %q", in, got, want)
		}
	}
}
