package config

import "testing"

func TestIsLocalAgent(t *testing.T) {
	cfg := &AppConfig{Agents: map[string]AgentConfig{
		"alpha-vps-host1": {AgentID: "alpha-vps-host1", IsPrimary: true},
		"alpha-vps-host2": {AgentID: "alpha-vps-host2"},
	}}
	cfg.UI.DefaultAgent = "alpha-vps-host2"

	cases := []struct {
		name    string
		cfg     *AppConfig
		agentID string
		want    bool
	}{
		{"is_primary の agent はローカル", cfg, "alpha-vps-host1", true},
		{"default_agent でも is_primary でなければローカルではない", cfg, "alpha-vps-host2", false},
		{"未登録の agent はローカルではない", cfg, "alpha-vps-unknown", false},
		{"空の ID はローカルではない（呼び出し側が既に空＝ローカルとして扱う）", cfg, "", false},
		{"cfg が nil でも落ちない", nil, "alpha-vps-host1", false},
		{"Agents が nil でも落ちない", &AppConfig{}, "alpha-vps-host1", false},
	}
	for _, c := range cases {
		if got := c.cfg.IsLocalAgent(c.agentID); got != c.want {
			t.Errorf("%s: IsLocalAgent(%q) = %v, want %v", c.name, c.agentID, got, c.want)
		}
	}
}
