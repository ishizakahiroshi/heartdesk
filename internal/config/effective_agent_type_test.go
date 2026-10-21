package config

import "testing"

func TestEffectiveAgentType(t *testing.T) {
	cfg := &AppConfig{Agents: map[string]AgentConfig{
		"alpha-a": {AgentType: "rental"},
		"alpha-b": {AgentType: " VPS "},
		"alpha-c": {AgentType: ""},
		"alpha-d": {AgentType: "weird"},
	}}
	cases := []struct {
		name     string
		cfg      *AppConfig
		id       string
		reported string
		want     string
	}{
		{"config wins over report", cfg, "alpha-a", "vps", "rental"},
		{"config is normalized", cfg, "alpha-b", "rental", "vps"},
		{"report used when config empty", cfg, "alpha-c", " Rental", "rental"},
		{"unknown config falls back to report", cfg, "alpha-d", "vps", "vps"},
		{"unknown agent uses report", cfg, "alpha-z", "rental", "rental"},
		{"unknown report value ignored", cfg, "alpha-c", "bogus", ""},
		{"no report, no config type", cfg, "alpha-c", "", ""},
		{"nil config uses report", nil, "alpha-a", "vps", "vps"},
	}
	for _, c := range cases {
		if got := c.cfg.EffectiveAgentType(c.id, c.reported); got != c.want {
			t.Errorf("%s: EffectiveAgentType(%q, %q) = %q, want %q", c.name, c.id, c.reported, got, c.want)
		}
	}
}
