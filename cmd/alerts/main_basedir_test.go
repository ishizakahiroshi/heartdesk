package main

import (
	"path/filepath"
	"testing"
)

func TestAlertPaths_BaseDir(t *testing.T) {
	t.Setenv("HEARTDESK_CONFIG_DIR", "")

	cases := []struct {
		name string
		fn   func() string
		rel  string
	}{
		{"resourceLogPath", resourceLogPath, "data/csv/resource_log.csv"},
		{"scoreLogPath", scoreLogPath, "data/csv/threat_score.csv"},
		{"alertRulesPath", alertRulesPath, "data/json/alert_rules.json"},
		{"lastCheckPath", lastCheckPath, "data/json/alert_check_last.csv"},
		{"lockoutLogPath", lockoutLogPath, "data/nc_extract/lockout_events.jsonl"},
		{"sshIPListPath", sshIPListPath, "config/managed_ips.toml"},
	}

	t.Run("BASE_DIR 未設定は従来の /var/lib/heartdesk", func(t *testing.T) {
		t.Setenv("HEARTDESK_BASE_DIR", "")
		for _, c := range cases {
			want := filepath.Join("/var/lib/heartdesk", filepath.FromSlash(c.rel))
			if got := c.fn(); got != want {
				t.Errorf("%s: got %q, want %q", c.name, got, want)
			}
		}
	})

	t.Run("BASE_DIR 設定ならその下", func(t *testing.T) {
		base := t.TempDir()
		t.Setenv("HEARTDESK_BASE_DIR", base)
		for _, c := range cases {
			want := filepath.Join(base, filepath.FromSlash(c.rel))
			if got := c.fn(); got != want {
				t.Errorf("%s: got %q, want %q", c.name, got, want)
			}
		}
	})

	t.Run("sshIPListPath は HEARTDESK_CONFIG_DIR を優先", func(t *testing.T) {
		cfg := t.TempDir()
		t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
		t.Setenv("HEARTDESK_CONFIG_DIR", cfg)
		if got, want := sshIPListPath(), filepath.Join(cfg, "managed_ips.toml"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}
