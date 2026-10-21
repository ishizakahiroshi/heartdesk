package daemon

import (
	"path/filepath"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// heartdesk 自身の置き場所の既定が HEARTDESK_BASE_DIR に従うことを確かめる。
func TestDaemonDefaultPathsFollowBaseDir(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)

	cases := map[string][2]string{
		"extractBaseDir":        {extractBaseDir(), filepath.Join(base, "data", "nc_extract")},
		"extractStateFile":      {extractStateFile(), filepath.Join(base, "data", "nc_extract", "extract_state.json")},
		"extractLoginFile":      {extractLoginFile(), filepath.Join(base, "data", "nc_extract", "login_events.jsonl")},
		"extractContextFile":    {extractContextFile(), filepath.Join(base, "data", "nc_extract", "login_context.jsonl")},
		"extractSecurityFile":   {extractSecurityFile(), filepath.Join(base, "data", "nc_extract", "security_events.jsonl")},
		"extractLockoutFile":    {extractLockoutFile(), filepath.Join(base, "data", "nc_extract", "lockout_events.jsonl")},
		"extractHeartbeatFile":  {extractHeartbeatFile(), filepath.Join(base, "data", "nc_extract", "extract_last.csv")},
		"extractNC4xxDir":       {extractNC4xxDir(), filepath.Join(base, "data", "json", "nc4xx")},
		"defaultCollectLogPath": {defaultCollectLogPath(), filepath.Join(base, "data", "logs", "collect_resources.log")},
		"defaultR2Metrics":      {defaultR2MetricsOutputPath(), filepath.Join(base, "data", "json", "r2_metrics.json")},
		"defaultGeoIPDBLogPath": {defaultGeoIPDBLogPath(), filepath.Join(base, "data", "logs", "update-geoip-db.log")},
		"scoreLoginEventsPath":  {resolveScorePaths(nil).LoginEventsPath, filepath.Join(base, "data", "nc_extract", "login_events.jsonl")},
	}
	for name, c := range cases {
		if c[0] != c[1] {
			t.Errorf("%s = %q, want %q", name, c[0], c[1])
		}
	}
}

// BASE_DIR 未設定のときは従来の /var/lib/heartdesk 配下の絶対パスになる。
func TestDaemonDefaultPathsWithoutBaseDir(t *testing.T) {
	t.Setenv("HEARTDESK_BASE_DIR", "")
	root := "/var/lib/heartdesk"

	cases := map[string][2]string{
		"extractBaseDir":        {extractBaseDir(), filepath.Join(root, "data/nc_extract")},
		"extractNC4xxDir":       {extractNC4xxDir(), filepath.Join(root, "data/json/nc4xx")},
		"defaultCollectLogPath": {defaultCollectLogPath(), filepath.Join(root, "data/logs/collect_resources.log")},
		"defaultR2Metrics":      {defaultR2MetricsOutputPath(), filepath.Join(root, "data/json/r2_metrics.json")},
		"defaultGeoIPDBLogPath": {defaultGeoIPDBLogPath(), filepath.Join(root, "data/logs/update-geoip-db.log")},
	}
	for name, c := range cases {
		if c[0] != c[1] {
			t.Errorf("%s = %q, want %q", name, c[0], c[1])
		}
	}
}

// 設定ファイル側の明示値は既定より優先され続ける。
func TestScorePathsConfigStillOverridesLoginEventsDefault(t *testing.T) {
	t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
	p := resolveScorePaths(&config.SchedulerConfig{LoginEventsPath: "/custom/login_events.jsonl"})
	if p.LoginEventsPath != "/custom/login_events.jsonl" {
		t.Fatalf("LoginEventsPath = %q, want config override", p.LoginEventsPath)
	}
}
