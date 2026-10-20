package monitor

// 通知ルール保存の境界条件（古い画面からの保存・件数しきい値の検証）の回帰テスト。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

func readSavedRules(t *testing.T, cfg *config.AppConfig) AlertRulesFile {
	t.Helper()
	raw, err := os.ReadFile(cfg.Alerts.RulesFile)
	if err != nil {
		t.Fatal(err)
	}
	var f AlertRulesFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// 更新前に開いたままの画面（新しい 7 本の項目が無いフォーム）から保存しても失敗せず、
// 新しい 7 本は保存済みの値（無ければ既定値・無効）のまま残る。
func TestSaveAlertRules_OldFormWithoutNewRules(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.AppConfig{}
	cfg.Alerts.RulesFile = filepath.Join(dir, "alert_rules.json")
	saved := AlertRulesFile{Rules: map[string]AlertRuleConfig{
		"nc_mass_access": {Threshold: 500, CooldownSec: 600, Enabled: true},
	}}
	b, _ := json.Marshal(saved)
	if err := os.WriteFile(cfg.Alerts.RulesFile, b, 0o644); err != nil {
		t.Fatal(err)
	}

	p := fullRulesPayload()
	for id := range ncFileAccessRuleDefaults {
		delete(p, id) // 古い画面はこの 7 本の項目を送らない
	}
	p["memory_high"] = map[string]string{"threshold": "85", "recovery": "80", "sustain_sec": "60", "cooldown_sec": "300", "enabled": "1"}
	if ok, errs := SaveAlertRules(cfg, p); !ok {
		t.Fatalf("saving from the old form should succeed, errors=%v", errs)
	}
	f := readSavedRules(t, cfg)
	if r := f.Rules["memory_high"]; r.Threshold != 85 || !r.Enabled {
		t.Fatalf("existing rule should be saved, got %+v", r)
	}
	if r := f.Rules["nc_mass_access"]; r.Threshold != 500 || r.CooldownSec != 600 || !r.Enabled {
		t.Fatalf("saved value of a rule missing from the form should be kept, got %+v", r)
	}
	if r := f.Rules["nc_folder_sweep"]; r.Enabled || r.Threshold != 50 || r.CooldownSec != 10800 {
		t.Fatalf("never-saved rule missing from the form should be default and disabled, got %+v", r)
	}
}

// nc_folder_sweep の上限はフォルダ集合の上限（2,000）。件数のしきい値は 1 以上の整数
// （nc_service_volume は 0＝判定しない も可）。既存ルールの検証は変えない。
func TestSaveAlertRules_CountThresholdValidation(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.AppConfig{}
	cfg.Alerts.RulesFile = filepath.Join(dir, "alert_rules.json")

	cases := []struct {
		rule, threshold string
		wantOK          bool
	}{
		{"nc_folder_sweep", "2000", true},
		{"nc_folder_sweep", "2001", false},
		{"nc_mass_access", "300", true},
		{"nc_mass_access", "300.5", false},
		{"nc_mass_access", "0", false},
		{"nc_service_volume", "0", true},
		{"nc_service_volume", "1.5", false},
		{"memory_high", "50.5", true}, // 既存の % ルールは小数も従来どおり受ける
	}
	for _, tc := range cases {
		p := fullRulesPayload()
		for id, d := range ncFileAccessRuleDefaults {
			th := d.threshold
			if th < 1 && id != "nc_service_volume" {
				th = 1
			}
			p[id] = map[string]string{"threshold": formatFloat(th), "cooldown_sec": "10800"}
		}
		p[tc.rule]["threshold"] = tc.threshold
		ok, errs := SaveAlertRules(cfg, p)
		if ok != tc.wantOK {
			t.Errorf("%s threshold %s: ok=%v want %v (errors=%v)", tc.rule, tc.threshold, ok, tc.wantOK, errs)
		}
	}

	html := renderNotificationRulesCard(t, cfg)
	re := func(id string) *regexp.Regexp {
		return regexp.MustCompile(`min="(\d+)" max="(\d+)" step="1"\s+name="alert_rules\[` + regexp.QuoteMeta(id) + `\]\[threshold\]"`)
	}
	for id, want := range map[string][2]string{
		"nc_folder_sweep":   {"1", "2000"},
		"nc_mass_access":    {"1", "100000"},
		"nc_service_volume": {"0", "100000"},
		"memory_high":       {"0", "100"},
	} {
		m := re(id).FindStringSubmatch(html)
		if m == nil || m[1] != want[0] || m[2] != want[1] {
			t.Errorf("%s threshold input min/max = %v, want %v", id, m, want)
		}
	}
}

func formatFloat(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}
