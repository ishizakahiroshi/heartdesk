package monitor

import (
	"bytes"
	"encoding/json"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// ncFileAccessRuleDefaults は internal/alerts の ncFADefaults と同じ既定値（画面に出す初期値）。
var ncFileAccessRuleDefaults = map[string]struct {
	threshold float64
	cooldown  int
}{
	"nc_mass_access":       {300, 10800},
	"nc_folder_sweep":      {50, 10800},
	"nc_new_ip_access":     {50, 10800},
	"nc_off_hours_access":  {100, 86400},
	"nc_public_link_burst": {50, 10800},
	"nc_service_new_ip":    {1, 86400},
	"nc_service_volume":    {0, 10800},
	// 連携アプリ自身のHTTPエラー（internal/alerts/integration_http_error.go）。件数のルールで、既定は無効。
	"integration_http_error": {1, 10800},
}

func TestAlertRuleDefsIncludesNCFileAccessRules(t *testing.T) {
	inOrder := map[string]bool{}
	for _, id := range AlertRuleDefOrder {
		inOrder[id] = true
	}
	for id, want := range ncFileAccessRuleDefaults {
		def, ok := AlertRuleDefs[id]
		if !ok {
			t.Fatalf("AlertRuleDefs[%q] not found", id)
		}
		if !inOrder[id] {
			t.Fatalf("AlertRuleDefOrder does not contain %q", id)
		}
		if !def.HasThreshold || def.HasRecovery || def.HasSustain {
			t.Fatalf("%s: want HasThreshold only, got %+v", id, def)
		}
		if def.ThresholdMax <= 100 {
			t.Fatalf("%s: count rule needs ThresholdMax > 100, got %v", id, def.ThresholdMax)
		}
		if def.DefaultThreshold != want.threshold || def.DefaultCooldownSec != want.cooldown {
			t.Fatalf("%s: defaults = (%v, %d), want (%v, %d)", id, def.DefaultThreshold, def.DefaultCooldownSec, want.threshold, want.cooldown)
		}
		if def.DefaultCooldownSec > 86400 {
			t.Fatalf("%s: default cooldown must fit the screen limit 86400", id)
		}
	}
}

// fullRulesPayload は画面が送るのと同じく、全ルールぶんの値を組み立てる
// （件数のルールは画面の初期値と同じ既定値、それ以外は 0）。
func fullRulesPayload() map[string]map[string]string {
	p := map[string]map[string]string{}
	for _, id := range AlertRuleDefOrder {
		th := "0"
		if d, ok := ncFileAccessRuleDefaults[id]; ok {
			th = formatFloat(d.threshold)
		}
		p[id] = map[string]string{"threshold": th, "recovery": "0", "sustain_sec": "0", "cooldown_sec": "0"}
	}
	return p
}

func TestSaveAlertRulesAcceptsNCCountThresholds(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.AppConfig{}
	cfg.Alerts.RulesFile = filepath.Join(dir, "alert_rules.json")

	p := fullRulesPayload()
	p["nc_mass_access"] = map[string]string{"threshold": "300", "cooldown_sec": "10800", "enabled": "1"}
	if ok, errs := SaveAlertRules(cfg, p); !ok {
		t.Fatalf("threshold 300 for nc_mass_access should be accepted, errors=%v", errs)
	}
	raw, err := os.ReadFile(cfg.Alerts.RulesFile)
	if err != nil {
		t.Fatal(err)
	}
	var f AlertRulesFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if r := f.Rules["nc_mass_access"]; r.Threshold != 300 || r.CooldownSec != 10800 || !r.Enabled {
		t.Fatalf("saved nc_mass_access = %+v", r)
	}

	p = fullRulesPayload()
	p["nc_mass_access"]["threshold"] = "100001"
	if ok, _ := SaveAlertRules(cfg, p); ok {
		t.Fatalf("threshold above ThresholdMax must be rejected")
	}

	// 既存の % ルールの上限 100 は変わらない。
	p = fullRulesPayload()
	p["memory_high"]["threshold"] = "101"
	if ok, _ := SaveAlertRules(cfg, p); ok {
		t.Fatalf("memory_high threshold above 100 must still be rejected")
	}
}

// renderNotificationRulesCard は cards.html の通知設定カードの define だけを取り出して描画する。
func renderNotificationRulesCard(t *testing.T, cfg *config.AppConfig) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "web", "templates", "cards.html"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	const head = `{{define "card-sec-notification-rules"}}`
	start := strings.Index(src, head)
	if start < 0 {
		t.Fatalf("define block not found in cards.html")
	}
	end := strings.Index(src[start:], "\n{{end}}\n")
	if end < 0 {
		t.Fatalf("end of define block not found")
	}
	block := src[start : start+end+len("\n{{end}}")]
	tmpl, err := template.New("cards").Funcs(template.FuncMap{
		"cardLabel": func(id string) string { return id },
	}).Parse(block)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "card-sec-notification-rules", GetNotificationRulesCardData(cfg)); err != nil {
		t.Fatalf("execute: %v", err)
	}
	return buf.String()
}

func inputValue(t *testing.T, html, ruleID, field string) (max, value string) {
	t.Helper()
	re := regexp.MustCompile(`(?:max="(\d+)" step="1"\s+)?name="alert_rules\[` + regexp.QuoteMeta(ruleID) + `\]\[` + field + `\]"\s+value="([^"]*)"`)
	m := re.FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("input %s[%s] not found", ruleID, field)
	}
	return m[1], m[2]
}

func TestNotificationRulesCardShowsNCDefaultsAndLimits(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.AppConfig{}
	cfg.Alerts.RulesFile = filepath.Join(dir, "alert_rules.json")

	// 未保存: 既定値が出る。件数ルールは上限 100000、既存の % ルールは 100 と 0 のまま。
	html := renderNotificationRulesCard(t, cfg)
	if max, v := inputValue(t, html, "nc_mass_access", "threshold"); max != "100000" || v != "300" {
		t.Fatalf("nc_mass_access threshold: max=%q value=%q", max, v)
	}
	if _, v := inputValue(t, html, "nc_mass_access", "cooldown_sec"); v != "10800" {
		t.Fatalf("nc_mass_access cooldown: value=%q", v)
	}
	if _, v := inputValue(t, html, "nc_service_volume", "threshold"); v != "0" {
		t.Fatalf("nc_service_volume threshold should default to 0 (disabled): %q", v)
	}
	if max, v := inputValue(t, html, "memory_high", "threshold"); max != "100" || v != "0" {
		t.Fatalf("memory_high threshold unchanged: max=%q value=%q", max, v)
	}
	if _, v := inputValue(t, html, "memory_high", "cooldown_sec"); v != "0" {
		t.Fatalf("memory_high cooldown unchanged: value=%q", v)
	}

	// 保存済み: 保存した値が出る。
	saved := AlertRulesFile{Rules: map[string]AlertRuleConfig{
		"nc_mass_access": {Threshold: 500, CooldownSec: 600, Enabled: true},
	}}
	b, _ := json.Marshal(saved)
	if err := os.WriteFile(cfg.Alerts.RulesFile, b, 0o644); err != nil {
		t.Fatal(err)
	}
	html = renderNotificationRulesCard(t, cfg)
	if _, v := inputValue(t, html, "nc_mass_access", "threshold"); v != "500" {
		t.Fatalf("saved threshold should be shown: %q", v)
	}
	if _, v := inputValue(t, html, "nc_mass_access", "cooldown_sec"); v != "600" {
		t.Fatalf("saved cooldown should be shown: %q", v)
	}
}
