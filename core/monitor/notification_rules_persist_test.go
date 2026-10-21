package monitor

// 通知設定の保存が、画面で扱わない設定（smtp・account_lockout など）を消さないこと、
// および画面の「発報中」がスケジューラの state ファイルを読むことの回帰テスト。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

const persistFixture = `{
  "rules": {
    "memory_high": {"threshold": 90, "cooldown_sec": 300, "enabled": true},
    "account_lockout": {"cooldown_sec": 600, "enabled": true, "notify_recovery": true}
  },
  "recipients": [
    {"id": "1", "name": "Ops", "email": "ops@example.com", "enabled": true}
  ],
  "smtp": {"smtp_host": "smtp.example.com", "smtp_port": "587", "smtp_user": "user", "smtp_pass": "secret-pass", "smtp_from": "alerts@example.com"}
}`

func newPersistConfig(t *testing.T) *config.AppConfig {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", dir)
	cfg := &config.AppConfig{}
	cfg.Alerts.RulesFile = filepath.Join(dir, "alert_rules.json")
	if err := os.WriteFile(cfg.Alerts.RulesFile, []byte(persistFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func readRawRules(t *testing.T, cfg *config.AppConfig) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(cfg.Alerts.RulesFile)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func assertSMTPAndLockoutKept(t *testing.T, cfg *config.AppConfig) {
	t.Helper()
	m := readRawRules(t, cfg)
	var smtp map[string]string
	if err := json.Unmarshal(m["smtp"], &smtp); err != nil || smtp["smtp_host"] != "smtp.example.com" || smtp["smtp_pass"] != "secret-pass" {
		t.Fatalf("smtp settings must survive a save from the screen, got %s (err=%v)", m["smtp"], err)
	}
	var rules map[string]AlertRuleConfig
	if err := json.Unmarshal(m["rules"], &rules); err != nil {
		t.Fatal(err)
	}
	lock, ok := rules["account_lockout"]
	if !ok || !lock.Enabled || lock.CooldownSec != 600 || !lock.NotifyRecovery {
		t.Fatalf("a rule the screen does not know (account_lockout) must survive a save, got %+v ok=%v", lock, ok)
	}
}

func TestSaveAlertRules_KeepsSMTPAndUnknownRules(t *testing.T) {
	cfg := newPersistConfig(t)
	p := fullRulesPayload()
	p["memory_high"] = map[string]string{"threshold": "85", "recovery": "80", "sustain_sec": "60", "cooldown_sec": "300", "enabled": "1"}
	if ok, errs := SaveAlertRules(cfg, p); !ok {
		t.Fatalf("save failed: %v", errs)
	}
	assertSMTPAndLockoutKept(t, cfg)
	f := readSavedRules(t, cfg)
	if r := f.Rules["memory_high"]; r.Threshold != 85 || !r.Enabled {
		t.Fatalf("the screen's own rule should still be updated, got %+v", r)
	}
	if len(f.Recipients) != 1 || f.Recipients[0].Email != "ops@example.com" {
		t.Fatalf("recipients must be kept, got %+v", f.Recipients)
	}
}

func TestSaveAlertRecipients_KeepsSMTPAndUnknownRules(t *testing.T) {
	cfg := newPersistConfig(t)
	recipients := []AlertRecipient{{Name: "Dev", Email: "dev@example.com", Enabled: true}}
	if ok, errs := SaveAlertRecipients(cfg, recipients); !ok {
		t.Fatalf("save failed: %v", errs)
	}
	assertSMTPAndLockoutKept(t, cfg)
	f := readSavedRules(t, cfg)
	if len(f.Recipients) != 1 || f.Recipients[0].Email != "dev@example.com" {
		t.Fatalf("recipients should be replaced, got %+v", f.Recipients)
	}
	if r := f.Rules["memory_high"]; r.Threshold != 90 || !r.Enabled {
		t.Fatalf("rules must be kept when saving recipients, got %+v", r)
	}
}

// smtp_pass（平文）を含むので、保存後は所有者だけが読み書きできる。既存の 0644 のファイルも締め直す。
func TestSaveAlertRules_FileModeIs0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX のファイル権限は Windows では検証できない")
	}
	cfg := newPersistConfig(t) // 0644 で作られる
	if ok, errs := SaveAlertRules(cfg, fullRulesPayload()); !ok {
		t.Fatalf("save failed: %v", errs)
	}
	fi, err := os.Stat(cfg.Alerts.RulesFile)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
}

// 壊れた既存ファイルを黙って空から作り直さない（smtp を失うため）。
func TestSaveAlertRules_RefusesToOverwriteUnparsableFile(t *testing.T) {
	cfg := newPersistConfig(t)
	if err := os.WriteFile(cfg.Alerts.RulesFile, []byte(`{"rules": {broken`), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, _ := SaveAlertRules(cfg, fullRulesPayload()); ok {
		t.Fatal("saving over an unparsable file must fail instead of discarding it")
	}
	raw, _ := os.ReadFile(cfg.Alerts.RulesFile)
	if string(raw) != `{"rules": {broken` {
		t.Fatalf("the original file must be left untouched, got %q", raw)
	}
}

// 画面の「発報中」は、スケジューラ（internal/alerts）が書く state ファイルを読む。
func TestRuntimeReadsSchedulerStateFile(t *testing.T) {
	cfg := newPersistConfig(t)
	// 設定（[alerts].state_file）が無いときの既定は BASE_DIR 基準の data/json/alert_state.json。
	statePath := filepath.Join(os.Getenv("HEARTDESK_BASE_DIR"), "data", "json", "alert_state.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		t.Fatal(err)
	}
	state := `{"active": {"memory_high": true, "disk_high": false}, "last_alert_time": {}, "first_breach": {}, "offsets": {}, "pending_nc_users": {}}`
	if err := os.WriteFile(statePath, []byte(state), 0o644); err != nil {
		t.Fatal(err)
	}

	rt := GetNotificationRulesAPIData(cfg).Runtime
	if m := rt["memory_high"]; !m.Active || !m.Evaluated {
		t.Fatalf("memory_high should be active (from the scheduler's state), got %+v", m)
	}
	if d := rt["disk_high"]; !d.Evaluated {
		t.Fatalf("disk_high is recorded in the state and should count as evaluated, got %+v", d)
	}
}

func TestRuntimeStateFileConfiguredPathAndLegacyFormat(t *testing.T) {
	cfg := newPersistConfig(t)
	dir := filepath.Dir(cfg.Alerts.RulesFile)
	cfg.Alerts.StateFile = filepath.Join(dir, "custom_state.json")

	// 旧形式（ルール ID をキーにした形）は落とさず空として扱う。
	if err := os.WriteFile(cfg.Alerts.StateFile, []byte(`{"memory_high": {"active": true}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if m := loadAlertRuntimeStates(cfg); len(m) != 0 {
		t.Fatalf("legacy-format state should be treated as empty, got %+v", m)
	}
	// 壊れたファイルも同じ。
	if err := os.WriteFile(cfg.Alerts.StateFile, []byte(`{nope`), 0o644); err != nil {
		t.Fatal(err)
	}
	if m := loadAlertRuntimeStates(cfg); len(m) != 0 {
		t.Fatalf("broken state should be treated as empty, got %+v", m)
	}
	// 設定したパスのスケジューラ形式は読める。
	if err := os.WriteFile(cfg.Alerts.StateFile, []byte(`{"active": {"service_down_nginx": true}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if m := loadAlertRuntimeStates(cfg); !m["service_down_nginx"].Active {
		t.Fatalf("scheduler-format state at the configured path should be read, got %+v", m)
	}
}
