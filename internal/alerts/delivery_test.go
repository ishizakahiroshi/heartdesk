package alerts

// メール送信の失敗・宛先の絞り込みに関する回帰テスト。
// 本物の sendAlert / sendMail を使い、接続できないローカルのポートへ送らせて失敗を再現する
// （外部へは送らない）。送信を試みた宛先は、既存のログ文言 "send mail to <addr> failed" で数える。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// unreachableSMTP は誰も待ち受けていないローカルのポートを指す SMTP 設定。接続は拒否される。
func unreachableSMTP() map[string]string {
	return map[string]string{
		"smtp_host": "127.0.0.1",
		"smtp_port": "18105",
		"smtp_user": "user",
		"smtp_pass": "pass",
		"smtp_from": "alerts@example.com",
	}
}

// useRealSender はテスト中だけ nowFn を固定し、sender を本物（sendAlert）にする。
func useRealSender(t *testing.T, now time.Time) {
	t.Helper()
	origNow, origSender := nowFn, sender
	nowFn = fixedNow(now)
	sender = sendAlert
	t.Cleanup(func() { nowFn, sender = origNow, origSender })
}

// 全宛先への送信が失敗したら発報済みにせず、次の評価（新しいサンプルが来たとき）で再試行する。
// 追加の通知経路（Notifier）は、メールの成否と無関係に発報ごとに呼ばれる。
func TestEvaluateResourceAlerts_AllMailFailedIsRetried(t *testing.T) {
	notifiersMu.Lock()
	saved := notifiers
	notifiers = nil
	notifiersMu.Unlock()
	t.Cleanup(func() {
		notifiersMu.Lock()
		notifiers = saved
		notifiersMu.Unlock()
	})
	fn := &fakeNotifier{}
	RegisterNotifier(fn)

	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	useRealSender(t, now)
	logs := captureLog(t)

	rules := AlertRules{
		Rules:      map[string]AlertRule{"memory_high": {Enabled: true, Threshold: 90, CooldownSec: 3600}},
		Recipients: []Recipient{{Name: "Ops", Email: "ops@example.com"}},
		SMTP:       unreachableSMTP(),
	}
	csvPath := filepath.Join(t.TempDir(), "resource_log.csv")
	appendFile(t, csvPath, ResourceLogColumns+"\n2026-10-21 11:59:00,10,95,10\n")
	state := newAlertState()

	// 1 回目: 送信は失敗する。発報済みにならず、クールダウンも始まらない。
	if got := evaluateResourceAlerts(csvPath, rules, state); len(got) != 0 {
		t.Fatalf("an undelivered alert must not be reported as fired, got %v", got)
	}
	if state.Active["memory_high"] {
		t.Fatal("Active must stay false when every mail failed")
	}
	if _, ok := state.LastAlertTime["memory_high"]; ok {
		t.Fatal("LastAlertTime must not be recorded when every mail failed")
	}

	// 2 回目: 新しいサンプルが来た評価で、もう一度送ろうとする（送信は 1 評価につき 1 回だけ）。
	appendFile(t, csvPath, "2026-10-21 12:00:00,10,96,10\n")
	if got := evaluateResourceAlerts(csvPath, rules, state); len(got) != 0 {
		t.Fatalf("still undeliverable, got %v", got)
	}
	if n := strings.Count(logs.String(), "send mail to ops@example.com failed"); n != 2 {
		t.Fatalf("expected one send attempt per evaluation (2 in total), got %d\nlog:\n%s", n, logs.String())
	}
	if state.Active["memory_high"] {
		t.Fatal("Active must still be false")
	}
	if !strings.Contains(logs.String(), "will retry") {
		t.Fatalf("the failure should be visible in the log, got:\n%s", logs.String())
	}
	if len(fn.sent) != 2 {
		t.Fatalf("the extra notifier must be called for every attempt regardless of mail, got %v", fn.sent)
	}
}

// SMTP を使えない（未設定）環境では今までどおり、評価結果は発報済みになる（再試行しても変わらない）。
func TestEvaluateResourceAlerts_NoSMTPStillMarksActive(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	useRealSender(t, now)
	captureLog(t)

	rules := AlertRules{
		Rules:      map[string]AlertRule{"memory_high": {Enabled: true, Threshold: 90, CooldownSec: 3600}},
		Recipients: []Recipient{{Name: "Ops", Email: "ops@example.com"}},
	}
	csvPath := filepath.Join(t.TempDir(), "resource_log.csv")
	appendFile(t, csvPath, ResourceLogColumns+"\n2026-10-21 11:59:00,10,95,10\n")
	state := newAlertState()
	if got := evaluateResourceAlerts(csvPath, rules, state); len(got) != 1 {
		t.Fatalf("expected 1 alert, got %v", got)
	}
	if !state.Active["memory_high"] {
		t.Fatal("Active should be set when mail is simply not configured")
	}
}

// 無効にした宛先には送らない。ルールを指定した宛先はそのルールのときだけ、指定なしは全ルール。
// alert_rules.json に enabled が無い古い宛先は有効のまま。
func TestSendAlertMail_RecipientFiltering(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "alert_rules.json")
	body := `{
  "rules": {"memory_high": {"enabled": true}},
  "recipients": [
    {"name": "legacy", "email": "legacy@example.com"},
    {"name": "off", "email": "off@example.com", "enabled": false},
    {"name": "on", "email": "on@example.com", "enabled": true},
    {"name": "mem-only", "email": "mem-only@example.com", "enabled": true, "rules": {"memory_high": true}},
    {"name": "disk-only", "email": "disk-only@example.com", "enabled": true, "rules": {"disk_high": true}},
    {"name": "blank", "email": "  ", "enabled": true}
  ],
  "smtp": {"smtp_host": "127.0.0.1", "smtp_port": "18105", "smtp_user": "u", "smtp_pass": "p", "smtp_from": "alerts@example.com"}
}`
	if err := os.WriteFile(rulesFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadAlertRules(rulesFile)
	if err != nil {
		t.Fatal(err)
	}
	logs := captureLog(t)

	sendAlertMail(rules, "memory_high", "msg")

	out := logs.String()
	for _, want := range []string{"legacy@example.com", "on@example.com", "mem-only@example.com"} {
		if !strings.Contains(out, "send mail to "+want+" failed") {
			t.Errorf("%s should have been tried for memory_high\nlog:\n%s", want, out)
		}
	}
	for _, not := range []string{"off@example.com", "disk-only@example.com"} {
		if strings.Contains(out, "send mail to "+not) {
			t.Errorf("%s must not receive memory_high mail\nlog:\n%s", not, out)
		}
	}
}
