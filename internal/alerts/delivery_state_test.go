package alerts

// 送信結果（届いた／全員失敗）と状態の更新、宛先の絞り込み、state ファイルの共有パスのテスト。
// mailSendFn を差し替えて送信の成否を決める（実際には送らない）。

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func boolPtr(b bool) *bool { return &b }

func TestMailRecipients(t *testing.T) {
	rules := AlertRules{Recipients: []Recipient{
		{Name: "legacy", Email: "legacy@example.com"},                                        // enabled 無し＝有効
		{Name: "off", Email: "off@example.com", Enabled: boolPtr(false)},                     // 無効
		{Name: "on", Email: "on@example.com", Enabled: boolPtr(true)},                        // 全ルール
		{Name: "mem", Email: "mem@example.com", Rules: map[string]bool{"memory_high": true}}, // メモリだけ
		{Name: "disk", Email: "disk@example.com", Rules: map[string]bool{"disk_high": true}}, // ディスクだけ
		{Name: "memoff", Email: "memoff@example.com", Rules: map[string]bool{"memory_high": false, "disk_high": true}},
		{Name: "off-mem", Email: "offmem@example.com", Enabled: boolPtr(false), Rules: map[string]bool{"memory_high": true}},
		{Name: "blank", Email: " ", Enabled: boolPtr(true)},
	}}
	names := func(rs []Recipient) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.Name)
		}
		return out
	}
	eq := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	if got, want := names(mailRecipients(rules, "memory_high")), []string{"legacy", "on", "mem"}; !eq(got, want) {
		t.Fatalf("memory_high recipients = %v, want %v", got, want)
	}
	if got, want := names(mailRecipients(rules, "disk_high")), []string{"legacy", "on", "disk", "memoff"}; !eq(got, want) {
		t.Fatalf("disk_high recipients = %v, want %v", got, want)
	}
	if got, want := names(mailRecipients(rules, "service_down_nginx")), []string{"legacy", "on"}; !eq(got, want) {
		t.Fatalf("service_down_nginx recipients = %v, want %v", got, want)
	}
}

func stubMail(t *testing.T, fn func(to string) error) *[]string {
	t.Helper()
	orig := mailSendFn
	tried := &[]string{}
	mailSendFn = func(_ map[string]string, to, _, _ string) error {
		*tried = append(*tried, to)
		return fn(to)
	}
	t.Cleanup(func() { mailSendFn = orig })
	return tried
}

// 一部の宛先にでも届いたら発報済み。全員失敗のときだけ未達。試みた宛先が無いときは未達にしない。
func TestSendAlertMail_DeliveredResult(t *testing.T) {
	captureLog(t)
	rules := AlertRules{
		SMTP: unreachableSMTP(),
		Recipients: []Recipient{
			{Name: "a", Email: "a@example.com"},
			{Name: "b", Email: "b@example.com"},
		},
	}

	stubMail(t, func(to string) error {
		if to == "a@example.com" {
			return errors.New("boom")
		}
		return nil
	})
	if !sendAlertMail(rules, "memory_high", "m") {
		t.Fatal("partial success must count as delivered")
	}

	stubMail(t, func(string) error { return errors.New("boom") })
	if sendAlertMail(rules, "memory_high", "m") {
		t.Fatal("failure to every recipient must not count as delivered")
	}

	// 全員が無効なら試みる宛先が無い。再試行しても変わらないので未達にしない（今までの挙動）。
	allOff := rules
	allOff.Recipients = []Recipient{{Name: "a", Email: "a@example.com", Enabled: boolPtr(false)}}
	if !sendAlertMail(allOff, "memory_high", "m") {
		t.Fatal("no recipient to try must not count as a failure")
	}
	// 宛先なし／SMTP 未設定も同じ。
	if !sendAlertMail(AlertRules{SMTP: unreachableSMTP()}, "memory_high", "m") {
		t.Fatal("no recipients configured must not count as a failure")
	}
	if !sendAlertMail(AlertRules{Recipients: rules.Recipients}, "memory_high", "m") {
		t.Fatal("SMTP not configured must not count as a failure")
	}
}

// 失敗後に sustain / cooldown の状態も元へ戻り、送信が通るようになった評価で発報済みになる。
func TestEvaluateResourceAlerts_RetryKeepsSustainProgress(t *testing.T) {
	captureLog(t)
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	useRealSender(t, now)
	fail := true
	stubMail(t, func(string) error {
		if fail {
			return errors.New("smtp down")
		}
		return nil
	})

	rules := AlertRules{
		Rules:      map[string]AlertRule{"memory_high": {Enabled: true, Threshold: 90, SustainSec: 60, CooldownSec: 3600}},
		Recipients: []Recipient{{Name: "Ops", Email: "ops@example.com"}},
		SMTP:       unreachableSMTP(),
	}
	csvPath := filepath.Join(t.TempDir(), "resource_log.csv")
	appendFile(t, csvPath, ResourceLogColumns+"\n")
	state := newAlertState()
	row := func(ts string) { appendFile(t, csvPath, ts+",10,95,10\n") }

	row("t0")
	if got := evaluateResourceAlerts(csvPath, rules, state); len(got) != 0 { // sustain 開始
		t.Fatalf("got %v", got)
	}
	first := state.FirstBreach["memory_high"]
	if first.IsZero() {
		t.Fatal("sustain should have started")
	}

	nowFn = fixedNow(now.Add(2 * time.Minute))
	row("t1")
	if got := evaluateResourceAlerts(csvPath, rules, state); len(got) != 0 { // 送信失敗
		t.Fatalf("got %v", got)
	}
	if state.Active["memory_high"] {
		t.Fatal("must not be active after a failed send")
	}
	if _, ok := state.LastAlertTime["memory_high"]; ok {
		t.Fatal("LastAlertTime must be rolled back")
	}
	if !state.FirstBreach["memory_high"].Equal(first) {
		t.Fatalf("FirstBreach must be restored so the sustain period is not restarted, got %v want %v", state.FirstBreach["memory_high"], first)
	}

	fail = false
	nowFn = fixedNow(now.Add(3 * time.Minute))
	row("t2")
	got := evaluateResourceAlerts(csvPath, rules, state)
	if len(got) != 1 || !state.Active["memory_high"] {
		t.Fatalf("retry should succeed and mark active, got %v active=%v", got, state.Active["memory_high"])
	}
	if _, ok := state.LastAlertTime["memory_high"]; !ok {
		t.Fatal("LastAlertTime should be recorded after a delivered alert")
	}
}

// サービス停止・脅威スコアも同じ。復旧通知が届かなかったときは Active を残して次回再試行する。
func TestEvaluateServiceAlerts_MailFailureRetriesAndRecovery(t *testing.T) {
	captureLog(t)
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	status := "failed"
	useRealSender(t, now)
	origSvc := serviceStatusFn
	serviceStatusFn = func(svc string) string {
		if svc == "nginx" {
			return status
		}
		return "active"
	}
	t.Cleanup(func() { serviceStatusFn = origSvc })
	fail := true
	tried := stubMail(t, func(string) error {
		if fail {
			return errors.New("smtp down")
		}
		return nil
	})

	rules := AlertRules{
		Rules:      map[string]AlertRule{"service_down_nginx": {Enabled: true, CooldownSec: 3600, NotifyRecovery: true}},
		Recipients: []Recipient{{Name: "Ops", Email: "ops@example.com"}},
		SMTP:       unreachableSMTP(),
	}
	state := newAlertState()

	if got := evaluateServiceAlerts(rules, state); len(got) != 0 || state.Active["service_down_nginx"] {
		t.Fatalf("failed send must not mark active, got %v active=%v", got, state.Active["service_down_nginx"])
	}
	if got := evaluateServiceAlerts(rules, state); len(got) != 0 || len(*tried) != 2 {
		t.Fatalf("second evaluation should retry once, got %v tries=%d", got, len(*tried))
	}
	fail = false
	if got := evaluateServiceAlerts(rules, state); len(got) != 1 || !state.Active["service_down_nginx"] {
		t.Fatalf("delivery should now succeed, got %v", got)
	}

	// 復旧: 送信が失敗する間は Active が残り、届いてから落ちる。
	status = "active"
	fail = true
	if got := evaluateServiceAlerts(rules, state); len(got) != 0 || !state.Active["service_down_nginx"] {
		t.Fatalf("undelivered recovery must keep Active, got %v", got)
	}
	fail = false
	if got := evaluateServiceAlerts(rules, state); len(got) != 1 || state.Active["service_down_nginx"] {
		t.Fatalf("recovery should be delivered and cleared, got %v", got)
	}
}

// スケジューラが書く state を、画面側が同じパス・同じ形式で読める。
func TestStatePathAndReadState(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	if got, want := StatePath(nil), filepath.Join(base, "data", "json", "alert_state.json"); got != want {
		t.Fatalf("StatePath(nil) = %q, want %q", got, want)
	}

	path := filepath.Join(base, "state.json")
	st := newAlertState()
	st.Active["memory_high"] = true
	if err := saveAlertState(path, st); err != nil {
		t.Fatal(err)
	}
	if got := ReadState(path); !got.Active["memory_high"] {
		t.Fatalf("ReadState should return what saveAlertState wrote, got %+v", got.Active)
	}

	// 旧形式・壊れたファイル・無いファイルは落とさず空にする。
	old := filepath.Join(base, "old.json")
	if err := os.WriteFile(old, []byte(`{"memory_high":{"active":true}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(base, "broken.json")
	if err := os.WriteFile(broken, []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{old, broken, filepath.Join(base, "none.json")} {
		got := ReadState(p)
		if got == nil || len(got.Active) != 0 {
			t.Fatalf("ReadState(%s) should be empty, got %+v", p, got)
		}
	}
}
