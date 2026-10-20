package alerts

import (
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

type fakeNotifier struct {
	prepared int
	sent     []string
}

func (f *fakeNotifier) Prepare(cfg *config.AppConfig) { f.prepared++ }
func (f *fakeNotifier) Notify(ruleID, message string) { f.sent = append(f.sent, ruleID+"|"+message) }

// 追加の通知経路は、メールの設定が無くても発報ごとに呼ばれる。
func TestRegisterNotifier_CalledIndependentlyOfMail(t *testing.T) {
	notifiersMu.Lock()
	saved := notifiers
	notifiers = nil
	notifiersMu.Unlock()
	t.Cleanup(func() {
		notifiersMu.Lock()
		notifiers = saved
		notifiersMu.Unlock()
	})

	RegisterNotifier(nil) // nil は無視される
	f := &fakeNotifier{}
	RegisterNotifier(f)

	prepareNotifiers(&config.AppConfig{})
	// SMTP も受信者も無い（メールはスキップされる）。
	sendAlert(AlertRules{}, "memory_high", "msg")

	if f.prepared != 1 {
		t.Fatalf("Prepare should be called once, got %d", f.prepared)
	}
	if len(f.sent) != 1 || f.sent[0] != "memory_high|msg" {
		t.Fatalf("Notify should be called once, got %v", f.sent)
	}
}

func TestRuleLabel(t *testing.T) {
	if got := RuleLabel("nc_mass_access"); got != "Nextcloud 大量取得" {
		t.Fatalf("RuleLabel(nc_mass_access) = %q", got)
	}
	if got := RuleLabel("unknown_rule"); got != "unknown_rule" {
		t.Fatalf("unknown rule should return the ID itself, got %q", got)
	}
	// 写しを返すので、書き換えても元の表は変わらない。
	m := NotifyRuleLabels()
	m["memory_high"] = "changed"
	if RuleLabel("memory_high") == "changed" {
		t.Fatal("NotifyRuleLabels must return a copy")
	}
}
