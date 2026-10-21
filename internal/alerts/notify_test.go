package alerts

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fixedNow はテスト用の固定時刻。
func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

// withStubs はテスト中だけ nowFn / sender / serviceStatusFn を差し替える。
func withStubs(t *testing.T, now time.Time, status func(string) string) *[]string {
	t.Helper()
	origNow, origSender, origSvc := nowFn, sender, serviceStatusFn
	captured := &[]string{}
	nowFn = fixedNow(now)
	sender = func(_ AlertRules, ruleID, msg string) bool {
		*captured = append(*captured, ruleID+"|"+msg)
		return true
	}
	if status != nil {
		serviceStatusFn = status
	}
	t.Cleanup(func() { nowFn, sender, serviceStatusFn = origNow, origSender, origSvc })
	return captured
}

func TestEvaluateServiceAlerts_DownFiresOnceThenCooldown(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	captured := withStubs(t, now, func(svc string) string {
		if svc == "nginx" {
			return "failed"
		}
		return "active"
	})

	rules := AlertRules{Rules: map[string]AlertRule{
		"service_down_nginx":   {Enabled: true, CooldownSec: 3600},
		"service_down_mariadb": {Enabled: true, CooldownSec: 3600},
	}}
	state := newAlertState()

	got := evaluateServiceAlerts(rules, state)
	if len(got) != 1 {
		t.Fatalf("expected 1 alert (nginx down), got %d: %v", len(got), got)
	}
	if !state.Active["service_down_nginx"] {
		t.Fatalf("nginx active flag should be set")
	}
	if state.Active["service_down_mariadb"] {
		t.Fatalf("mariadb should not be marked active")
	}

	// 2 回目（cooldown 中・まだ down）→ 発報されない。
	nowFn = fixedNow(now.Add(time.Minute))
	got2 := evaluateServiceAlerts(rules, state)
	if len(got2) != 0 {
		t.Fatalf("expected no re-alert during cooldown, got %v", got2)
	}

	if len(*captured) != 1 {
		t.Fatalf("sender should have been called once, got %d: %v", len(*captured), *captured)
	}
}

func TestEvaluateServiceAlerts_EmptyStatusSkips(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	withStubs(t, now, func(string) string { return "" }) // コマンド失敗

	rules := AlertRules{Rules: map[string]AlertRule{
		"service_down_nginx": {Enabled: true, CooldownSec: 3600},
	}}
	state := newAlertState()
	if got := evaluateServiceAlerts(rules, state); len(got) != 0 {
		t.Fatalf("status unknown should not fire, got %v", got)
	}
	if state.Active["service_down_nginx"] {
		t.Fatalf("unknown status must not mark active")
	}
}

func TestEvaluateThreatScore_AboveThresholdFires(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	captured := withStubs(t, now, nil)

	dir := t.TempDir()
	scoreCSV := filepath.Join(dir, "threat_score.csv")
	// 1 行目ヘッダ + データ（>=10 列、record[1]=ip, record[2]=score）。
	rows := "ts,ip,score,c3,c4,c5,c6,c7,c8,c9\n" +
		"2026-05-31,1.1.1.1,150,,,,,,,\n" +
		"2026-05-31,2.2.2.2,50,,,,,,,\n" +
		"2026-05-31,9.9.9.9,999,,,,,,,\n" // 9.9.9.9 は除外 IP
	if err := os.WriteFile(scoreCSV, []byte(rows), 0o644); err != nil {
		t.Fatal(err)
	}
	ipList := filepath.Join(dir, "managed_ips.toml")
	if err := os.WriteFile(ipList, []byte("[[ips]]\nip=\"9.9.9.9\"\ntype=\"wlm\"\nname=\"office\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rules := AlertRules{Rules: map[string]AlertRule{
		"threat_score_critical": {Enabled: true, Threshold: 100, CooldownSec: 3600},
	}}
	state := newAlertState()

	got := evaluateThreatScore(scoreCSV, ipList, rules, state)
	if len(got) != 1 {
		t.Fatalf("expected 1 threat alert, got %d: %v", len(got), got)
	}
	// 除外 IP(9.9.9.9, score 999) は無視され、最大は 1.1.1.1(150)。
	if want := "1.1.1.1"; !contains(got[0], want) {
		t.Fatalf("alert should mention top IP %s, got %q", want, got[0])
	}
	if len(*captured) != 1 {
		t.Fatalf("sender should fire once, got %v", *captured)
	}
}

func TestEvaluateThreatScore_BelowThresholdNoFire(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	withStubs(t, now, nil)

	dir := t.TempDir()
	scoreCSV := filepath.Join(dir, "threat_score.csv")
	rows := "ts,ip,score,c3,c4,c5,c6,c7,c8,c9\n2026-05-31,1.1.1.1,40,,,,,,,\n"
	if err := os.WriteFile(scoreCSV, []byte(rows), 0o644); err != nil {
		t.Fatal(err)
	}
	rules := AlertRules{Rules: map[string]AlertRule{
		"threat_score_critical": {Enabled: true, Threshold: 100, CooldownSec: 3600},
	}}
	state := newAlertState()
	if got := evaluateThreatScore(scoreCSV, filepath.Join(dir, "nope.toml"), rules, state); len(got) != 0 {
		t.Fatalf("below threshold should not fire, got %v", got)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
