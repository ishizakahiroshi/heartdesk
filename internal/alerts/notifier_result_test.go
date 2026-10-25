package alerts

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

type resultNotifier struct {
	result DeliveryResult
	calls  int
}

func (*resultNotifier) Prepare(*config.AppConfig) {}
func (n *resultNotifier) Notify(string, string) DeliveryResult {
	n.calls++
	return n.result
}

func useResultNotifiers(t *testing.T, ns ...Notifier) {
	t.Helper()
	notifiersMu.Lock()
	saved := notifiers
	notifiers = append([]Notifier(nil), ns...)
	notifiersMu.Unlock()
	t.Cleanup(func() {
		notifiersMu.Lock()
		notifiers = saved
		notifiersMu.Unlock()
	})
}

func TestSendAlertDeliveryResultTruthTable(t *testing.T) {
	captureLog(t)
	states := []DeliveryResult{{}, {Attempted: true}, {Attempted: true, Delivered: true}}
	for mailState := range states {
		for extensionState := range states {
			t.Run(string(rune('A'+mailState))+string(rune('A'+extensionState)), func(t *testing.T) {
				n := &resultNotifier{result: states[extensionState]}
				useResultNotifiers(t, n)
				rules := AlertRules{}
				if mailState > 0 {
					rules.SMTP = unreachableSMTP()
					rules.Recipients = []Recipient{{Email: "ops@example.com"}}
				}
				mailCalls := stubMail(t, func(string) error {
					if mailState == 1 {
						return errors.New("synthetic mail failure")
					}
					return nil
				})
				want := (mailState == 0 && extensionState == 0) || mailState == 2 || extensionState == 2
				if got := sendAlert(rules, "memory_high", "synthetic alert"); got != want {
					t.Fatalf("mail=%+v extension=%+v got=%v want=%v", states[mailState], states[extensionState], got, want)
				}
				if n.calls != 1 {
					t.Fatalf("extension called %d times, want 1", n.calls)
				}
				wantMailCalls := 0
				if mailState > 0 {
					wantMailCalls = 1
				}
				if len(*mailCalls) != wantMailCalls {
					t.Fatalf("mail calls=%d want=%d", len(*mailCalls), wantMailCalls)
				}
			})
		}
	}
}

func TestSendAlertMultipleNotifiersRemainIndependent(t *testing.T) {
	captureLog(t)
	a := &resultNotifier{result: DeliveryResult{Attempted: true}}
	b := &resultNotifier{result: DeliveryResult{Attempted: true, Delivered: true}}
	c := &resultNotifier{}
	useResultNotifiers(t, a, b, c)
	if !sendAlert(AlertRules{}, "memory_high", "synthetic alert") {
		t.Fatal("a later successful notifier did not count as delivered")
	}
	for _, n := range []*resultNotifier{a, b, c} {
		if n.calls != 1 {
			t.Fatalf("each notifier must run once, got %d", n.calls)
		}
	}
}

func TestSendAlertIgnoresDeliveryWithoutAttempt(t *testing.T) {
	captureLog(t)
	n := &resultNotifier{result: DeliveryResult{Delivered: true}}
	useResultNotifiers(t, n)
	stubMail(t, func(string) error { return errors.New("synthetic mail failure") })
	rules := AlertRules{SMTP: unreachableSMTP(), Recipients: []Recipient{{Email: "ops@example.com"}}}
	if sendAlert(rules, "memory_high", "synthetic alert") {
		t.Fatal("a notifier with Attempted=false masked a real mail failure")
	}
}

func TestSendAlertMailResultDistinguishesNoAttemptAndPartialSuccess(t *testing.T) {
	captureLog(t)
	stubMail(t, func(to string) error {
		if to == "a@example.com" {
			return errors.New("synthetic mail failure")
		}
		return nil
	})
	for _, rules := range []AlertRules{
		{},
		{SMTP: unreachableSMTP()},
		{SMTP: unreachableSMTP(), Recipients: []Recipient{{Email: "ops@example.com", Enabled: boolPtr(false)}}},
		{SMTP: unreachableSMTP(), Recipients: []Recipient{{Email: " "}}},
		{SMTP: unreachableSMTP(), Recipients: []Recipient{{Email: "ops@example.com", Rules: map[string]bool{"memory_high": false}}}},
	} {
		if got := sendAlertMailResult(rules, "memory_high", "m"); got != (DeliveryResult{}) {
			t.Fatalf("no eligible mail delivery must return the zero result, got %+v", got)
		}
	}
	rules := AlertRules{SMTP: unreachableSMTP(), Recipients: []Recipient{{Email: "a@example.com"}, {Email: "b@example.com"}}}
	if got := sendAlertMailResult(rules, "memory_high", "m"); got != (DeliveryResult{Attempted: true, Delivered: true}) {
		t.Fatalf("partial mail delivery result=%+v", got)
	}
}

func TestResourceAlertFailedNotifierRetriesWithoutRestartingSustain(t *testing.T) {
	captureLog(t)
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	useRealSender(t, now)
	n := &resultNotifier{result: DeliveryResult{Attempted: true}}
	useResultNotifiers(t, n)
	rules := AlertRules{Rules: map[string]AlertRule{"memory_high": {Enabled: true, Threshold: 90, SustainSec: 60, CooldownSec: 3600}}}
	path := filepath.Join(t.TempDir(), "resource_log.csv")
	appendFile(t, path, ResourceLogColumns+"\n2026-10-21 12:00:00,10,95,10\n")
	state := newAlertState()
	evaluateResourceAlerts(path, rules, state)
	first := state.FirstBreach["memory_high"]
	if first.IsZero() {
		t.Fatal("sustain did not start")
	}
	nowFn = fixedNow(now.Add(2 * time.Minute))
	appendFile(t, path, "2026-10-21 12:02:00,10,95,10\n")
	if got := evaluateResourceAlerts(path, rules, state); len(got) != 0 || state.Active["memory_high"] {
		t.Fatalf("failed notifier marked alert active: %v", got)
	}
	if _, ok := state.LastAlertTime["memory_high"]; ok {
		t.Fatal("failed notifier started cooldown")
	}
	if !state.FirstBreach["memory_high"].Equal(first) {
		t.Fatal("failed notifier reset sustain progress")
	}
	n.result.Delivered = true
	nowFn = fixedNow(now.Add(3 * time.Minute))
	appendFile(t, path, "2026-10-21 12:03:00,10,95,10\n")
	if got := evaluateResourceAlerts(path, rules, state); len(got) != 1 || !state.Active["memory_high"] {
		t.Fatalf("retry did not mark delivery: %v", got)
	}
}

func TestServiceRecoveryFailedNotifierRemainsActiveUntilDelivered(t *testing.T) {
	captureLog(t)
	useRealSender(t, time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC))
	serviceState := "failed"
	origService := serviceStatusFn
	serviceStatusFn = func(s string) string {
		if s == "nginx" {
			return serviceState
		}
		return "active"
	}
	t.Cleanup(func() { serviceStatusFn = origService })
	n := &resultNotifier{result: DeliveryResult{Attempted: true, Delivered: true}}
	useResultNotifiers(t, n)
	rules := AlertRules{Rules: map[string]AlertRule{"service_down_nginx": {Enabled: true, CooldownSec: 3600, NotifyRecovery: true}}}
	state := newAlertState()
	if got := evaluateServiceAlerts(rules, state); len(got) != 1 || !state.Active["service_down_nginx"] {
		t.Fatal("initial service-down notification did not activate")
	}
	serviceState = "active"
	n.result.Delivered = false
	if got := evaluateServiceAlerts(rules, state); len(got) != 0 || !state.Active["service_down_nginx"] {
		t.Fatal("failed recovery must leave the alert active")
	}
	n.result.Delivered = true
	if got := evaluateServiceAlerts(rules, state); len(got) != 1 || state.Active["service_down_nginx"] {
		t.Fatal("successful recovery retry must clear the active alert")
	}
}
