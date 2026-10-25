package alerts

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// This synthetic delivery path never opens a socket or sends a notification.
type eventDeliveryNotifier struct {
	result    DeliveryResult
	calls     int
	resultFor func(string) DeliveryResult
}

func (*eventDeliveryNotifier) Prepare(*config.AppConfig) {}
func (n *eventDeliveryNotifier) Notify(_ string, message string) DeliveryResult {
	n.calls++
	if n.resultFor != nil {
		return n.resultFor(message)
	}
	return n.result
}

func useEventDelivery(t *testing.T, now time.Time, paths ...Notifier) {
	t.Helper()
	useRealSender(t, now)
	captureLog(t)
	notifiersMu.Lock()
	previous := notifiers
	notifiers = append([]Notifier(nil), paths...)
	notifiersMu.Unlock()
	t.Cleanup(func() {
		notifiersMu.Lock()
		notifiers = previous
		notifiersMu.Unlock()
	})
}

func TestEventDeliveryLockoutRetryAndAggregateResult(t *testing.T) {
	for _, mode := range []string{"failed", "one-delivered", "unconfigured"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
			first := &eventDeliveryNotifier{result: DeliveryResult{Attempted: mode != "unconfigured"}}
			second := &eventDeliveryNotifier{result: DeliveryResult{Attempted: mode == "one-delivered", Delivered: mode == "one-delivered"}}
			useEventDelivery(t, now, first, second)
			rules := AlertRules{Rules: map[string]AlertRule{"account_lockout": {Enabled: true, CooldownSec: 3600}}}
			path := filepath.Join(t.TempDir(), "events.jsonl")
			writeFile(t, path, `{"timestamp":"2026-10-21T11:59:00Z","user_id":"sample","username":"sample","ip":"192.0.2.7"}`+"\n")
			state := newAlertState()
			got := evaluateAccountLockout(path, rules, state)
			if mode == "failed" {
				if len(got) != 0 || state.Offsets[path] != 0 || len(state.LastAlertTime) != 0 {
					t.Fatalf("failed delivery consumed lockout: fired=%v offset=%d cooldown=%v", got, state.Offsets[path], state.LastAlertTime)
				}
				if again := evaluateAccountLockout(path, rules, state); len(again) != 0 || first.calls != 2 || second.calls != 2 {
					t.Fatalf("failed delivery was not retried once: fired=%v calls=%d/%d", again, first.calls, second.calls)
				}
				first.result.Delivered = true
				if retry := evaluateAccountLockout(path, rules, state); len(retry) != 1 || state.Offsets[path] == 0 {
					t.Fatalf("recovered delivery did not commit event: %v", retry)
				}
			} else if len(got) != 1 || state.Offsets[path] == 0 || len(state.LastAlertTime) != 1 {
				t.Fatalf("successful/no-path delivery did not advance: %v", got)
			}
			before := first.calls
			if again := evaluateAccountLockout(path, rules, state); len(again) != 0 || first.calls != before {
				t.Fatal("committed event was delivered twice")
			}
		})
	}
}

func TestEventDeliveryNCUserRetryRestoresOffsetsAndPending(t *testing.T) {
	for _, firstLogin := range []bool{false, true} {
		t.Run(fmt.Sprint("first-login=", firstLogin), func(t *testing.T) {
			dir := ncTestEnv(t)
			now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
			n := &eventDeliveryNotifier{result: DeliveryResult{Attempted: true}}
			useEventDelivery(t, now, n)
			rules := enabledNCRules()
			state := newAlertState()
			path := filepath.Join(dir, "data", "logs", "nextcloud.jsonl")
			writeFile(t, path, "")
			evaluateNCUserEvents(nil, rules, state) // Establish the first-run offset.
			if firstLogin {
				state.PendingNCUsers["local|sample"] = now.Add(-time.Minute)
				appendFile(t, path, ncLoginSuccessLine("2026-10-21T11:59:30Z", "sample"))
			} else {
				appendFile(t, path, ncCreatedLine("2026-10-21T11:59:00Z", "sample"))
			}
			for attempt := 1; attempt <= 2; attempt++ {
				got := evaluateNCUserEvents(nil, rules, state)
				_, pending := state.PendingNCUsers["local|sample"]
				if len(got) != 0 || state.Offsets[path] != 0 || len(state.LastAlertTime) != 0 || pending != firstLogin || n.calls != attempt {
					t.Fatalf("failed event consumed: fired=%v offset=%d pending=%v cooldown=%v calls=%d", got, state.Offsets[path], pending, state.LastAlertTime, n.calls)
				}
			}
			n.result.Delivered = true
			if got := evaluateNCUserEvents(nil, rules, state); len(got) != 1 || state.Offsets[path] == 0 {
				t.Fatalf("recovered user event not committed: %v", got)
			}
			_, pending := state.PendingNCUsers["local|sample"]
			if pending == firstLogin {
				t.Fatal("successful creation/login pending transition lost")
			}
		})
	}
}

func TestEventDeliveryFileAccessFailureDoesNotStartCooldown(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	n := &eventDeliveryNotifier{result: DeliveryResult{Attempted: true}}
	useEventDelivery(t, now, n)
	rules := ncFARules(ruleNCMassAccess)
	state := newAlertState()
	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)
	appendFile(t, env.auditPath, ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 300, "sample@example.com", "192.0.2.7", uaBrowser, nil))
	for attempt := 1; attempt <= 2; attempt++ {
		if got := env.run(rules, state, now); len(got) != 0 || len(state.LastAlertTime) != 0 || n.calls != attempt {
			t.Fatalf("failed access notification started cooldown: fired=%v cooldown=%v calls=%d", got, state.LastAlertTime, n.calls)
		}
	}
	n.result.Delivered = true
	if got := env.run(rules, state, now); len(got) != 1 || len(state.LastAlertTime) != 1 {
		t.Fatalf("recovered access notification not committed: %v", got)
	}
}

func TestEventDeliveryFileAccessFailedSummaryKeepsOverflowSubjects(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	n := &eventDeliveryNotifier{resultFor: func(message string) DeliveryResult {
		return DeliveryResult{Attempted: true, Delivered: !strings.Contains(message, "ほか ")}
	}}
	useEventDelivery(t, now, n)
	rules := ncFARules(ruleNCMassAccess)
	state := newAlertState()
	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)
	for i := 0; i < 2*ncFAMaxAlertsPerRule+2; i++ {
		appendFile(t, env.auditPath, ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 300, fmt.Sprintf("sample%02d@example.com", i), "192.0.2.7", uaBrowser, nil))
	}
	for attempt := 1; attempt <= 2; attempt++ {
		got := env.run(rules, state, now)
		if len(got) != ncFAMaxAlertsPerRule || len(state.LastAlertTime) != attempt*ncFAMaxAlertsPerRule || n.calls != attempt*(ncFAMaxAlertsPerRule+1) {
			t.Fatalf("failed summary consumed subjects: fired=%d cooldowns=%d calls=%d", len(got), len(state.LastAlertTime), n.calls)
		}
		if _, ok := state.LastAlertTime[ncFACooldownKey(ruleNCMassAccess, ncFAOverflowSubject)]; ok {
			t.Fatal("failed summary started its cooldown")
		}
	}
	if got := env.run(rules, state, now); len(got) != 2 || len(state.LastAlertTime) != 2*ncFAMaxAlertsPerRule+2 {
		t.Fatalf("overflow subjects did not remain eligible: fired=%d cooldowns=%d", len(got), len(state.LastAlertTime))
	}
}
