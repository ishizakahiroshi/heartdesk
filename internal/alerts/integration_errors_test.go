package alerts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func integrationFixture(t *testing.T) (string, *time.Time, AlertRules, *bool, *[]string) {
	t.Helper()
	now := time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC)
	oldNow, oldSender := nowFn, sender
	allowed := true
	messages := []string{}
	nowFn = func() time.Time { return now }
	sender = func(_ AlertRules, _ string, msg string) bool { messages = append(messages, msg); return allowed }
	t.Cleanup(func() { nowFn = oldNow; sender = oldSender })
	rules := AlertRules{Rules: map[string]AlertRule{integrationErrorRule: {Enabled: true, Threshold: 1, CooldownSec: 10800, NotifyRecovery: true}}}
	return filepath.Join(t.TempDir(), "snapshot.json"), &now, rules, &allowed, &messages
}

func integrationResource(key string, now time.Time, ids ...string) integrationErrorResource {
	r := integrationErrorResource{Key: strings.Repeat(key, 64), Source: "host-1", Operation: "fetch_file", Status: 404, Count: len(ids), First: now.Add(-time.Minute), Last: now.Add(-time.Minute)}
	for i, id := range ids {
		r.Events = append(r.Events, integrationErrorEvent{ID: strings.Repeat(id, 64), TS: now.Add(time.Duration(i-60) * time.Second)})
	}
	if len(r.Events) > 0 {
		r.Last = r.Events[len(r.Events)-1].TS
	}
	return r
}

func writeIntegration(t *testing.T, path string, now time.Time, resources ...integrationErrorResource) {
	t.Helper()
	b, err := json.Marshal(integrationErrorSnapshot{GeneratedAt: now, Resources: resources})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationErrorsFailureRetryRestartAndCooldown(t *testing.T) {
	path, now, rules, allowed, messages := integrationFixture(t)
	state := newAlertState()
	r := integrationResource("a", *now, "b")
	writeIntegration(t, path, *now, r)
	*allowed = false
	if got := evaluateIntegrationErrors(path, rules, state); len(got) != 0 {
		t.Fatal(got)
	}
	if state.IntegrationErrors[r.Key].Pending != 1 || len(state.LastAlertTime) != 0 {
		t.Fatal("failed send lost pending state")
	}
	// Persist and reload, then retry even if the snapshot cannot be read.
	persist := filepath.Join(t.TempDir(), "state.json")
	if err := saveAlertState(persist, state); err != nil {
		t.Fatal(err)
	}
	state = ReadState(persist)
	*allowed = true
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := evaluateIntegrationErrors(path, rules, state); len(got) != 1 {
		t.Fatal("missing snapshot must not discard retry", got)
	}
	r = integrationResource("a", *now, "b", "c")
	writeIntegration(t, path, *now, r)
	if got := evaluateIntegrationErrors(path, rules, state); len(got) != 0 {
		t.Fatal("cooldown", got)
	}
	if state.IntegrationErrors[r.Key].Pending != 1 {
		t.Fatal("new failure during cooldown lost")
	}
	*now = now.Add(3 * time.Hour)
	// The same old snapshot is stale, but accumulated pending work must retry.
	if got := evaluateIntegrationErrors(path, rules, state); len(got) != 1 {
		t.Fatal(got)
	}
	if !strings.Contains((*messages)[len(*messages)-1], "未通知 1 件") {
		t.Fatal(*messages)
	}
}

func TestIntegrationErrorsNewTargetAndReliableRecovery(t *testing.T) {
	path, now, rules, allowed, _ := integrationFixture(t)
	state := newAlertState()
	a := integrationResource("a", *now, "b")
	writeIntegration(t, path, *now, a)
	if len(evaluateIntegrationErrors(path, rules, state)) != 1 {
		t.Fatal("first target")
	}
	b := integrationResource("c", *now, "d")
	writeIntegration(t, path, *now, a, b)
	if len(evaluateIntegrationErrors(path, rules, state)) != 1 {
		t.Fatal("new target hidden by cooldown")
	}
	// Empty snapshot is not evidence of recovery.
	writeIntegration(t, path, *now)
	if len(evaluateIntegrationErrors(path, rules, state)) != 0 || !state.Active[integrationErrorRule] {
		t.Fatal("absence falsely recovered")
	}
	a.LastSuccess = now.Add(-time.Second)
	writeIntegration(t, path, *now, a)
	*allowed = false
	evaluateIntegrationErrors(path, rules, state)
	if !state.IntegrationErrors[a.Key].Delivered {
		t.Fatal("failed recovery marked complete")
	}
	*allowed = true
	if len(evaluateIntegrationErrors(path, rules, state)) != 1 || state.IntegrationErrors[a.Key].Delivered {
		t.Fatal("recovery retry failed")
	}
	if len(evaluateIntegrationErrors(path, rules, state)) != 0 {
		t.Fatal("duplicate recovery")
	}
}

func TestIntegrationErrorsExactEventDedupeWithRollingCount(t *testing.T) {
	path, now, rules, _, _ := integrationFixture(t)
	state := newAlertState()
	r := integrationResource("a", *now, "b")
	writeIntegration(t, path, *now, r)
	evaluateIntegrationErrors(path, rules, state)
	// Window count stays 1 while the old event leaves and a new event arrives.
	r = integrationResource("a", now.Add(time.Minute), "c")
	writeIntegration(t, path, *now, r)
	evaluateIntegrationErrors(path, rules, state)
	evaluateIntegrationErrors(path, rules, state)
	if state.IntegrationErrors[r.Key].Pending != 1 {
		t.Fatal("event IDs must retain exact unseen count")
	}
}

func TestIntegrationErrorsRejectInvalidSnapshots(t *testing.T) {
	path, now, rules, _, _ := integrationFixture(t)
	for _, kind := range []string{"future", "malformed", "duplicate-key", "conflicting-event", "unsafe-source"} {
		t.Run(kind, func(t *testing.T) {
			state := newAlertState()
			r := integrationResource("a", *now, "b")
			snapTime := *now
			resources := []integrationErrorResource{r}
			switch kind {
			case "future":
				snapTime = now.Add(time.Hour)
			case "duplicate-key":
				resources = append(resources, r)
			case "conflicting-event":
				r = integrationResource("c", *now, "b")
				resources = append(resources, r)
			case "unsafe-source":
				resources[0].Source = "host\nforged"
			}
			writeIntegration(t, path, snapTime, resources...)
			if kind == "malformed" {
				os.WriteFile(path, []byte("{"), 0600)
			}
			if got := evaluateIntegrationErrors(path, rules, state); len(got) != 0 || len(state.IntegrationErrors) != 0 {
				t.Fatal("invalid snapshot accepted", got)
			}
		})
	}
}

func TestIntegrationErrorsDisabledAndOverflowRetry(t *testing.T) {
	path, now, rules, allowed, messages := integrationFixture(t)
	state := newAlertState()
	resources := []integrationErrorResource{}
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "1"} {
		resources = append(resources, integrationResource(id, *now, id))
	}
	writeIntegration(t, path, *now, resources...)
	rules.Rules[integrationErrorRule] = AlertRule{Enabled: false}
	if len(evaluateIntegrationErrors(path, rules, state)) != 0 {
		t.Fatal("disabled rule notified")
	}
	rules.Rules[integrationErrorRule] = AlertRule{Enabled: true}
	*allowed = false
	if len(evaluateIntegrationErrors(path, rules, state)) != 0 {
		t.Fatal("failed delivery")
	}
	if len(*messages) != 6 {
		t.Fatal("failed delivery attempts must also respect 5+overflow cap", len(*messages))
	}
	*allowed = true
	if got := evaluateIntegrationErrors(path, rules, state); len(got) != 6 {
		t.Fatal("want 5 individual + overflow", got)
	}
	for _, s := range state.IntegrationErrors {
		if s.Pending != 0 || !s.Delivered {
			t.Fatal("overflow not consumed after delivery")
		}
	}
}

func TestIntegrationErrorsConflictingReplayDoesNotRecoverOrCount(t *testing.T) {
	path, now, rules, _, _ := integrationFixture(t)
	state := newAlertState()
	r := integrationResource("a", *now, "b")
	writeIntegration(t, path, *now, r)
	evaluateIntegrationErrors(path, rules, state)
	r.Events[0].TS = r.Events[0].TS.Add(time.Second)
	r.LastSuccess = *now
	writeIntegration(t, path, *now, r)
	if got := evaluateIntegrationErrors(path, rules, state); len(got) != 0 || !state.IntegrationErrors[r.Key].Delivered {
		t.Fatal("conflicting replay accepted", got)
	}
}

func TestIntegrationErrorsSuccessThenNewFailureStartsNewEpisode(t *testing.T) {
	path, now, rules, _, _ := integrationFixture(t)
	state := newAlertState()
	r := integrationResource("a", *now, "b")
	writeIntegration(t, path, *now, r)
	evaluateIntegrationErrors(path, rules, state)
	r.LastSuccess = now.Add(-30 * time.Second)
	r.Events = append(r.Events, integrationErrorEvent{ID: strings.Repeat("c", 64), TS: now.Add(-time.Second)})
	r.Count = 2
	r.Last = now.Add(-time.Second)
	writeIntegration(t, path, *now, r)
	if got := evaluateIntegrationErrors(path, rules, state); len(got) != 1 || !strings.Contains(got[0], "未通知 1 件") {
		t.Fatal("new episode hidden by previous cooldown", got)
	}
}
