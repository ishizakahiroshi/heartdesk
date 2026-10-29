package alerts

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

type loopbackEventNotifier struct {
	url    string
	client *http.Client
}

func (*loopbackEventNotifier) Prepare(*config.AppConfig) {}
func (n *loopbackEventNotifier) Notify(_ string, message string) DeliveryResult {
	resp, err := n.client.Post(n.url, "text/plain", strings.NewReader(message))
	if err != nil {
		return DeliveryResult{Attempted: true}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return DeliveryResult{Attempted: true, Delivered: resp.StatusCode == 200}
}

func TestObservationEventsRetryPersistAndDoNotNeedAI(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(200)
		}
	}))
	defer server.Close()
	sourcesMu.Lock()
	previous := eventSources
	eventSources = []registeredEventSource{{collect: func(*config.AppConfig) ([]Event, error) {
		return []Event{{ID: "synthetic-observation", RuleID: "inventory_changed", Message: "synthetic change"}}, nil
	}, rules: []string{"inventory_changed"}}}
	sourcesMu.Unlock()
	t.Cleanup(func() { sourcesMu.Lock(); eventSources = previous; sourcesMu.Unlock() })
	notifiersMu.Lock()
	old := notifiers
	notifiers = []Notifier{&loopbackEventNotifier{url: server.URL, client: server.Client()}}
	notifiersMu.Unlock()
	t.Cleanup(func() { notifiersMu.Lock(); notifiers = old; notifiersMu.Unlock() })
	rules := AlertRules{Rules: map[string]AlertRule{"inventory_changed": {Enabled: true}}}
	state := newAlertState()
	if fired, err := evaluateEvents(nil, rules, state); err != nil || len(fired) != 0 || len(state.EventReceipts) != 0 {
		t.Fatal("503 consumed event")
	}
	if fired, err := evaluateEvents(nil, rules, state); err != nil || len(fired) != 1 || len(state.EventReceipts) != 1 {
		t.Fatal("retry not delivered")
	}
	file := filepath.Join(t.TempDir(), "state.json")
	if err := saveAlertState(file, state); err != nil {
		t.Fatal(err)
	}
	restored, err := loadAlertState(file)
	if err != nil {
		t.Fatal(err)
	}
	if fired, err := evaluateEvents(nil, rules, restored); err != nil || len(fired) != 0 || calls.Load() != 2 {
		t.Fatal("restart delivered duplicate")
	}
	// Source failure is observable, never a successful no-findings evaluation.
	sourcesMu.Lock()
	eventSources = []registeredEventSource{{collect: func(*config.AppConfig) ([]Event, error) { return nil, errors.New("synthetic source failure") }, rules: []string{"inventory_changed"}}}
	sourcesMu.Unlock()
	if _, err := evaluateEvents(nil, rules, restored); err == nil {
		t.Fatal("source failure hidden")
	}
	if _, err := evaluateEvents(nil, AlertRules{}, restored); err != nil {
		t.Fatal("disabled source was evaluated")
	}
	// An unavailable agent must not block events returned for other agents.
	sourcesMu.Lock()
	eventSources = []registeredEventSource{{collect: func(*config.AppConfig) ([]Event, error) {
		return []Event{{ID: "other-agent", RuleID: "inventory_changed", Message: "independent change"}}, errors.New("one agent unavailable")
	}, rules: []string{"inventory_changed"}}}
	sourcesMu.Unlock()
	if fired, err := evaluateEvents(nil, rules, restored); err == nil || len(fired) != 1 || calls.Load() != 3 {
		t.Fatal("partial source failure blocked independent event or hid error")
	}
}
