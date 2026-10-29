package alerts

import (
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

func TestObservationEventWithoutDestinationIsNotDelivered(t *testing.T) {
	sourcesMu.Lock()
	oldSources := eventSources
	eventSources = []registeredEventSource{{collect: func(*config.AppConfig) ([]Event, error) {
		return []Event{{ID: "synthetic", RuleID: "inventory_changed", Message: "synthetic change"}}, nil
	}, rules: []string{"inventory_changed"}}}
	sourcesMu.Unlock()
	notifiersMu.Lock()
	oldNotifiers := notifiers
	notifiers = nil
	notifiersMu.Unlock()
	t.Cleanup(func() {
		sourcesMu.Lock()
		eventSources = oldSources
		sourcesMu.Unlock()
		notifiersMu.Lock()
		notifiers = oldNotifiers
		notifiersMu.Unlock()
	})
	state := newAlertState()
	rules := AlertRules{Rules: map[string]AlertRule{"inventory_changed": {Enabled: true}}}
	for i := 0; i < 2; i++ {
		fired, err := evaluateEvents(nil, rules, state)
		if err != nil || len(fired) != 0 || len(state.EventReceipts) != 0 {
			t.Fatal("missing destination consumed event")
		}
	}
}
