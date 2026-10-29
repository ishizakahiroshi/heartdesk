package alerts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// Event carries an already determined observation from its owner. It performs
// no AI inference or vulnerability matching. ID is stable across delivery retries.
type Event struct {
	ID      string
	RuleID  string
	Message string
}
type EventSource func(*config.AppConfig) ([]Event, error)

var sourcesMu sync.RWMutex

type registeredEventSource struct {
	collect EventSource
	rules   []string
}

var eventSources []registeredEventSource

func RegisterEventSource(source EventSource, ruleIDs ...string) {
	if source == nil {
		return
	}
	sourcesMu.Lock()
	eventSources = append(eventSources, registeredEventSource{collect: source, rules: append([]string(nil), ruleIDs...)})
	sourcesMu.Unlock()
}

func evaluateEvents(cfg *config.AppConfig, rules AlertRules, state *AlertState) ([]string, error) {
	sourcesMu.RLock()
	sources := append([]registeredEventSource(nil), eventSources...)
	sourcesMu.RUnlock()
	fired := []string{}
	var sourceFailed bool
	for _, source := range sources {
		if len(source.rules) > 0 {
			enabled := false
			for _, id := range source.rules {
				enabled = enabled || rules.Rules[id].Enabled
			}
			if !enabled {
				continue
			}
		}
		events, err := source.collect(cfg)
		if err != nil {
			sourceFailed = true
		}
		for _, event := range events {
			if !rules.Rules[event.RuleID].Enabled || event.ID == "" || event.Message == "" {
				continue
			}
			id := sha256.Sum256([]byte(event.RuleID + "\x00" + event.ID))
			key := hex.EncodeToString(id[:])
			if _, done := state.EventReceipts[key]; done {
				continue
			}
			message := event.Message + " [event:" + key + "]"
			result := sendAlertResult(rules, event.RuleID, message)
			if !result.Attempted || !result.Delivered {
				// Neither a missing destination nor an unsuccessful delivery consumes
				// this event. The next scheduled evaluation retries without AI.
				log.Printf("alerts: observation delivery pending rule=%s attempted=%t", event.RuleID, result.Attempted)
				continue
			}
			state.EventReceipts[key] = nowFn()
			fired = append(fired, message)
		}
	}
	if sourceFailed {
		return fired, fmt.Errorf("observation source unavailable")
	}
	return fired, nil
}
