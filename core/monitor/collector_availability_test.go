package monitor

import (
	"encoding/json"
	"testing"
)

func TestCollectorFailureIsUnavailable(t *testing.T) {
	const id = "alpha-vps-fixture"
	agentLastSeenMu.Lock()
	previous, existed := agentLatestCollectors[id]
	agentLastSeenMu.Unlock()
	t.Cleanup(func() {
		agentLastSeenMu.Lock()
		defer agentLastSeenMu.Unlock()
		if existed {
			agentLatestCollectors[id] = previous
		} else {
			delete(agentLatestCollectors, id)
		}
	})
	for _, raw := range []string{`{"_error":"synthetic failure"}`, `{"_error":""}`, `null`, `{}`, `[]`, `{"services":null}`, `{"services":{}}`, `{"update_count":"bad"}`} {
		t.Run(raw, func(t *testing.T) {
			agentLastSeenMu.Lock()
			agentLatestCollectors[id] = map[string]json.RawMessage{"updates": json.RawMessage(raw), "services": json.RawMessage(raw)}
			agentLastSeenMu.Unlock()
			if got := updatesDataFromAgentReport(id); !got.Unavailable {
				t.Fatal("updates failure became successful zero data")
			}
			if _, ok := servicesFromReport(id); ok {
				t.Fatal("services failure became successful empty data")
			}
		})
	}
}

func TestCollectorSuccessfulEmptyIsAvailable(t *testing.T) {
	const id = "alpha-vps-empty"
	agentLastSeenMu.Lock()
	agentLatestCollectors[id] = map[string]json.RawMessage{
		"updates":  json.RawMessage(`{"update_count":0}`),
		"services": json.RawMessage(`{"services":{},"order":[]}`),
	}
	agentLastSeenMu.Unlock()
	t.Cleanup(func() { agentLastSeenMu.Lock(); delete(agentLatestCollectors, id); agentLastSeenMu.Unlock() })
	if got := updatesDataFromAgentReport(id); got.Unavailable || got.UpdateCount != 0 {
		t.Fatal("successful zero updates lost")
	}
	if _, ok := servicesFromReport(id); !ok {
		t.Fatal("successful empty services lost")
	}
}
