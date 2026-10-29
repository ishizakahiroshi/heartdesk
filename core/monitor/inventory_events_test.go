package monitor

import (
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

func TestInventoryEventsKeepOtherAgentWhenHistoryFails(t *testing.T) {
	cfg := &config.AppConfig{Agents: map[string]config.AgentConfig{"alpha-vps-one": {}, "beta-vps-two": {}}}
	events, err := inventoryAlertEvents(cfg, func(id string) InventoryView {
		if id == "alpha-vps-one" {
			return InventoryView{Status: "history_error"}
		}
		return InventoryView{Status: "stale", Stale: true, ObservedAt: "2026-01-01T00:00:00Z"}
	})
	if err == nil || len(events) != 1 || events[0].RuleID != "inventory_stale" {
		t.Fatalf("independent event lost or error hidden: events=%+v err=%v", events, err)
	}
}
