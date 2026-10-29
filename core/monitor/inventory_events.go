package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/ishizakahiroshi/heartdesk/internal/alerts"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

func InventoryAlertEvents(cfg *config.AppConfig) ([]alerts.Event, error) {
	return inventoryAlertEvents(cfg, GetInventory)
}

func inventoryAlertEvents(cfg *config.AppConfig, get func(string) InventoryView) ([]alerts.Event, error) {
	if cfg == nil {
		return nil, nil
	}
	ids := make([]string, 0, len(cfg.Agents))
	for id := range cfg.Agents {
		if isValidAgentID(id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	events := []alerts.Event{}
	failed := false
	for _, id := range ids {
		v := get(id)
		if v.Status == "history_error" {
			failed = true
			continue
		}
		if v.Status == "unavailable" {
			continue
		} // Registration alone is not a snapshot.
		add := func(rule, identity, message string) {
			sum := sha256.Sum256([]byte(id + "\x00" + rule + "\x00" + identity))
			events = append(events, alerts.Event{ID: hex.EncodeToString(sum[:]), RuleID: rule, Message: message})
		}
		if v.Stale {
			add("inventory_stale", v.ObservedAt, "構成情報の再収集が必要: "+id)
		}
		if v.Status == "error" || v.Status == "partial" {
			// Repeated failures with the same coverage/error do not generate a
			// fresh incident merely because the collection timestamp changed.
			identity := ""
			for _, s := range v.Sections {
				identity += s.Key + ":" + s.Status + ":" + s.ErrorCode + ":" + s.LastSuccessAt + ";"
			}
			add("inventory_collection_failed", identity, "構成情報の取得に未確認・失敗あり: "+id)
		}
		if len(v.Changes) > 0 {
			body, _ := json.Marshal(v.Changes)
			add("inventory_changed", v.ObservedAt+string(body), fmt.Sprintf("構成変更を観測: %s (%d件)", id, len(v.Changes)))
		}
	}
	if failed {
		return events, fmt.Errorf("inventory history unavailable")
	}
	return events, nil
}
