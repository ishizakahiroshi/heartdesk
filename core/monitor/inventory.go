package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc/store"
)

// InventoryView is derived exclusively from inventory observations. Activity in
// other collector groups never makes an old inventory look fresh.
type InventoryView struct {
	AgentID        string             `json:"agent_id"`
	Status         string             `json:"status"`
	ObservedAt     string             `json:"observed_at,omitempty"`
	Stale          bool               `json:"stale"`
	HistoryLimited bool               `json:"history_limited"`
	Sections       []InventorySection `json:"sections"`
	Changes        []InventoryChange  `json:"changes"`
}
type InventorySection struct {
	Key           string            `json:"key"`
	Label         string            `json:"label"`
	Status        string            `json:"status"`
	Source        string            `json:"source,omitempty"`
	ObservedAt    string            `json:"observed_at,omitempty"`
	LastSuccessAt string            `json:"last_success_at,omitempty"`
	ErrorCode     string            `json:"error_code,omitempty"`
	Items         map[string]string `json:"items"`
	Stale         bool              `json:"stale"`
}
type InventoryChange struct {
	Section string `json:"section"`
	Item    string `json:"item"`
	Before  string `json:"before"`
	After   string `json:"after"`
}
type inventoryObservation struct {
	Status     string          `json:"status"`
	Source     string          `json:"source"`
	ObservedAt string          `json:"observed_at"`
	ErrorCode  string          `json:"error_code"`
	Value      json.RawMessage `json:"value"`
}
type inventorySnapshot struct {
	SchemaVersion int                  `json:"schema_version"`
	ObservedAt    string               `json:"observed_at"`
	OS            inventoryObservation `json:"os"`
	Kernel        inventoryObservation `json:"kernel"`
	Packages      inventoryObservation `json:"packages"`
	Runtimes      inventoryObservation `json:"runtimes"`
	Containers    inventoryObservation `json:"containers"`
}

// Hourly collection needs room for execution and retry jitter. Two hours lets
// one delayed collection complete before treating the last observation as stale.
const inventoryStaleAfter = 2 * time.Hour

func withInventory(data UpdatesData, agentID string) UpdatesData {
	if isValidAgentID(agentID) {
		v := GetInventory(agentID)
		data.Inventory = &v
	}
	return data
}
func (v InventoryView) StatusText() string { return inventoryStatusText(v.Status) }
func (s InventorySection) StatusText() string {
	if s.Stale && s.Status == "ok" {
		return inventoryStatusText("stale")
	}
	return inventoryStatusText(s.Status)
}
func inventoryStatusText(status string) string {
	switch status {
	case "ok":
		return "取得済み"
	case "stale":
		return "再収集が必要"
	case "partial":
		return "一部未確認"
	case "unsupported":
		return "未対応"
	case "permission_denied":
		return "権限不足"
	case "error", "history_error":
		return "取得エラー"
	default:
		return "未取得"
	}
}
func (s InventorySection) DisplayItems() map[string]string {
	keys := make([]string, 0, len(s.Items))
	for k := range s.Items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 50 {
		keys = keys[:50]
	}
	out := map[string]string{}
	for _, k := range keys {
		out[k] = s.Items[k]
	}
	return out
}

func GetInventory(agentID string) InventoryView {
	if !isValidAgentID(agentID) {
		return InventoryView{AgentID: agentID, Status: "unavailable", Sections: []InventorySection{}, Changes: []InventoryChange{}}
	}
	rows, limited, err := inventoryHistory(agentID)
	if err != nil {
		return InventoryView{AgentID: agentID, Status: "history_error", Sections: []InventorySection{}, Changes: []InventoryChange{}}
	}
	view := inventoryView(agentID, rows, time.Now())
	view.HistoryLimited = limited
	return view
}

func inventoryHistory(agentID string) ([]json.RawMessage, bool, error) {
	out := []json.RawMessage{}
	if _, _, reports, ok := currentAgentReportStores(); ok {
		limit := 4000
		var rows []store.RawReport
		var err error
		if filtered, ok := reports.(interface {
			ListRawReportsForCollector(context.Context, string, string, string, int) ([]store.RawReport, error)
		}); ok {
			limit = 100
			rows, err = filtered.ListRawReportsForCollector(context.Background(), tenantIDFromAgentID(agentID), agentID, "inventory", limit)
		} else {
			rows, err = reports.ListRawReports(context.Background(), tenantIDFromAgentID(agentID), agentID, time.Unix(0, 0), time.Now().Add(latestReportFutureBuffer), limit)
		}
		if err != nil {
			return nil, false, fmt.Errorf("inventory history unavailable")
		}
		for _, row := range rows {
			var cols map[string]json.RawMessage
			if json.Unmarshal([]byte(row.CollectorsJSON), &cols) != nil {
				return nil, false, fmt.Errorf("invalid history")
			}
			if raw, ok := cols["inventory"]; ok {
				out = append(out, raw)
			}
		}
		return out, len(rows) == limit, nil
	}
	return inventoryJSONLHistory(agentReportDirPath(), agentID)
}

func inventoryJSONLHistory(dir, agentID string) ([]json.RawMessage, bool, error) {
	out := []json.RawMessage{}
	files, err := filepath.Glob(filepath.Join(dir, "report_"+agentID+"_*.jsonl"))
	if err != nil {
		return nil, false, err
	}
	// Read newest records first, with a fixed I/O budget. Old report files stay
	// untouched; an exhausted budget is reported as limited history.
	const budget = 16 << 20
	remaining := int64(budget)
	limited := false
	for index := len(files) - 1; index >= 0; index-- {
		file := files[index]
		f, err := os.Open(file)
		if err != nil {
			return nil, false, fmt.Errorf("inventory history open failed")
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, false, fmt.Errorf("inventory history stat failed")
		}
		size := info.Size()
		readSize := size
		if readSize > remaining {
			readSize = remaining
			limited = true
		}
		data := make([]byte, int(readSize))
		if readSize > 0 {
			if _, err := f.ReadAt(data, size-readSize); err != nil {
				f.Close()
				return nil, false, fmt.Errorf("inventory history read failed")
			}
		}
		f.Close()
		remaining -= readSize
		lines := bytes.Split(data, []byte("\n"))
		if len(data) > 0 && data[len(data)-1] != '\n' {
			// The writer commits JSONL records with a newline. A newest-file
			// tail may be between writes; never accept even valid JSON before
			// its terminator arrives. Older unclosed files are a history error.
			if index != len(files)-1 {
				return nil, false, fmt.Errorf("unterminated history")
			}
			lines = lines[:len(lines)-1]
			limited = true
		}
		if size > readSize && len(lines) > 0 {
			lines = lines[1:]
		}
		for i := len(lines) - 1; i >= 0; i-- {
			if len(bytes.TrimSpace(lines[i])) == 0 {
				continue
			}
			var row agentReportRecord
			if json.Unmarshal(lines[i], &row) != nil {
				return nil, false, fmt.Errorf("invalid history")
			}
			if row.AgentID == agentID {
				if raw, ok := row.Collectors["inventory"]; ok {
					out = append(out, raw)
					if len(out) == 100 {
						return out, true, nil
					}
				}
			}
		}
		if remaining == 0 {
			if index > 0 {
				limited = true
			}
			break
		}
	}
	return out, limited, nil
}

func snapshotSections(s inventorySnapshot) []inventoryObservation {
	return []inventoryObservation{s.OS, s.Kernel, s.Packages, s.Runtimes, s.Containers}
}

func inventoryView(agentID string, rows []json.RawMessage, now time.Time) InventoryView {
	v := InventoryView{AgentID: agentID, Status: "unavailable", Sections: []InventorySection{}, Changes: []InventoryChange{}}
	if len(rows) == 0 {
		return v
	}
	keys := []string{"os", "kernel", "packages", "runtimes", "containers"}
	labels := []string{"OS", "カーネル", "パッケージ", "実行環境", "コンテナ"}
	var current inventorySnapshot
	valid := json.Unmarshal(rows[0], &current) == nil && current.SchemaVersion == 1
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(rows[0], &fields)
	if _, failed := fields["_error"]; failed {
		valid = false
	}
	v.Status = "ok"
	v.ObservedAt = current.ObservedAt
	at, err := time.Parse(time.RFC3339Nano, current.ObservedAt)
	if err != nil || at.After(now.Add(5*time.Minute)) {
		valid = false
	} else {
		v.Stale = now.Sub(at) > inventoryStaleAfter
	}
	if !valid {
		v.Status = "error"
		v.ObservedAt = ""
	}
	for i, key := range keys {
		cur := snapshotSections(current)[i]
		section := InventorySection{Key: key, Label: labels[i], Status: cur.Status, Source: cur.Source, ObservedAt: cur.ObservedAt, ErrorCode: cur.ErrorCode, Items: map[string]string{}}
		sectionTimeValid := false
		if observed, e := time.Parse(time.RFC3339Nano, cur.ObservedAt); e == nil && !observed.After(now.Add(5*time.Minute)) {
			sectionTimeValid = true
			section.Stale = now.Sub(observed) > inventoryStaleAfter
			if section.Stale {
				v.Stale = true
			}
		}
		switch section.Status {
		case "ok", "partial", "unavailable", "unsupported", "permission_denied", "error":
		default:
			section.Status = "unavailable"
			section.ErrorCode = "not_reported"
		}
		if !valid {
			section.Status = "error"
			section.ErrorCode = "invalid_snapshot"
		} else if !sectionTimeValid {
			section.Status = "error"
			section.ErrorCode = "invalid_observation_time"
		}
		var successful []inventoryObservation
		for _, raw := range rows {
			var s inventorySnapshot
			if json.Unmarshal(raw, &s) != nil || s.SchemaVersion != 1 {
				continue
			}
			var historyFields map[string]json.RawMessage
			if json.Unmarshal(raw, &historyFields) != nil {
				continue
			}
			if _, failed := historyFields["_error"]; failed {
				continue
			}
			if observed, e := time.Parse(time.RFC3339Nano, s.ObservedAt); e != nil || observed.After(now.Add(5*time.Minute)) {
				continue
			}
			o := snapshotSections(s)[i]
			if o.Status != "ok" {
				continue
			}
			if observed, err := time.Parse(time.RFC3339Nano, o.ObservedAt); err != nil || observed.After(now.Add(5*time.Minute)) {
				continue
			}
			if _, ok := inventoryItems(key, o.Value); ok {
				successful = append(successful, o)
				if len(successful) == 2 {
					break
				}
			}
		}
		if len(successful) > 0 {
			section.LastSuccessAt = successful[0].ObservedAt
			section.Items, _ = inventoryItems(key, successful[0].Value)
		}
		if valid && sectionTimeValid && cur.Status == "ok" {
			if items, ok := inventoryItems(key, cur.Value); ok {
				section.Items = items
			} else {
				section.Status = "error"
				section.ErrorCode = "invalid_output"
			}
		}
		if valid && sectionTimeValid && cur.Status == "partial" {
			if items, ok := inventoryItems(key, cur.Value); ok {
				for id, value := range items {
					section.Items[id] = value
				}
			}
		}
		if section.Status != "ok" {
			v.Status = "partial"
			if !valid {
				v.Status = "error"
			}
		}
		// Missing/failed data can never remove previously known software.
		if valid && section.Status == "ok" && len(successful) == 2 {
			before, _ := inventoryItems(key, successful[1].Value)
			set := map[string]bool{}
			for k := range before {
				set[k] = true
			}
			for k := range section.Items {
				set[k] = true
			}
			ids := make([]string, 0, len(set))
			for k := range set {
				ids = append(ids, k)
			}
			sort.Strings(ids)
			for _, id := range ids {
				if before[id] != section.Items[id] {
					v.Changes = append(v.Changes, InventoryChange{Section: labels[i], Item: id, Before: before[id], After: section.Items[id]})
				}
			}
		}
		v.Sections = append(v.Sections, section)
	}
	if v.Stale && v.Status == "ok" {
		v.Status = "stale"
	}
	return v
}

func inventoryItems(key string, raw json.RawMessage) (map[string]string, bool) {
	out := map[string]string{}
	if len(raw) == 0 || string(raw) == "null" {
		return out, false
	}
	switch key {
	case "os":
		var fields map[string]string
		if json.Unmarshal(raw, &fields) != nil || fields["ID"] == "" {
			return out, false
		}
		for _, k := range []string{"ID", "VERSION_ID", "ID_LIKE"} {
			if fields[k] != "" {
				out[k] = fields[k]
			}
		}
	case "kernel":
		var value string
		if json.Unmarshal(raw, &value) != nil || value == "" {
			return out, false
		}
		out["kernel"] = value
	case "packages":
		var values []struct {
			Name         string `json:"name"`
			Version      string `json:"version"`
			Architecture string `json:"architecture"`
		}
		if json.Unmarshal(raw, &values) != nil {
			return out, false
		}
		for _, v := range values {
			id := v.Name + ":" + v.Architecture
			if v.Name == "" || v.Version == "" || v.Architecture == "" {
				return out, false
			}
			if _, dup := out[id]; dup {
				return out, false
			}
			out[id] = v.Version
		}
	case "runtimes":
		var values []struct {
			Kind     string `json:"kind"`
			Binary   string `json:"binary"`
			Evidence string `json:"evidence"`
			Version  string `json:"version"`
			Status   string `json:"status"`
			Deleted  bool   `json:"deleted"`
		}
		if json.Unmarshal(raw, &values) != nil {
			return out, false
		}
		versions := map[string]map[string]bool{}
		for _, v := range values {
			if v.Status != "ok" {
				continue
			}
			if v.Kind == "" || v.Binary == "" || v.Version == "" || (v.Evidence != "path_probe" && v.Evidence != "proc_exe") {
				return out, false
			}
			id := v.Kind + ":" + v.Evidence + ":" + v.Binary
			if v.Deleted {
				id += " (deleted)"
			}
			if versions[id] == nil {
				versions[id] = map[string]bool{}
			}
			versions[id][v.Version] = true
		}
		for id, versionSet := range versions {
			list := make([]string, 0, len(versionSet))
			for version := range versionSet {
				list = append(list, version)
			}
			sort.Strings(list)
			out[id] = strings.Join(list, " / ")
		}
	case "containers":
		var values []struct {
			ID      string   `json:"id"`
			ImageID string   `json:"image_id"`
			State   string   `json:"state"`
			Digests []string `json:"digests"`
		}
		if json.Unmarshal(raw, &values) != nil {
			return out, false
		}
		for _, v := range values {
			if v.ID == "" || v.ImageID == "" {
				return out, false
			}
			if _, duplicate := out[v.ID]; duplicate {
				return out, false
			}
			out[v.ID] = v.ImageID + " " + v.State + " " + strings.Join(v.Digests, ", ")
		}
	default:
		return out, false
	}
	return out, true
}
