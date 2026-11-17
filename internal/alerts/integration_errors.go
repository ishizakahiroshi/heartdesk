package alerts

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"time"
)

const integrationErrorRule = "integration_http_error"

// This snapshot is produced from authenticated, correlated HTTP outcomes by the
// scheduler. It intentionally contains neither raw paths nor account names.
type integrationErrorSnapshot struct {
	GeneratedAt time.Time                  `json:"generated_at"`
	Resources   []integrationErrorResource `json:"resources"`
}
type integrationErrorResource struct {
	Key         string                  `json:"key"`
	Source      string                  `json:"source"`
	Operation   string                  `json:"operation"`
	Status      int                     `json:"status"`
	Count       int                     `json:"count"`
	First       time.Time               `json:"first"`
	Last        time.Time               `json:"last"`
	LastSuccess time.Time               `json:"last_success,omitempty"`
	Events      []integrationErrorEvent `json:"events"`
}

type integrationErrorEvent struct {
	ID string    `json:"id"`
	TS time.Time `json:"ts"`
}

type integrationErrorState struct {
	Source        string               `json:"source"`
	Operation     string               `json:"operation"`
	Status        int                  `json:"status"`
	LastSuccess   time.Time            `json:"last_success,omitempty"`
	Pending       int                  `json:"pending"`
	First         time.Time            `json:"first"`
	Last          time.Time            `json:"last"`
	Delivered     bool                 `json:"delivered"`
	Updated       time.Time            `json:"updated"`
	Seen          map[string]time.Time `json:"seen"`
	PendingEvents map[string]time.Time `json:"pending_events"`
}

var integrationSourcePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func readIntegrationSnapshot(path string, now time.Time) (*integrationErrorSnapshot, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4*1024*1024+1))
	if err != nil || len(data) > 4*1024*1024 {
		return nil, false
	}
	var snap integrationErrorSnapshot
	if json.Unmarshal(data, &snap) != nil || len(snap.Resources) > 10000 || snap.GeneratedAt.IsZero() || snap.GeneratedAt.After(now.Add(5*time.Minute)) || snap.GeneratedAt.Before(now.Add(-30*time.Minute)) {
		return nil, false
	}
	seen := map[string]bool{}
	eventIDs := map[string]string{}
	for _, r := range snap.Resources {
		key, err := hex.DecodeString(r.Key)
		if err != nil || len(key) != 32 || len(r.Key) != 64 || seen[r.Key] || !integrationSourcePattern.MatchString(r.Source) || (r.Operation != "fetch_file" && r.Operation != "preview_file") || r.Status != 404 || r.Count < 0 || r.Count > 10000000 || r.LastSuccess.After(now.Add(5*time.Minute)) {
			return nil, false
		}
		seen[r.Key] = true
		if r.Count > 0 && (r.First.IsZero() || r.Last.IsZero() || r.First.After(r.Last) || r.Last.After(now.Add(5*time.Minute))) {
			return nil, false
		}
		if r.Count == 0 && r.LastSuccess.IsZero() {
			return nil, false
		}
		if len(r.Events) > 100000 {
			return nil, false
		}
		for _, event := range r.Events {
			id, err := hex.DecodeString(event.ID)
			if err != nil || len(id) != 32 || len(event.ID) != 64 || event.TS.IsZero() || event.TS.After(now.Add(5*time.Minute)) || event.TS.Before(now.Add(-24*time.Hour)) {
				return nil, false
			}
			identity := r.Key + "|" + event.TS.Format(time.RFC3339Nano)
			if prior, ok := eventIDs[event.ID]; ok && prior != identity {
				return nil, false
			}
			eventIDs[event.ID] = identity
		}
		if r.Count > 0 && len(r.Events) == 0 {
			return nil, false
		}
	}
	return &snap, true
}

func evaluateIntegrationErrors(path string, rules AlertRules, state *AlertState) []string {
	now := nowFn()
	snap, ok := readIntegrationSnapshot(path, now)
	state.ensureMaps()
	rule, enabled := rules.Rules[integrationErrorRule]
	enabled = enabled && rule.Enabled
	threshold := rule.Threshold
	if threshold <= 0 {
		threshold = 1
	}
	cd := rule.CooldownSec
	if cd <= 0 {
		cd = 10800
	}
	if ok {
		// Conflicting replayed IDs must not manufacture a new event, resource,
		// or recovery. Pending events already stored still remain retryable.
		known := map[string]string{}
		for key, s := range state.IntegrationErrors {
			if s == nil {
				continue
			}
			for id, ts := range s.Seen {
				known[id] = key + "|" + ts.Format(time.RFC3339Nano)
			}
		}
		for _, r := range snap.Resources {
			if s := state.IntegrationErrors[r.Key]; s != nil && (s.Source != r.Source || s.Operation != r.Operation || s.Status != r.Status) {
				ok = false
			}
			for _, event := range r.Events {
				if prior, exists := known[event.ID]; exists && prior != r.Key+"|"+event.TS.Format(time.RFC3339Nano) {
					ok = false
				}
			}
		}
	}
	if ok {
		for _, r := range snap.Resources {
			s := state.IntegrationErrors[r.Key]
			if s == nil {
				s = &integrationErrorState{}
				state.IntegrationErrors[r.Key] = s
			}
			if s.Seen == nil {
				s.Seen = map[string]time.Time{}
			}
			if s.PendingEvents == nil {
				s.PendingEvents = map[string]time.Time{}
			}
			if r.LastSuccess.After(s.LastSuccess) {
				s.LastSuccess = r.LastSuccess
				for id, ts := range s.PendingEvents {
					if !ts.After(r.LastSuccess) {
						delete(s.PendingEvents, id)
					}
				}
				// A success followed by another failure starts an independent episode.
				if r.Last.After(r.LastSuccess) {
					s.Delivered = false
					delete(state.LastAlertTime, integrationErrorRule+":"+r.Key)
				}
			}
			for _, event := range r.Events {
				if _, seen := s.Seen[event.ID]; seen {
					continue
				}
				s.Seen[event.ID] = event.TS
				if !event.TS.After(s.LastSuccess) {
					continue
				}
				s.PendingEvents[event.ID] = event.TS
				if event.TS.After(s.Last) {
					s.Last = event.TS
				}
			}
			s.Pending = len(s.PendingEvents)
			s.First = time.Time{}
			for _, ts := range s.PendingEvents {
				if s.First.IsZero() || ts.Before(s.First) {
					s.First = ts
				}
			}
			s.Source = r.Source
			s.Operation = r.Operation
			s.Status = r.Status
			s.Updated = now
		}
	}
	keys := make([]string, 0, len(state.IntegrationErrors))
	for key, s := range state.IntegrationErrors {
		if s != nil && len(key) == 64 {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var out []string
	sent := 0
	var overflow []string
	active := false
	for _, key := range keys {
		s := state.IntegrationErrors[key]
		coolKey := integrationErrorRule + ":" + key
		if s.LastSuccess.After(s.Last) {
			if s.Delivered && enabled && rule.NotifyRecovery {
				if sent >= 5 {
					active = true
					continue
				}
				sent++
				message, delivered := fireDelivered(rules, integrationErrorRule, fmt.Sprintf("%s: %s 対象 %s の取得が回復しました", RuleLabel(integrationErrorRule), s.Source, key[:12]))
				if !delivered {
					active = true
					continue
				}
				out = append(out, message)
			}
			s.Pending = 0
			s.PendingEvents = map[string]time.Time{}
			s.Delivered = false
			s.First = time.Time{}
			s.Last = time.Time{}
			delete(state.LastAlertTime, coolKey)
			delete(state.FirstBreach, coolKey)
			continue
		}
		if s.Pending > 0 || s.Delivered {
			active = true
		}
		if !enabled || float64(s.Pending) < threshold || s.Pending == 0 {
			continue
		}
		if last, exists := state.LastAlertTime[coolKey]; exists && now.Sub(last) < time.Duration(cd)*time.Second {
			continue
		}
		if sent >= 5 {
			overflow = append(overflow, key)
			continue
		}
		snapshot := snapshotAlertKey(coolKey, state)
		if !shouldAlert(coolKey, 0, cd, state, now) {
			continue
		}
		msg := fmt.Sprintf("%s: %s の %s（対象 %s）が HTTP %d、未通知 %d 件（%s〜%s）", RuleLabel(integrationErrorRule), s.Source, s.Operation, key[:12], s.Status, s.Pending, s.First.Format(time.RFC3339), s.Last.Format(time.RFC3339))
		sent++
		if message, delivered := fireTracked(rules, integrationErrorRule, coolKey, state, snapshot, msg); delivered {
			out = append(out, message)
			s.Pending = 0
			s.PendingEvents = map[string]time.Time{}
			s.Delivered = true
		}
	}
	if enabled && len(overflow) > 0 {
		coolKey := integrationErrorRule + ":overflow"
		snapshot := snapshotAlertKey(coolKey, state)
		if shouldAlert(coolKey, 0, cd, state, now) {
			count := 0
			for _, key := range overflow {
				count += state.IntegrationErrors[key].Pending
			}
			msg := fmt.Sprintf("%s: ほか %d 対象で未通知 %d 件の取得失敗", RuleLabel(integrationErrorRule), len(overflow), count)
			if message, delivered := fireTracked(rules, integrationErrorRule, coolKey, state, snapshot, msg); delivered {
				out = append(out, message)
				for _, key := range overflow {
					s := state.IntegrationErrors[key]
					s.Pending = 0
					s.PendingEvents = map[string]time.Time{}
					s.Delivered = true
					state.LastAlertTime[integrationErrorRule+":"+key] = now
				}
			}
		}
	}
	if enabled {
		state.Active[integrationErrorRule] = active
	}
	for key, s := range state.IntegrationErrors {
		if s == nil {
			continue
		}
		for id, ts := range s.Seen {
			if now.Sub(ts) > 7*24*time.Hour {
				if _, pending := s.PendingEvents[id]; !pending {
					delete(s.Seen, id)
				}
			}
		}
		if s.Pending == 0 && !s.Delivered && now.Sub(s.Updated) > 7*24*time.Hour {
			delete(state.IntegrationErrors, key)
		}
	}
	return out
}
