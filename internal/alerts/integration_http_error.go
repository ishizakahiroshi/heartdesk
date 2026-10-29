package alerts

// integration_http_error: a trusted receipt from the integration says one of
// its own requests failed (for example GET of a file that should exist ->
// 404). Such events are not attacks, so they are removed from the threat score
// (internal/scheduler/daemon/score.go) and reported here instead.
//
// One notification key per (source scope, operation, resource hash). Items not
// yet delivered stay in alert_state.json and are retried; a failed delivery
// leaves cooldown and sent counters untouched. Recovery needs a reliable
// success (matched 2xx receipt) for the same resource that is newer than the
// last error.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/httpclassification"
	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/httpclassload"
)

const (
	ruleIntegrationHTTPError = "integration_http_error"

	integrationDefaultThreshold = 1
	integrationDefaultCooldown  = 10800
	// integrationLookback bounds how much of the event files is read per run.
	// Pending items live in the state file, so a long delivery outage does not
	// lose them when the files rotate.
	integrationLookback = 24 * time.Hour
	// integrationItemRetention drops idle, delivered items from the state.
	integrationItemRetention = 30 * 24 * time.Hour
	// integrationSeenRetention bounds the per-key identity memory.
	integrationSeenRetention = 7 * 24 * time.Hour
	// integrationMaxPerRun caps notifications per evaluation; the rest stay
	// pending and go out on the next runs.
	integrationMaxPerRun = 5
)

// IntegrationHTTPItem is the persisted state of one (scope, operation,
// resource) key.
type IntegrationHTTPItem struct {
	Scope     string `json:"scope"`
	Operation string `json:"operation"`
	PathHash  string `json:"path_hash"`
	// Pending is the number of integration errors not yet delivered;
	// PendingIDs holds their (hashed) request identities.
	Pending     int                  `json:"pending,omitempty"`
	PendingIDs  map[string]time.Time `json:"pending_ids,omitempty"`
	PendingLast time.Time            `json:"pending_last,omitempty"`
	// Seen remembers every error identity already counted (hashed request id ->
	// time) for integrationSeenRetention, so an error is counted exactly once
	// even when several errors share a timestamp second or the window slides.
	Seen map[string]time.Time `json:"seen,omitempty"`
	// SentThrough is the newest error time already delivered; older errors are
	// never counted again.
	SentThrough time.Time `json:"sent_through,omitempty"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
}

// integrationAgentDirs returns the agent event directories to read. Overridable
// in tests.
var integrationAgentDirs = func(cfg *config.AppConfig) []string {
	base := heartdesk.PathOrDefault("data/logs/agents")
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), "_") {
			out = append(out, filepath.Join(base, e.Name()))
		}
	}
	return out
}

func integrationKey(scope, op, hash string) string {
	sum := sha256.Sum256([]byte(scope + "|" + op + "|" + hash))
	return ruleIntegrationHTTPError + ":" + hex.EncodeToString(sum[:8])
}

type integrationErr struct {
	id string
	ts time.Time
}

type integrationObs struct {
	scope, op, hash string
	errs            []integrationErr
	successLast     time.Time
}

func evaluateIntegrationHTTPError(cfg *config.AppConfig, rules AlertRules, state *AlertState) []string {
	rule, defined := rules.Rules[ruleIntegrationHTTPError]
	if !defined || !rule.Enabled {
		return nil
	}
	th := int(rule.Threshold)
	if th <= 0 {
		th = integrationDefaultThreshold
	}
	cd := rule.CooldownSec
	if cd <= 0 {
		cd = integrationDefaultCooldown
	}
	now := nowFn()
	if state.IntegrationHTTP == nil {
		state.IntegrationHTTP = map[string]*IntegrationHTTPItem{}
	}

	// Observe: classification is recomputed over whatever is on disk now.
	cutoff := now.Add(-integrationLookback)
	obs := map[string]*integrationObs{}
	for _, dir := range integrationAgentDirs(cfg) {
		events, receipts := httpclassload.Load(
			filepath.Join(dir, httpclassload.RawFile), filepath.Join(dir, httpclassload.ReceiptFile),
			now, cutoff, parseAlertTimestamp,
			func(e httpclassload.Event) bool { return httpclassification.ValidRequestID(e.RequestID) })
		results := httpclassload.Classify(events, receipts)
		for i, e := range events {
			r := results[i]
			if r.Class != httpclassification.IntegrationError && r.Class != httpclassification.Success {
				continue
			}
			k := integrationKey(e.Scope, r.Operation, r.PathHash)
			o := obs[k]
			if o == nil {
				o = &integrationObs{scope: e.Scope, op: r.Operation, hash: r.PathHash}
				obs[k] = o
			}
			if r.Class == httpclassification.Success {
				if e.Time.After(o.successLast) {
					o.successLast = e.Time
				}
				continue
			}
			sum := sha256.Sum256([]byte(e.Scope + "|" + e.RequestID))
			o.errs = append(o.errs, integrationErr{id: hex.EncodeToString(sum[:12]), ts: e.Time})
		}
	}

	for k, o := range obs {
		item := state.IntegrationHTTP[k]
		if item == nil {
			if len(o.errs) == 0 {
				continue // success for a resource that never failed
			}
			item = &IntegrationHTTPItem{Scope: o.scope, Operation: o.op, PathHash: o.hash}
			state.IntegrationHTTP[k] = item
		}
		item.LastSeen = now
		if item.Seen == nil {
			item.Seen = map[string]time.Time{}
		}
		if item.PendingIDs == nil {
			item.PendingIDs = map[string]time.Time{}
		}
		for _, er := range o.errs {
			if _, dup := item.Seen[er.id]; dup {
				continue // already counted (delivered or pending)
			}
			item.Seen[er.id] = er.ts
			item.PendingIDs[er.id] = er.ts
			if er.ts.After(item.PendingLast) {
				item.PendingLast = er.ts
			}
		}
		item.Pending = len(item.PendingIDs)
	}

	keys := make([]string, 0, len(state.IntegrationHTTP))
	for k := range state.IntegrationHTTP {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []string
	notified := 0
	for _, k := range keys {
		item := state.IntegrationHTTP[k]
		if item.Pending >= th && notified < integrationMaxPerRun {
			snap := snapshotAlertKey(k, state)
			if shouldAlert(k, 0, cd, state, now) {
				msg := fmt.Sprintf("連携アプリのHTTPエラー: 操作=%s 対象(ハッシュ)=%s 送信元=%s 件数=%d 最終=%s",
					item.Operation, shortHash(item.PathHash), item.Scope, item.Pending,
					item.PendingLast.Format("2006-01-02 15:04:05"))
				if sent, ok := fireTracked(rules, ruleIntegrationHTTPError, k, state, snap, msg); ok {
					out = append(out, sent)
					item.SentThrough = item.PendingLast
					item.Pending = 0
					item.PendingIDs = map[string]time.Time{}
					state.Active[k] = true
				}
				notified++
			}
		}
		// Recovery: only a reliable success newer than the last error.
		if state.Active[k] && item.Pending == 0 {
			if o := obs[k]; o != nil && o.successLast.After(item.SentThrough) {
				recovered := true
				if rule.NotifyRecovery {
					msg, ok := fireDelivered(rules, ruleIntegrationHTTPError,
						fmt.Sprintf("連携アプリのHTTPエラーが解消しました: 操作=%s 対象(ハッシュ)=%s 送信元=%s",
							item.Operation, shortHash(item.PathHash), item.Scope))
					if ok {
						out = append(out, msg)
					} else {
						recovered = false
					}
				}
				if recovered {
					state.Active[k] = false
					// The episode is over: a later failure is a new episode and must
					// not be held back by the old episode's cooldown.
					delete(state.LastAlertTime, k)
				}
			}
		}
	}

	// Aggregate flag so the rule shows as firing while any key is.
	anyActive := false
	for k := range state.IntegrationHTTP {
		if state.Active[k] {
			anyActive = true
			break
		}
	}
	state.Active[ruleIntegrationHTTPError] = anyActive

	for k, item := range state.IntegrationHTTP {
		for id, ts := range item.Seen {
			if _, pending := item.PendingIDs[id]; !pending && now.Sub(ts) > integrationSeenRetention {
				delete(item.Seen, id)
			}
		}
		if item.Pending == 0 && !state.Active[k] && now.Sub(item.LastSeen) > integrationItemRetention {
			delete(state.IntegrationHTTP, k)
			delete(state.LastAlertTime, k)
			delete(state.Active, k)
		}
	}
	return out
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// parseAlertTimestamp accepts the RFC 3339 forms agents write.
func parseAlertTimestamp(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable timestamp")
}
