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
)

// IntegrationHTTPItem is the persisted state of one (scope, operation,
// resource) key.
type IntegrationHTTPItem struct {
	Scope     string `json:"scope"`
	Operation string `json:"operation"`
	PathHash  string `json:"path_hash"`
	// Pending is the number of integration errors not yet delivered.
	Pending     int       `json:"pending,omitempty"`
	PendingLast time.Time `json:"pending_last,omitempty"`
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

type integrationObs struct {
	scope, op, hash string
	errCount        int
	errLast         time.Time
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
			cutoff, parseAlertTimestamp,
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
			item := state.IntegrationHTTP[k]
			if item != nil && !e.Time.After(item.SentThrough) {
				continue // already delivered
			}
			o.errCount++
			if e.Time.After(o.errLast) {
				o.errLast = e.Time
			}
		}
	}

	for k, o := range obs {
		item := state.IntegrationHTTP[k]
		if item == nil {
			if o.errCount == 0 {
				continue // success for a resource that never failed
			}
			item = &IntegrationHTTPItem{Scope: o.scope, Operation: o.op, PathHash: o.hash}
			state.IntegrationHTTP[k] = item
		}
		item.LastSeen = now
		if o.errCount > item.Pending {
			item.Pending = o.errCount
		}
		if o.errLast.After(item.PendingLast) {
			item.PendingLast = o.errLast
		}
	}

	keys := make([]string, 0, len(state.IntegrationHTTP))
	for k := range state.IntegrationHTTP {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []string
	for _, k := range keys {
		item := state.IntegrationHTTP[k]
		if item.Pending >= th {
			snap := snapshotAlertKey(k, state)
			if shouldAlert(k, 0, cd, state, now) {
				msg := fmt.Sprintf("連携アプリのHTTPエラー: 操作=%s 対象(ハッシュ)=%s 送信元=%s 件数=%d 最終=%s",
					item.Operation, shortHash(item.PathHash), item.Scope, item.Pending,
					item.PendingLast.Format("2006-01-02 15:04:05"))
				if sent, ok := fireTracked(rules, ruleIntegrationHTTPError, k, state, snap, msg); ok {
					out = append(out, sent)
					item.SentThrough = item.PendingLast
					item.Pending = 0
					state.Active[k] = true
				}
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
