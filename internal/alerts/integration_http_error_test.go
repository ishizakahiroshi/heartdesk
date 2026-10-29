package alerts

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/httpclassification"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

const (
	ihID1  = "00000000000000000000000000000011"
	ihID2  = "00000000000000000000000000000012"
	ihID3  = "00000000000000000000000000000013"
	ihPath = "/nextcloud/remote.php/dav/files/alice/report.txt"
)

type ihEnv struct {
	t   *testing.T
	dir string
	now time.Time
	msg []string
	ok  bool
}

func newIHEnv(t *testing.T) *ihEnv {
	t.Helper()
	e := &ihEnv{t: t, dir: filepath.Join(t.TempDir(), "agent-a"), now: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC), ok: true}
	if err := os.MkdirAll(e.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	origDirs, origNow, origSender := integrationAgentDirs, nowFn, sender
	integrationAgentDirs = func(_ *config.AppConfig) []string { return []string{e.dir} }
	nowFn = func() time.Time { return e.now }
	sender = func(_ AlertRules, _, message string) bool {
		if e.ok {
			e.msg = append(e.msg, message)
		}
		return e.ok
	}
	t.Cleanup(func() { integrationAgentDirs, nowFn, sender = origDirs, origNow, origSender })
	return e
}

func (e *ihEnv) append(name, line string) {
	e.t.Helper()
	f, err := os.OpenFile(filepath.Join(e.dir, name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		e.t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		e.t.Fatal(err)
	}
}

// pair writes a raw event and its receipt (ts offsets are relative to now).
func (e *ihEnv) pair(id, method string, status int, op, outcome string, ago time.Duration, path string) {
	ts := e.now.Add(-ago).Format(time.RFC3339)
	e.append("web_access.jsonl", fmt.Sprintf(`{"ts":%q,"ip":"203.0.113.30","agent_id":"agent-a","request_id":%q,"method":%q,"path":%q,"status":%d}`, ts, id, method, path, status))
	e.append("integration_receipt.jsonl", fmt.Sprintf(`{"ts":%q,"agent_id":"agent-a","request_id":%q,"method":%q,"path_hash":%q,"status":%d,"operation":%q,"outcome":%q}`,
		ts, id, method, httpclassification.PathHash(path), status, op, outcome))
}

func (e *ihEnv) run(rule AlertRule, st *AlertState) []string {
	e.t.Helper()
	rules := AlertRules{Rules: map[string]AlertRule{ruleIntegrationHTTPError: rule}}
	return evaluateIntegrationHTTPError(nil, rules, st)
}

var ihRule = AlertRule{Enabled: true, Threshold: 1, CooldownSec: 10800}

func TestIntegrationHTTPErrorDisabledByDefault(t *testing.T) {
	e := newIHEnv(t)
	e.pair(ihID1, "GET", 404, "fetch_file", "integration_error", time.Minute, ihPath)
	st := newAlertState()
	if out := e.run(AlertRule{}, st); len(out) != 0 || len(e.msg) != 0 {
		t.Fatalf("disabled rule must not fire: %v", out)
	}
	if len(st.IntegrationHTTP) != 0 {
		t.Fatal("disabled rule must not touch state")
	}
}

func TestIntegrationHTTPErrorFiresOncePerKeyWithCooldown(t *testing.T) {
	e := newIHEnv(t)
	e.pair(ihID1, "GET", 404, "fetch_file", "integration_error", time.Minute, ihPath)
	e.pair(ihID2, "GET", 404, "preview_file", "integration_error", time.Minute, ihPath) // same resource, other operation
	st := newAlertState()
	if out := e.run(ihRule, st); len(out) != 2 {
		t.Fatalf("want 2 notifications (one per operation), got %v", out)
	}
	if strings.Contains(strings.Join(e.msg, "\n"), "report.txt") {
		t.Fatal("message must not contain the raw path")
	}
	// Same data again: nothing new.
	if out := e.run(ihRule, st); len(out) != 0 {
		t.Fatalf("already delivered: %v", out)
	}
	// A new error on the same key inside cooldown is held, then sent after it.
	e.now = e.now.Add(time.Hour)
	e.pair(ihID3, "GET", 404, "fetch_file", "integration_error", time.Minute, ihPath)
	if out := e.run(ihRule, st); len(out) != 0 {
		t.Fatalf("inside cooldown: %v", out)
	}
	e.now = e.now.Add(3 * time.Hour)
	if out := e.run(ihRule, st); len(out) != 1 {
		t.Fatalf("after cooldown the held item must be sent: %v", out)
	}
}

func TestIntegrationHTTPErrorFailedSendKeepsPendingAndCooldown(t *testing.T) {
	e := newIHEnv(t)
	e.pair(ihID1, "GET", 404, "fetch_file", "integration_error", time.Minute, ihPath)
	st := newAlertState()
	e.ok = false
	if out := e.run(ihRule, st); len(out) != 0 {
		t.Fatalf("failed send must not report: %v", out)
	}
	var k string
	for key, it := range st.IntegrationHTTP {
		k = key
		if it.Pending != 1 || !it.SentThrough.IsZero() {
			t.Fatalf("pending must persist, sent counters unchanged: %+v", it)
		}
	}
	if _, ok := st.LastAlertTime[k]; ok || st.Active[k] {
		t.Fatal("cooldown / active must not advance on failure")
	}
	// Retry on the next evaluation, even if the files no longer hold the event.
	if err := os.Remove(filepath.Join(e.dir, "web_access.jsonl")); err != nil {
		t.Fatal(err)
	}
	e.ok = true
	if out := e.run(ihRule, st); len(out) != 1 {
		t.Fatalf("pending item must be retried from state: %v", out)
	}
}

func TestIntegrationHTTPErrorExpectedAndUnmatchedDoNotAlert(t *testing.T) {
	e := newIHEnv(t)
	e.pair(ihID1, "MKCOL", 405, "ensure_collection", "expected", time.Minute, ihPath)
	e.pair(ihID2, "PROPFIND", 404, "path_exists", "expected", time.Minute, ihPath)
	// raw 404 with no receipt: this is the threat score's business, not ours.
	e.append("web_access.jsonl", fmt.Sprintf(`{"ts":%q,"agent_id":"agent-a","request_id":%q,"method":"GET","path":%q,"status":404}`, e.now.Format(time.RFC3339), ihID3, ihPath))
	st := newAlertState()
	if out := e.run(ihRule, st); len(out) != 0 {
		t.Fatalf("%v", out)
	}
}

func TestIntegrationHTTPErrorRecoveryNeedsReliableSuccess(t *testing.T) {
	e := newIHEnv(t)
	rule := ihRule
	rule.NotifyRecovery = true
	e.pair(ihID1, "GET", 404, "fetch_file", "integration_error", 10*time.Minute, ihPath)
	st := newAlertState()
	if out := e.run(rule, st); len(out) != 1 {
		t.Fatal(out)
	}
	if !st.Active[ruleIntegrationHTTPError] {
		t.Fatal("aggregate flag must be set while a key is active")
	}
	// A raw 200 without a receipt is not reliable.
	e.append("web_access.jsonl", fmt.Sprintf(`{"ts":%q,"agent_id":"agent-a","request_id":%q,"method":"GET","path":%q,"status":200}`, e.now.Format(time.RFC3339), ihID2, ihPath))
	if out := e.run(rule, st); len(out) != 0 {
		t.Fatalf("unreliable success must not recover: %v", out)
	}
	// A success for a different resource does not recover this one.
	e.pair(ihID3, "GET", 200, "fetch_file", "success", time.Minute, "/nextcloud/other.txt")
	if out := e.run(rule, st); len(out) != 0 {
		t.Fatalf("other resource: %v", out)
	}
	// A reliable success for the same resource and operation does.
	id4 := "00000000000000000000000000000014"
	e.pair(id4, "GET", 200, "fetch_file", "success", time.Minute, ihPath)
	e.ok = false
	if out := e.run(rule, st); len(out) != 0 {
		t.Fatalf("failed recovery send must stay active: %v", out)
	}
	e.ok = true
	out := e.run(rule, st)
	if len(out) != 1 || !strings.Contains(out[0], "解消") {
		t.Fatalf("recovery: %v", out)
	}
	if st.Active[ruleIntegrationHTTPError] {
		t.Fatal("aggregate flag must clear")
	}
}
