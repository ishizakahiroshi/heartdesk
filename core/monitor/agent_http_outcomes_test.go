package monitor

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentHTTPOutcomeReceiptsPreserveCorrelationAndIndependentRequests(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	raw := json.RawMessage(`{"events":[{"ts":"2026-10-30T01:00:00Z","request_id":"nonce-1","method":"GET","path_hash":"abc","status":404,"operation":"fetch_file","outcome":"failed"},{"ts":"2026-10-30T01:00:00Z","request_id":"nonce-2","method":"GET","path_hash":"abc","status":404,"operation":"fetch_file","outcome":"failed"}]}`)
	rec := agentReportRecord{AgentID: "host-1", AgentType: "vps", Collectors: map[string]json.RawMessage{"http_outcome": raw}}
	if err := saveAgentEventStreams(rec); err != nil {
		t.Fatal(err)
	}
	if err := saveAgentEventStreams(rec); err != nil {
		t.Fatal(err)
	}
	lines := readJSONLLines(t, filepath.Join(base, "data/logs/agents/host-1/http_outcome.jsonl"))
	if len(lines) != 2 {
		t.Fatalf("want 2 independent receipts, got %d", len(lines))
	}
	for _, line := range lines {
		var event map[string]interface{}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event["source"] != "http_outcome" || event["method"] != "GET" || event["path_hash"] != "abc" || !strings.HasPrefix(eventString(event, "request_id"), "nonce-") {
			t.Fatal(event)
		}
	}
}

func TestIntegrationErrorRuleDefaults(t *testing.T) {
	d := AlertRuleDefs["integration_http_error"]
	if d.Label != "連携ファイル取得エラー" || d.DefaultThreshold != 1 || d.DefaultCooldownSec != 10800 || d.HasSustain {
		t.Fatal(d)
	}
	// UI load does not enable a rule merely because a definition exists.
	t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
	if LoadAlertRules(nil).Rules["integration_http_error"].Enabled {
		t.Fatal("new rule defaulted enabled")
	}
}
