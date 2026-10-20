package monitor

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAgentEventStreamsNormalizesAndDedupes(t *testing.T) {
	base := t.TempDir()
	t.Setenv("SAB_BASE_DIR", base)

	raw := json.RawMessage(`{
		"new_events": 2,
		"events": [
			{"ts":"2026-04-23T10:00:00+09:00","ip":"203.0.113.10","method":"GET","path":"/","status":200,"bytes":123,"ua":"curl","referer":"","resp_ms":-1},
			{"ts":"2026-04-23T10:00:00+09:00","ip":"203.0.113.10","method":"GET","path":"/","status":200,"bytes":123,"ua":"curl","referer":"","resp_ms":-1}
		]
	}`)
	rec := agentReportRecord{
		AgentID:   "alpha-rental-main",
		AgentType: "rental",
		Collectors: map[string]json.RawMessage{
			"apache_log": raw,
		},
	}

	if err := saveAgentEventStreams(rec); err != nil {
		t.Fatalf("saveAgentEventStreams: %v", err)
	}
	if err := saveAgentEventStreams(rec); err != nil {
		t.Fatalf("second saveAgentEventStreams: %v", err)
	}

	path := filepath.Join(base, "data/logs/agents/alpha-rental-main/web_access.jsonl")
	lines := readJSONLLines(t, path)
	if got, want := len(lines), 1; got != want {
		t.Fatalf("line count = %d, want %d", got, want)
	}

	var event map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatalf("unmarshal saved event: %v", err)
	}
	if event["agent_id"] != "alpha-rental-main" {
		t.Fatalf("agent_id = %v", event["agent_id"])
	}
	if event["agent_type"] != "rental" {
		t.Fatalf("agent_type = %v", event["agent_type"])
	}
	if event["source"] != "apache" {
		t.Fatalf("source = %v", event["source"])
	}
	if event["dedupe_key"] == "" {
		t.Fatalf("dedupe_key is empty")
	}
}

func TestNormalizeNextcloudAuditEventKind(t *testing.T) {
	rec := agentReportRecord{AgentID: "alpha-vps-main", AgentType: "vps"}
	event, kind, ok := normalizeAgentEvent(rec, "nextcloud", map[string]interface{}{
		"ts":     "2026-04-23T10:00:00+09:00",
		"source": "audit",
		"ip":     "203.0.113.20",
		"msg":    "Login failed",
	})
	if !ok {
		t.Fatalf("normalizeAgentEvent returned ok=false")
	}
	if kind != "audit" {
		t.Fatalf("kind = %q, want audit", kind)
	}
	if event["source"] != "audit" {
		t.Fatalf("source = %v", event["source"])
	}
	if event["agent_id"] != "alpha-vps-main" {
		t.Fatalf("agent_id = %v", event["agent_id"])
	}
}

func readJSONLLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return out
}
