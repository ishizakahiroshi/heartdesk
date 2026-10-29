package monitor

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/httpclassification"
	"github.com/ishizakahiroshi/heartdesk/internal/httpclassload"
)

// A report shaped exactly like heartpost's collectors: nginx CollectResult
// (events carry request_id from the trailing op= field) and the http_outcome
// CollectResult (new_events, dropped_invalid, jsonl_path, skipped, events).
func TestIngestCorrelatesHeartpostHTTPOutcomeWithNginxEvent(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)

	const id1 = "0123456789abcdef0123456789abcdef"
	const id2 = "fedcba9876543210fedcba9876543210"
	const p1 = "/nextcloud/remote.php/dav/files/alice/folder/"
	const p2 = "/nextcloud/remote.php/dav/files/alice/missing.txt"
	now := time.Now().UTC()
	ts := now.Format(time.RFC3339)
	nginxTS := now.In(time.FixedZone("JST", 9*3600)).Format(time.RFC3339)

	nginx := fmt.Sprintf(`{"new_events":3,"jsonl_path":"/var/lib/heartpost/logs/nginx.jsonl","events":[
		{"ts":%q,"ip":"203.0.113.40","method":"MKCOL","path":%q,"status":405,"bytes":0,"ua":"x","referer":"","resp_ms":3,"request_id":%q},
		{"ts":%q,"ip":"203.0.113.40","method":"GET","path":%q,"status":404,"bytes":0,"ua":"x","referer":"","resp_ms":3,"request_id":%q},
		{"ts":%q,"ip":"203.0.113.41","method":"MKCOL","path":%q,"status":405,"bytes":0,"ua":"x","referer":"","resp_ms":3}
	]}`, nginxTS, p1, id1, nginxTS, p2, id2, nginxTS, p1)
	outcome := fmt.Sprintf(`{"new_events":2,"dropped_invalid":1,"jsonl_path":"/var/lib/heartpost/logs/http_outcome.jsonl",
		"skipped":[{"path":"/var/log/x.jsonl","reason":"file does not exist"}],
		"events":[
		{"ts":%q,"request_id":%q,"method":"MKCOL","path_hash":%q,"status":405,"operation":"ensure_collection","outcome":"expected"},
		{"ts":%q,"request_id":%q,"method":"GET","path_hash":%q,"status":404,"operation":"fetch_file","outcome":"integration_error"}
	]}`, ts, id1, httpclassification.PathHash(p1), ts, id2, httpclassification.PathHash(p2))

	rec := agentReportRecord{
		AgentID: "alpha-vps-main", AgentType: "vps",
		Collectors: map[string]json.RawMessage{"nginx": json.RawMessage(nginx), "http_outcome": json.RawMessage(outcome)},
	}
	for i := 0; i < 2; i++ { // heartpost may re-send old receipts after a rotation
		if err := saveAgentEventStreams(rec); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(base, "data/logs/agents/alpha-vps-main")
	if n := len(readJSONLLines(t, filepath.Join(dir, "http_outcome.jsonl"))); n != 2 {
		t.Fatalf("receipt lines after re-send = %d, want 2", n)
	}

	cutoff := now.Add(-time.Hour)
	parse := func(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }
	events, receipts := httpclassload.Load(filepath.Join(dir, "web_access.jsonl"), filepath.Join(dir, "http_outcome.jsonl"), now, cutoff, parse, nil)
	if len(events) != 3 || len(receipts) != 2 {
		t.Fatalf("events=%d receipts=%d", len(events), len(receipts))
	}
	got := map[string]httpclassification.Class{}
	for i, r := range httpclassload.Classify(events, receipts) {
		got[fmt.Sprintf("%s|%s", events[i].IP, events[i].Method)] = r.Class
	}
	if got["203.0.113.40|MKCOL"] != httpclassification.Expected ||
		got["203.0.113.40|GET"] != httpclassification.IntegrationError ||
		got["203.0.113.41|MKCOL"] != httpclassification.Unclassified {
		t.Fatalf("classification = %v", got)
	}

	// A conflicting receipt with an already used request id makes it ambiguous.
	bad := fmt.Sprintf(`{"events":[{"ts":%q,"request_id":%q,"method":"MKCOL","path_hash":%q,"status":405,"operation":"ensure_collection","outcome":"expected"}]}`,
		ts, id1, httpclassification.PathHash("/other"))
	if err := saveAgentEventStreams(agentReportRecord{AgentID: "alpha-vps-main", AgentType: "vps",
		Collectors: map[string]json.RawMessage{"http_outcome": json.RawMessage(bad)}}); err != nil {
		t.Fatal(err)
	}
	events, receipts = httpclassload.Load(filepath.Join(dir, "web_access.jsonl"), filepath.Join(dir, "http_outcome.jsonl"), now, cutoff, parse, nil)
	for i, r := range httpclassload.Classify(events, receipts) {
		if events[i].RequestID == id1 && r.Class != httpclassification.Unclassified {
			t.Fatalf("conflicting duplicate must disable the match: %v", r.Class)
		}
	}
}
