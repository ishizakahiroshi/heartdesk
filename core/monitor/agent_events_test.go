package monitor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSaveAgentEventStreamsNormalizesAndDedupes(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)

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

// nginxEventReport は dedupe_key と ts を指定した nginx イベント 1 件の報告を作る。
func nginxEventReport(t *testing.T, agentID, key string, ts time.Time) agentReportRecord {
	t.Helper()
	raw, err := json.Marshal(map[string]interface{}{
		"events": []map[string]interface{}{{
			"ts": ts.Format(time.RFC3339), "ip": "203.0.113.10", "method": "GET", "path": "/", "status": 200, "dedupe_key": key,
		}},
	})
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	return agentReportRecord{AgentID: agentID, AgentType: "vps", Collectors: map[string]json.RawMessage{"nginx": raw}}
}

// writeEventLines はイベント JSONL へ dedupe_key と ts だけの行を書き足す。
func writeEventLines(t *testing.T, path string, keyPrefix string, n int, ts time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for i := 0; i < n; i++ {
		fmt.Fprintf(w, `{"ts":%q,"dedupe_key":"%s-%d","path":"/padding-padding-padding-padding-padding-padding"}`+"\n", ts.Format(time.RFC3339), keyPrefix, i)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

// 報告のたびにファイル全体を読み直さないこと。ファイルの先頭にだけあるキーは、
// 重複確認の対象（直近 48 時間）の外なので、同じキーの報告は書き足される。
// 直す前のコード（毎回全行を読む）では先頭のキーを拾って書き足さないので、このテストは落ちる。
func TestSaveAgentEventStreamsDoesNotRescanWholeFile(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	now := time.Now()
	path := filepath.Join(base, "data/logs/agents/alpha-vps-main/web_access.jsonl")

	writeEventLines(t, path, "head", 1, now.Add(-time.Hour))                           // 先頭: 時刻だけ新しい行
	writeEventLines(t, path, "old", 3*agentEventSeedChunk/100, now.Add(-72*time.Hour)) // 約 3MiB の古い行
	writeEventLines(t, path, "tail", 1, now.Add(-time.Hour))                           // 末尾: 直近の行
	before := len(readJSONLLines(t, path))

	if err := saveAgentEventStreams(nginxEventReport(t, "alpha-vps-main", "head-0", now)); err != nil {
		t.Fatalf("saveAgentEventStreams: %v", err)
	}
	if got, want := len(readJSONLLines(t, path)), before+1; got != want {
		t.Fatalf("line count = %d, want %d (the whole file was scanned)", got, want)
	}
}

// 起動直後（キーの表が空）でも、ファイル末尾の直近の分とは重複しない。
func TestSaveAgentEventStreamsDedupesRecentHistoryAfterRestart(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	now := time.Now()
	path := filepath.Join(base, "data/logs/agents/alpha-vps-main/web_access.jsonl")

	writeEventLines(t, path, "old", 3*agentEventSeedChunk/100, now.Add(-72*time.Hour))
	writeEventLines(t, path, "tail", 3, now.Add(-time.Hour))
	before := len(readJSONLLines(t, path))

	if err := saveAgentEventStreams(nginxEventReport(t, "alpha-vps-main", "tail-1", now.Add(-time.Hour))); err != nil {
		t.Fatalf("saveAgentEventStreams: %v", err)
	}
	if got := len(readJSONLLines(t, path)); got != before {
		t.Fatalf("line count = %d, want %d (recent duplicate was written)", got, before)
	}
}

// 送り直しが重なって同じ報告が同時に届いても、1 回分しか書かない。
func TestSaveAgentEventStreamsConcurrentRetriesWriteOnce(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	rec := nginxEventReport(t, "alpha-vps-main", "retry-1", time.Now())

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- saveAgentEventStreams(rec)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("saveAgentEventStreams: %v", err)
		}
	}
	path := filepath.Join(base, "data/logs/agents/alpha-vps-main/web_access.jsonl")
	if got := len(readJSONLLines(t, path)); got != 1 {
		t.Fatalf("line count = %d, want 1", got)
	}
}

// 48 時間より前のキーは、1 時間に 1 回の掃除で表から消える。
func TestAgentEventDedupeIndexPrunesOldKeys(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	start := time.Date(2026, 10, 30, 0, 0, 0, 0, time.FixedZone("JST", 9*3600))
	now := start
	agentEventNow = func() time.Time { return now }
	t.Cleanup(func() { agentEventNow = time.Now })

	if err := saveAgentEventStreams(nginxEventReport(t, "alpha-vps-main", "first", start)); err != nil {
		t.Fatalf("save first: %v", err)
	}
	now = start.Add(agentEventDedupeWindow + 2*time.Hour)
	if err := saveAgentEventStreams(nginxEventReport(t, "alpha-vps-main", "second", now)); err != nil {
		t.Fatalf("save second: %v", err)
	}

	idx := agentEventIndexFor(filepath.Join(base, "data/logs/agents/alpha-vps-main/web_access.jsonl"))
	idx.mu.Lock()
	defer idx.mu.Unlock()
	if _, ok := idx.keys["first"]; ok {
		t.Fatalf("old key was not pruned")
	}
	if _, ok := idx.keys["second"]; !ok {
		t.Fatalf("new key is missing")
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
