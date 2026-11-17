package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestThreatEventHistoryShowsExpectedAndIntegrationWithoutThreatPoints(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	dir := filepath.Join(base, "data/logs/agents/host-1")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var raw, receipts []byte
	for i, method := range []string{"MKCOL", "GET", "GET"} {
		path := "/nextcloud/remote.php/dav/files/service/file" + string(rune('a'+i))
		status := 404
		op := "fetch_file"
		outcome := "error"
		if i == 0 {
			status = 405
			op = "ensure_collection"
			outcome = "expected"
		}
		nonce := strings.Repeat(string(rune('a'+i)), 32)
		ts := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
		b, _ := json.Marshal(map[string]any{"ts": ts, "agent_id": "host-1", "request_id": nonce, "ip": "203.0.113.10", "method": method, "path": path, "status": status, "ua": "synthetic-client"})
		raw = append(raw, b...)
		raw = append(raw, '\n')
		if i != 2 {
			sum := sha256.Sum256([]byte(path))
			b, _ = json.Marshal(map[string]any{"ts": ts, "agent_id": "host-1", "source": "http_outcome", "request_id": nonce, "method": method, "path_hash": hex.EncodeToString(sum[:]), "status": status, "operation": op, "outcome": outcome})
			receipts = append(receipts, b...)
			receipts = append(receipts, '\n')
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "web_access.jsonl"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "http_outcome.jsonl"), receipts, 0600); err != nil {
		t.Fatal(err)
	}
	r := GetThreatEventHistory("203.0.113.10", "host-1")
	seen := map[string]int{}
	for _, event := range r.Events {
		seen[event.Category]++
		if !strings.Contains(event.Detail, "/nextcloud/") {
			t.Fatal("raw resource hidden", event)
		}
		if (event.Category == "正常" || event.Category == "連携エラー") && event.ScoreDelta != 0 {
			t.Fatal("attributed benign/operational result charged as threat", event)
		}
		if event.Category == "4XX" && event.ScoreDelta <= 0 {
			t.Fatal("unknown request no longer detected", event)
		}
	}
	if seen["正常"] != 1 || seen["連携エラー"] != 1 || seen["4XX"] != 1 {
		t.Fatal(seen)
	}
}
