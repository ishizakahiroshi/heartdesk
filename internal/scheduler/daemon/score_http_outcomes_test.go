package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/httpevents"
)

func TestScoreHTTPOutcomesKeepUnknownAndAuthenticationFailures(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "host-1")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	var raws, receipts []byte
	add := func(nonce, method, path string, status int, operation, outcome string) {
		id := strings.Repeat(nonce, 32)
		ts := now.Add(-time.Minute).Format(time.RFC3339)
		b, _ := json.Marshal(map[string]any{"ts": ts, "agent_id": "host-1", "request_id": id, "method": method, "path": path, "status": status, "ip": "203.0.113.10"})
		raws = append(raws, b...)
		raws = append(raws, '\n')
		if operation != "" {
			sum := sha256.Sum256([]byte(path))
			b, _ = json.Marshal(map[string]any{"ts": ts, "agent_id": "host-1", "source": "http_outcome", "request_id": id, "method": method, "path_hash": hex.EncodeToString(sum[:]), "status": status, "operation": operation, "outcome": outcome})
			receipts = append(receipts, b...)
			receipts = append(receipts, '\n')
		}
	}
	add("a", "MKCOL", "/nextcloud/remote.php/dav/files/service/folder", 405, "ensure_collection", "expected")
	add("b", "PROPFIND", "/nextcloud/remote.php/dav/files/service/missing", 404, "path_exists", "expected")
	add("c", "GET", "/nextcloud/remote.php/dav/files/service/file", 404, "fetch_file", "error")
	add("d", "GET", "/nextcloud/unknown", 404, "", "")
	add("e", "GET", "/nextcloud/private", 401, "", "")
	if err := os.WriteFile(filepath.Join(dir, "web_access.jsonl"), raws, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "http_outcome.jsonl"), receipts, 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := httpevents.Load(context.Background(), filepath.Join(dir, "web_access.jsonl"), now, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got := classifiedNC4xxCounts(rows)["203.0.113.10"]; got != 2 {
		t.Fatalf("want unknown 404 + auth401, got %d", got)
	}
	if got := collectNC4xxEventCounts(context.Background(), filepath.Join(dir, "web_access.jsonl"), now.Add(-24*time.Hour), func(string, string) {})["203.0.113.10"]; got != 2 {
		t.Fatal("legacy helper differs", got)
	}
	snapshot := httpevents.Snapshot(rows, now)
	if len(snapshot.Resources) != 1 || snapshot.Resources[0].Count != 1 || len(snapshot.Resources[0].Events) != 1 {
		t.Fatal(snapshot)
	}
}
