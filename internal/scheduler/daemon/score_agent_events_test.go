package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectAgentEventScoreInputs(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatalf("WriteFile(%s): %v", name, err)
		}
		return path
	}
	cutoff := time.Date(2026, 4, 29, 0, 0, 0, 0, time.FixedZone("JST", 9*60*60))
	logLine := func(string, string) {}
	ctx := context.Background()

	hpPath := write("honeypot.jsonl", `{"ts":"2026-04-29T10:00:00+09:00","ip":"203.0.113.10","trigger":"backdoor"}`+"\n")
	webPath := write("web_access.jsonl",
		`{"ts":"2026-04-29T10:01:00+09:00","ip":"203.0.113.10","path":"/admin","status":401}`+"\n"+
			`{"ts":"2026-04-29T10:02:00+09:00","ip":"203.0.113.10","path":"/nextcloud/status.php","status":404}`+"\n")
	ncPath := write("nextcloud_login.jsonl", `{"ts":"2026-04-29T10:03:00+09:00","ip":"203.0.113.10","msg":"Login failed: user bob"}`+"\n")
	f2bPath := write("fail2ban.jsonl", `{"ts":"2026-04-29T10:04:00+09:00","event":"ban","ip":"203.0.113.10"}`+"\n")

	scanHits, scanCrit := collectHoneypotEventCounts(ctx, hpPath, cutoff, logLine)
	if scanHits["203.0.113.10"] != 1 || scanCrit["203.0.113.10"] != 1 {
		t.Fatalf("honeypot counts = hits=%v crit=%v", scanHits, scanCrit)
	}
	if got := collectAuth401EventCounts(ctx, webPath, cutoff, logLine)["203.0.113.10"]; got != 1 {
		t.Fatalf("auth401 count = %d, want 1", got)
	}
	if got := collectNC4xxEventCounts(ctx, webPath, cutoff, logLine)["203.0.113.10"]; got != 1 {
		t.Fatalf("nc4xx count = %d, want 1", got)
	}
	if got := collectNCFailEventCounts(ctx, ncPath, cutoff, nil, logLine)["203.0.113.10"]; got != 1 {
		t.Fatalf("nc fail count = %d, want 1", got)
	}
	if _, ok := collectBannedIPsFromEvents(ctx, f2bPath, cutoff, logLine)["203.0.113.10"]; !ok {
		t.Fatalf("banned IP not found")
	}
}
