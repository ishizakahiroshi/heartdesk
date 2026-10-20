package monitor

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGetSearchIPUsesAgentEventJSONL(t *testing.T) {
	base := t.TempDir()
	t.Setenv("SAB_BASE_DIR", base)

	dir := filepath.Join(base, "data", "logs", "agents", "alpha-vps-host1")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatalf("WriteFile(%s): %v", name, err)
		}
	}
	// GetSearchIP は Agent 指定時、ハニーポットだけ「直近 3 か月」で足切りする（search_ip.go の
	// now.AddDate(0, -3, 0)）。固定日付を埋めるとその日を過ぎた時点でハニーポットだけ結果から
	// 消えて必ず落ちるため、相対日付で書く。
	evBase := time.Now().Add(-24 * time.Hour)
	ts := func(offset time.Duration) string { return evBase.Add(offset).Format(time.RFC3339) }

	write("honeypot.jsonl", `{"schema":"honeypot.v1","ts":"`+ts(0)+`","ip":"203.0.113.10","method":"GET","path":"/.env","query":"","trigger":"dotfile","headers":{"user-agent":"curl/8.0"},"dedupe_key":"hp1"}`+"\n")
	write("web_access.jsonl", `{"ts":"`+ts(time.Minute)+`","ip":"203.0.113.10","method":"GET","path":"/nextcloud/status.php","status":404,"bytes":10,"ua":"curl","referer":"","resp_ms":1}`+"\n")
	write("fail2ban.jsonl", `{"ts":"`+ts(2*time.Minute)+`","event":"ban","jail":"recidive","ip":"203.0.113.10"}`+"\n")

	got := GetSearchIP("203.0.113.10", "alpha-vps-host1")
	if got.Count < 3 {
		t.Fatalf("Count = %d, want at least 3; results=%+v", got.Count, got.Results)
	}
	assertHasType := func(want string) {
		t.Helper()
		for _, r := range got.Results {
			if r.Type == want {
				return
			}
		}
		t.Fatalf("missing result type %q in %+v", want, got.Results)
	}
	assertHasType("ハニーポット(dotfile)")
	assertHasType("Nginx (404)")
	assertHasType("NC 4xx (404)")
	assertHasType("fail2ban BAN")
}
