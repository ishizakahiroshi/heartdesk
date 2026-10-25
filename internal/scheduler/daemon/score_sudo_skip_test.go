package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// イベントモード（AgentEventDir あり）では、旧経路（sudo grep・sudo fail2ban-client・
// honeypot ディレクトリ・nginx ログ）を呼ばず、イベント由来の値だけで入力を作る。
// 旧経路が呼ばれると、その関数の logLine（"agent " で始まらない）が出るので、それで検知する。
func TestCollectScoreInputsEventModeSkipsLegacy(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatalf("WriteFile(%s): %v", name, err)
		}
	}
	write("honeypot.jsonl", `{"ts":"2026-04-29T10:00:00+09:00","ip":"203.0.113.10","trigger":"backdoor"}`+"\n")
	write("web_access.jsonl", `{"ts":"2026-04-29T10:01:00+09:00","ip":"203.0.113.10","path":"/admin","status":401}`+"\n")
	write("nextcloud_login.jsonl", `{"ts":"2026-04-29T10:03:00+09:00","ip":"203.0.113.10","msg":"Login failed: user bob"}`+"\n")
	write("fail2ban.jsonl", `{"ts":"2026-04-29T10:04:00+09:00","event":"ban","ip":"203.0.113.10"}`+"\n")

	// 旧経路のパスには実在するファイルを置く。collectAuth401Counts のように、ファイルが無いと
	// ログを出さずに戻る関数があり、パスが存在しないと「呼ばれた」ことを検知できないため。
	// 旧経路にだけ存在する IP（198.51.100.7）が結果に混ざらないことも確かめる。
	legacyDir := filepath.Join(dir, "legacy")
	if err := os.MkdirAll(legacyDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	nginxLog := filepath.Join(legacyDir, "access.log")
	if err := os.WriteFile(nginxLog,
		[]byte(`198.51.100.7 - - [29/Apr/2026:10:00:00 +0900] "GET /admin HTTP/1.1" 401 0 "-" "-"`+"\n"), 0644); err != nil {
		t.Fatalf("WriteFile(access.log): %v", err)
	}
	paths := scorePaths{
		AgentEventDir:      dir,
		HoneypotDir:        legacyDir,
		NC4xxDir:           legacyDir,
		LoginEventsPath:    filepath.Join(legacyDir, "login_events.jsonl"),
		NextcloudLogPath:   filepath.Join(legacyDir, "nextcloud.log"),
		NginxAccessLogPath: nginxLog,
	}
	cutoff := time.Date(2026, 4, 29, 0, 0, 0, 0, time.FixedZone("JST", 9*60*60))
	var logged []string
	logLine := func(_ string, msg string) { logged = append(logged, msg) }

	in := collectScoreInputs(context.Background(), paths, cutoff, nil, logLine)

	if in.autobanEnabled {
		t.Fatalf("autobanEnabled = true, want false in event mode")
	}
	if in.scanHits["203.0.113.10"] != 1 || in.authFails["203.0.113.10"] != 1 || in.ncFails["203.0.113.10"] != 1 {
		t.Fatalf("event counts not read: scan=%v auth=%v nc=%v", in.scanHits, in.authFails, in.ncFails)
	}
	if _, ok := in.authFails["198.51.100.7"]; ok {
		t.Fatalf("legacy nginx log was read in event mode: authFails=%v", in.authFails)
	}
	if _, ok := in.banned["203.0.113.10"]; !ok {
		t.Fatalf("banned IP from fail2ban.jsonl not found: %v", in.banned)
	}
	if len(logged) == 0 {
		t.Fatalf("no log lines")
	}
	for _, msg := range logged {
		if msg == "agent event score input enabled; monitor-side autoban disabled" {
			continue
		}
		if !strings.HasPrefix(msg, "agent ") {
			t.Fatalf("legacy collector ran in event mode: %q (all: %v)", msg, logged)
		}
	}
}

func TestIpsetFound(t *testing.T) {
	notFound := func(string) (string, error) { return "", errors.New("not found") }
	found := func(string) (string, error) { return "/usr/sbin/ipset", nil }
	mustNotCall := func(string) (string, error) {
		t.Fatalf("lookPath must not be called for a path found by os.Stat")
		return "", nil
	}

	cases := []struct {
		name     string
		path     string
		lookPath func(string) (string, error)
		want     bool
	}{
		{"os.Stat で見つかった絶対パス", "/usr/sbin/ipset", mustNotCall, true},
		{"見つからず PATH にも無い", "ipset", notFound, false},
		{"見つからないが PATH にある", "ipset", found, true},
	}
	for _, c := range cases {
		if got := ipsetFound(c.path, c.lookPath); got != c.want {
			t.Errorf("%s: ipsetFound(%q) = %v, want %v", c.name, c.path, got, c.want)
		}
	}
}
