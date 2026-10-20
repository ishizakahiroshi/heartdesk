package alerts

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// ncTestEnv は SAB_BASE_DIR を一時ディレクトリへ向け、ncSources() が読む
// パス構造（data/logs/nextcloud.jsonl / data/logs/agents/<id>/*.jsonl）を再現する。
func ncTestEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SAB_BASE_DIR", dir)
	return dir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

func ncCreatedLine(ts, uid string) string {
	return `{"ts":"` + ts + `","source":"audit","user":"","msg":"User created: \"` + uid + `\""}` + "\n"
}

func ncLoginSuccessLine(ts, uid string) string {
	return `{"ts":"` + ts + `","source":"app","user":"` + uid + `","msg":"Login successful: \"` + uid + `\""}` + "\n"
}

func enabledNCRules() AlertRules {
	return AlertRules{Rules: map[string]AlertRule{
		ruleNCUserCreated:    {Enabled: true},
		ruleNCUserFirstLogin: {Enabled: true},
	}}
}

func TestEvaluateNCUserEvents_FirstRunSkipsBacklogThenFires(t *testing.T) {
	dir := ncTestEnv(t)
	now := time.Date(2026, 5, 31, 9, 10, 0, 0, time.UTC)
	captured := withStubs(t, now, nil)

	localPath := filepath.Join(dir, "data/logs/nextcloud.jsonl")
	// 既に溜まっている過去分（Monitor が今回はじめてこのファイルを見るケース）。
	writeFile(t, localPath, ncCreatedLine("2026-01-01T09:00:00+09:00", "oldstaff"))

	cfg := &config.AppConfig{}
	cfg.VendorLicense.TenantID = "alpha"
	rules := enabledNCRules()
	state := newAlertState()

	got := evaluateNCUserEvents(cfg, rules, state)
	if len(got) != 0 {
		t.Fatalf("first run must not fire for pre-existing backlog, got %v", got)
	}
	if len(*captured) != 0 {
		t.Fatalf("sender must not be called on first run, got %v", *captured)
	}
	fi, err := os.Stat(localPath)
	if err != nil {
		t.Fatal(err)
	}
	if state.Offsets[localPath] != fi.Size() {
		t.Fatalf("offset should be fast-forwarded to EOF on first run: got %d want %d", state.Offsets[localPath], fi.Size())
	}
	if len(state.PendingNCUsers) != 0 {
		t.Fatalf("first-run backlog must not register pending first-login tracking, got %v", state.PendingNCUsers)
	}

	// 2 回目: 新規に追記された分だけを見る。
	appendFile(t, localPath, ncCreatedLine("2026-05-31T09:05:00+09:00", "newstaff"))
	got2 := evaluateNCUserEvents(cfg, rules, state)
	if len(got2) != 1 {
		t.Fatalf("expected 1 created alert, got %d: %v", len(got2), got2)
	}
	if !contains(got2[0], "newstaff") || !contains(got2[0], "alpha") {
		t.Fatalf("message should mention uid and tenant id, got %q", got2[0])
	}
	if _, pending := state.PendingNCUsers["local|newstaff"]; !pending {
		t.Fatalf("created user should be tracked pending first login")
	}
	if len(*captured) != 1 {
		t.Fatalf("sender should fire once, got %v", *captured)
	}
}

func TestEvaluateNCUserEvents_FirstLoginAcrossEvaluations(t *testing.T) {
	dir := ncTestEnv(t)
	now := time.Date(2026, 5, 31, 9, 0, 0, 0, time.UTC)
	captured := withStubs(t, now, nil)

	localPath := filepath.Join(dir, "data/logs/nextcloud.jsonl")
	writeFile(t, localPath, "")

	cfg := &config.AppConfig{}
	rules := enabledNCRules()
	state := newAlertState()

	// 初回評価（空ファイル。offset だけ確立）。
	if got := evaluateNCUserEvents(cfg, rules, state); len(got) != 0 {
		t.Fatalf("expected no alerts on empty first run, got %v", got)
	}

	// 作成イベントだけを追記 → created が発報し、pending に載る。
	appendFile(t, localPath, ncCreatedLine("2026-05-31T09:00:00+09:00", "alice"))
	got := evaluateNCUserEvents(cfg, rules, state)
	if len(got) != 1 || !contains(got[0], "alice") {
		t.Fatalf("expected 1 created alert for alice, got %v", got)
	}

	// 別評価タイミングでログイン成功が来る → 初回ログインとして発報。
	nowFn = fixedNow(now.Add(10 * time.Minute))
	appendFile(t, localPath, ncLoginSuccessLine("2026-05-31T09:10:00+09:00", "alice"))
	got2 := evaluateNCUserEvents(cfg, rules, state)
	if len(got2) != 1 || !contains(got2[0], "alice") {
		t.Fatalf("expected 1 first-login alert for alice, got %v", got2)
	}
	if _, pending := state.PendingNCUsers["local|alice"]; pending {
		t.Fatalf("alice should be consumed from pending after first login")
	}

	// 2 回目のログインは初回ログインとして再発報されない。
	nowFn = fixedNow(now.Add(20 * time.Minute))
	appendFile(t, localPath, ncLoginSuccessLine("2026-05-31T09:20:00+09:00", "alice"))
	got3 := evaluateNCUserEvents(cfg, rules, state)
	if len(got3) != 0 {
		t.Fatalf("second login must not fire first-login alert again, got %v", got3)
	}

	if len(*captured) != 2 {
		t.Fatalf("sender should have fired twice (created + first login), got %v", *captured)
	}
}

func TestEvaluateNCUserEvents_AgentSplitFilesAndCapabilityFilter(t *testing.T) {
	dir := ncTestEnv(t)
	now := time.Date(2026, 5, 31, 9, 0, 0, 0, time.UTC)
	withStubs(t, now, nil)

	const ncAgent = "alpha-vps-host1"
	const otherAgent = "beta-rental-host2"

	auditPath := filepath.Join(dir, "data/logs/agents", ncAgent, "audit.jsonl")
	loginPath := filepath.Join(dir, "data/logs/agents", ncAgent, "nextcloud_login.jsonl")
	writeFile(t, auditPath, "")
	writeFile(t, loginPath, "")

	cfg := &config.AppConfig{}
	cfg.Agents = map[string]config.AgentConfig{
		ncAgent:    {AgentType: "vps", Capabilities: []string{"module.nextcloud"}},
		otherAgent: {AgentType: "rental"}, // module.nextcloud 無し → 対象外
	}
	rules := enabledNCRules()
	state := newAlertState()

	// 初回評価（空ファイルで offset 確立）。
	if got := evaluateNCUserEvents(cfg, rules, state); len(got) != 0 {
		t.Fatalf("expected no alerts on empty first run, got %v", got)
	}
	if _, ok := state.Offsets[auditPath]; !ok {
		t.Fatalf("audit.jsonl offset should be tracked for nextcloud-capable agent")
	}
	if _, ok := state.Offsets[loginPath]; !ok {
		t.Fatalf("nextcloud_login.jsonl offset should be tracked for nextcloud-capable agent")
	}
	otherAuditPath := filepath.Join(dir, "data/logs/agents", otherAgent, "audit.jsonl")
	if _, ok := state.Offsets[otherAuditPath]; ok {
		t.Fatalf("agent without module.nextcloud capability must not be scanned")
	}

	// audit.jsonl だけへ作成イベントを追記。
	appendFile(t, auditPath, ncCreatedLine("2026-05-31T09:05:00+09:00", "bob"))
	got := evaluateNCUserEvents(cfg, rules, state)
	if len(got) != 1 || !contains(got[0], "bob") || !contains(got[0], ncAgent) {
		t.Fatalf("expected created alert for bob mentioning agent id, got %v", got)
	}

	// nextcloud_login.jsonl だけへログイン成功を追記（audit.jsonl には触れない）。
	appendFile(t, loginPath, ncLoginSuccessLine("2026-05-31T09:10:00+09:00", "bob"))
	got2 := evaluateNCUserEvents(cfg, rules, state)
	if len(got2) != 1 || !contains(got2[0], "bob") || !contains(got2[0], ncAgent) {
		t.Fatalf("expected first-login alert for bob mentioning agent id, got %v", got2)
	}
}

func TestEvaluateNCUserEvents_DisabledCreatedRuleStillTracksPending(t *testing.T) {
	dir := ncTestEnv(t)
	now := time.Date(2026, 5, 31, 9, 0, 0, 0, time.UTC)
	captured := withStubs(t, now, nil)

	localPath := filepath.Join(dir, "data/logs/nextcloud.jsonl")
	writeFile(t, localPath, "")

	cfg := &config.AppConfig{}
	rules := AlertRules{Rules: map[string]AlertRule{
		ruleNCUserCreated:    {Enabled: false},
		ruleNCUserFirstLogin: {Enabled: true},
	}}
	state := newAlertState()

	if got := evaluateNCUserEvents(cfg, rules, state); len(got) != 0 {
		t.Fatalf("expected no alerts on empty first run, got %v", got)
	}

	appendFile(t, localPath, ncCreatedLine("2026-05-31T09:05:00+09:00", "carol"))
	got := evaluateNCUserEvents(cfg, rules, state)
	if len(got) != 0 {
		t.Fatalf("created rule disabled must not fire, got %v", got)
	}
	if _, pending := state.PendingNCUsers["local|carol"]; !pending {
		t.Fatalf("pending tracking must continue even when created rule is disabled")
	}

	appendFile(t, localPath, ncLoginSuccessLine("2026-05-31T09:10:00+09:00", "carol"))
	got2 := evaluateNCUserEvents(cfg, rules, state)
	if len(got2) != 1 || !contains(got2[0], "carol") {
		t.Fatalf("first-login rule enabled should still fire once created was tracked, got %v", got2)
	}
	if len(*captured) != 1 {
		t.Fatalf("sender should fire exactly once (first login only), got %v", *captured)
	}
}

func TestEvaluateNCUserEvents_PendingUserTTLExpires(t *testing.T) {
	dir := ncTestEnv(t)
	now := time.Date(2026, 5, 31, 9, 0, 0, 0, time.UTC)
	withStubs(t, now, nil)

	localPath := filepath.Join(dir, "data/logs/nextcloud.jsonl")
	writeFile(t, localPath, "")

	cfg := &config.AppConfig{}
	rules := enabledNCRules()
	state := newAlertState()

	if got := evaluateNCUserEvents(cfg, rules, state); len(got) != 0 {
		t.Fatalf("expected no alerts on empty first run, got %v", got)
	}

	appendFile(t, localPath, ncCreatedLine("2026-05-31T09:05:00+09:00", "dave"))
	if got := evaluateNCUserEvents(cfg, rules, state); len(got) != 1 {
		t.Fatalf("expected 1 created alert, got %v", got)
	}
	if _, pending := state.PendingNCUsers["local|dave"]; !pending {
		t.Fatalf("dave should be pending right after creation")
	}

	// TTL を超えて未ログインのまま経過 → pending から破棄される。
	nowFn = fixedNow(now.Add(ncPendingUserTTL + time.Hour))
	if got := evaluateNCUserEvents(cfg, rules, state); len(got) != 0 {
		t.Fatalf("expected no alerts on TTL sweep run, got %v", got)
	}
	if _, pending := state.PendingNCUsers["local|dave"]; pending {
		t.Fatalf("dave should have been evicted from pending after TTL")
	}
}

func TestNcAgentJSONLPath_RejectsInvalidOrTraversalID(t *testing.T) {
	ncTestEnv(t)
	cases := []string{
		"",
		"../../etc/passwd",
		"alpha-vps-../../escape",
		"not_an_agent_id",
		"T101-VPS-UPPER",
		"alpha-VPS-host1",
		"alpha-vps host1",
		"alpha",
		"alpha-",
		"-vps-host1",
		"alpha-vps\nhost1",
	}
	for _, id := range cases {
		if _, ok := ncAgentJSONLPath(id, "audit"); ok {
			t.Fatalf("expected rejection for invalid agent id %q", id)
		}
	}
	for _, id := range []string{"alpha-vps-host3", "t101-vps-host1", "tenant_b-rental-host-2", "alpha-host1"} {
		if path, ok := ncAgentJSONLPath(id, "audit"); !ok || path == "" {
			t.Fatalf("expected valid agent id %q to resolve, got ok=%v path=%q", id, ok, path)
		}
	}
}

// TestEvaluateNCUserEvents_FileAppearingLaterSkipsBacklog は、初回評価の時点で
// まだ存在しないファイルが後から中身つきで現れたケースを固定する。
//
// Agent を後から追加した場合、その Agent の初回レポートには手元のログ全体
// （既定 120,000 行まで）が含まれるため、Monitor 側のファイルは「ある日突然
// 過去分ごと出現する」。ファイル未存在をもって「見た」と記録してしまうと、
// 出現時に過去分が一斉に発報される。
func TestEvaluateNCUserEvents_FileAppearingLaterSkipsBacklog(t *testing.T) {
	dir := ncTestEnv(t)
	now := time.Date(2026, 5, 31, 9, 10, 0, 0, time.UTC)
	captured := withStubs(t, now, nil)

	localPath := filepath.Join(dir, "data/logs/nextcloud.jsonl")
	cfg := &config.AppConfig{}
	cfg.VendorLicense.TenantID = "alpha"
	rules := enabledNCRules()
	state := newAlertState()

	// 1 回目: ファイルがまだ無い。
	if got := evaluateNCUserEvents(cfg, rules, state); len(got) != 0 {
		t.Fatalf("missing file must not fire, got %v", got)
	}

	// 2 回目: 過去分を抱えたファイルが出現した。ここで一斉発報してはいけない。
	writeFile(t, localPath,
		ncCreatedLine("2026-01-01T09:00:00+09:00", "oldstaff1")+
			ncCreatedLine("2026-01-02T09:00:00+09:00", "oldstaff2"))
	got2 := evaluateNCUserEvents(cfg, rules, state)
	if len(got2) != 0 {
		t.Fatalf("backlog of a file that appeared later must not fire, got %v", got2)
	}
	if len(*captured) != 0 {
		t.Fatalf("sender must not be called for appearing backlog, got %v", *captured)
	}

	// 3 回目: 出現後に追記された分だけを拾う。
	appendFile(t, localPath, ncCreatedLine("2026-05-31T09:05:00+09:00", "newstaff"))
	got3 := evaluateNCUserEvents(cfg, rules, state)
	if len(got3) != 1 || !contains(got3[0], "newstaff") {
		t.Fatalf("expected 1 alert for newstaff, got %v", got3)
	}
}
