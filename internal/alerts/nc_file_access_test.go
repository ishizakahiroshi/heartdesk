package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// テストの fixture はすべて合成値（利用者は example.com、IP は文書用の
// 192.0.2.0/24・198.51.100.0/24・203.0.113.0/24）。

// ncFABaseNow は 2026-10-14（水）05:05 UTC = JST 14:05（平日の日中）。
var ncFABaseNow = time.Date(2026, 10, 14, 5, 5, 0, 0, time.UTC)

const (
	uaBrowser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
	uaSync    = "Mozilla/5.0 (Windows) mirall/3.13.0 (build 1) (Nextcloud, windows-10.0.22631)"
	uaAndroid = "Mozilla/5.0 (Android) Nextcloud-android/3.29.0"
	uaIOS     = "Mozilla/5.0 (iOS) Nextcloud-iOS/5.0.0"
	uaCurl    = "curl/8.5.0"
)

type ncFATestEnv struct {
	dir       string
	auditPath string
	cfg       *config.AppConfig
}

// newNCFATestEnv は SAB_BASE_DIR を一時ディレクトリへ向け、任意設定ファイルで
// audit.log の場所を一時ディレクトリの中へ差し替える（/var/www や /home/sab は触らない）。
func newNCFATestEnv(t *testing.T) *ncFATestEnv {
	t.Helper()
	dir := ncTestEnv(t)
	env := &ncFATestEnv{
		dir:       dir,
		auditPath: filepath.Join(dir, "nc", "data", "audit.log"),
		cfg:       &config.AppConfig{},
	}
	env.cfg.VendorLicense.TenantID = "alpha"
	// サービスアカウントの既定は無しなので、サービスアカウントを使うテストのために svc-app を明示する。
	env.writeSettings(t, map[string]any{"audit_log_path": env.auditPath, "service_accounts": []string{"svc-app"}})
	return env
}

func (e *ncFATestEnv) writeSettings(t *testing.T, v map[string]any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(e.dir, "data", "json", "nc_file_access.json"), string(b))
}

// run は評価時刻を now にして evaluateNCFileAccess を 1 回呼ぶ。
func (e *ncFATestEnv) run(rules AlertRules, state *AlertState, now time.Time) []string {
	nowFn = fixedNow(now)
	return evaluateNCFileAccess(e.cfg, rules, state)
}

func (e *ncFATestEnv) loadState(t *testing.T) *ncFAState {
	t.Helper()
	st, existed := loadNCFAState(ncFAStatePath())
	if !existed {
		t.Fatalf("state file should exist at %s", ncFAStatePath())
	}
	return st
}

// ncFARecord は Nextcloud admin_audit の 1 行を模した合成レコードを JSON にする。
func ncFARecord(ts time.Time, user, ip, ua, msg string) string {
	rec := map[string]any{
		"reqId":      "ReqSynthetic0001",
		"level":      1,
		"time":       ts.UTC().Format("2006-01-02T15:04:05+00:00"),
		"remoteAddr": ip,
		"user":       user,
		"app":        "admin_audit",
		"method":     "GET",
		"url":        "/remote.php/dav/files/synthetic",
		"message":    msg,
		"userAgent":  ua,
		"version":    "33.0.0.0",
	}
	b, _ := json.Marshal(rec)
	return string(b) + "\n"
}

func ncFAAccessLine(ts time.Time, user, ip, ua, filePath string, id int) string {
	return ncFARecord(ts, user, ip, ua, fmt.Sprintf(`File with id "%d" accessed: "%s"`, id, filePath))
}

// ncFAAccessLines は n 件の取得行を start から step 刻みで作る。pathFn が nil なら同じフォルダ。
func ncFAAccessLines(start time.Time, step time.Duration, n int, user, ip, ua string, pathFn func(i int) string) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		p := fmt.Sprintf("/%s/files/営業/見積/a%d.pdf", user, i)
		if pathFn != nil {
			p = pathFn(i)
		}
		b.WriteString(ncFAAccessLine(start.Add(time.Duration(i)*step), user, ip, ua, p, 1000+i))
	}
	return b.String()
}

func ncFALoginLine(ts time.Time, user, ip string) string {
	return ncFARecord(ts, user, ip, uaBrowser, fmt.Sprintf(`Login successful: "%s"`, user))
}

func ncFALinkLine(ts time.Time, token, ip, owner string) string {
	msg := fmt.Sprintf(`The shared folder with the token "%s" has been accessed.`, token)
	if owner != "" {
		msg = fmt.Sprintf(`The shared folder with the token "%s" by "%s" has been accessed.`, token, owner)
	}
	return ncFARecord(ts, "--", ip, uaBrowser, msg)
}

func ncFARules(ids ...string) AlertRules {
	r := AlertRules{Rules: map[string]AlertRule{}}
	for _, id := range ids {
		r.Rules[id] = AlertRule{Enabled: true}
	}
	return r
}

func countContaining(list []string, needle string) int {
	n := 0
	for _, s := range list {
		if strings.Contains(s, needle) {
			n++
		}
	}
	return n
}

// 1. 初回はバックログで発報しない。2 回目以降は 299 件で出ず、300 件ちょうどで出る。
func TestNCFileAccess_FirstRunSkipsBacklogThenThresholdBoundary(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	captured := withStubs(t, now, nil)
	rules := ncFARules(ruleNCMassAccess)
	state := newAlertState()

	// 窓の中の 500 件が既に溜まっている（はじめて見るファイル）。
	writeFile(t, env.auditPath, ncFAAccessLines(now.Add(-40*time.Minute), time.Second, 500, "alice@example.com", "203.0.113.5", uaBrowser, nil))
	if got := env.run(rules, state, now); len(got) != 0 {
		t.Fatalf("first run must not fire for the backlog, got %v", got)
	}
	fi, err := os.Stat(env.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if off := env.loadState(t).Offsets[env.auditPath]; off != fi.Size() {
		t.Fatalf("offset should be fast-forwarded to EOF on first run: got %d want %d", off, fi.Size())
	}

	// 299 件（しきい値の 1 つ手前）→ 出ない。
	appendFile(t, env.auditPath, ncFAAccessLines(now.Add(-20*time.Minute), time.Second, 299, "alice@example.com", "203.0.113.5", uaBrowser, nil))
	if got := env.run(rules, state, now); len(got) != 0 {
		t.Fatalf("299 accesses must not fire, got %v", got)
	}

	// +1 件で 300 件ちょうど → 出る（実行をまたいで数えている）。
	appendFile(t, env.auditPath, ncFAAccessLine(now.Add(-time.Minute), "alice@example.com", "203.0.113.5", uaBrowser, "/alice@example.com/files/営業/見積/last.pdf", 9999))
	got := env.run(rules, state, now)
	if len(got) != 1 {
		t.Fatalf("300 accesses must fire once, got %d: %v", len(got), got)
	}
	want := "Nextcloud 大量取得: alice@example.com が直近 60 分で 300 件取得（フォルダ 1・主な接続元 203.0.113.5・端末 ブラウザ）(alpha) 窓 13:05〜14:05\n" +
		"初動: 本人確認 → occ user:disable alice@example.com → 監査ログで範囲確定"
	if got[0] != want {
		t.Fatalf("unexpected message:\n got: %q\nwant: %q", got[0], want)
	}
	if len(*captured) != 1 || !strings.HasPrefix((*captured)[0], ruleNCMassAccess+"|") {
		t.Fatalf("sender should be called once with nc_mass_access, got %v", *captured)
	}
}

// 2. サービスアカウントは nc_mass_access の対象外（任意設定ファイルで差し替えられる）。
func TestNCFileAccess_ServiceAccountExcludedFromMassAccess(t *testing.T) {
	t.Run("no service account by default", func(t *testing.T) {
		env := newNCFATestEnv(t)
		env.writeSettings(t, map[string]any{"audit_log_path": env.auditPath})
		now := ncFABaseNow
		withStubs(t, now, nil)
		rules := ncFARules(ruleNCMassAccess)
		state := newAlertState()

		writeFile(t, env.auditPath, "")
		env.run(rules, state, now)
		appendFile(t, env.auditPath,
			ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 400, "svc-app", "198.51.100.10", uaCurl, nil)+
				ncFAAccessLines(now.Add(-20*time.Minute), time.Second, 300, "alice@example.com", "203.0.113.5", uaBrowser, nil))
		got := env.run(rules, state, now)
		if len(got) != 2 || countContaining(got, "svc-app") != 1 || countContaining(got, "alice@example.com") != 1 {
			t.Fatalf("with no service account configured both users should fire, got %v", got)
		}
	})

	t.Run("listed in settings file", func(t *testing.T) {
		env := newNCFATestEnv(t)
		now := ncFABaseNow
		withStubs(t, now, nil)
		rules := ncFARules(ruleNCMassAccess)
		state := newAlertState()

		writeFile(t, env.auditPath, "")
		env.run(rules, state, now)
		appendFile(t, env.auditPath,
			ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 400, "svc-app", "198.51.100.10", uaCurl, nil)+
				ncFAAccessLines(now.Add(-20*time.Minute), time.Second, 300, "alice@example.com", "203.0.113.5", uaBrowser, nil))
		got := env.run(rules, state, now)
		if len(got) != 1 || !strings.Contains(got[0], "alice@example.com") {
			t.Fatalf("only alice should fire, got %v", got)
		}
		if countContaining(got, "svc-app") != 0 {
			t.Fatalf("service account must be excluded, got %v", got)
		}
	})

	t.Run("overridden by settings file", func(t *testing.T) {
		env := newNCFATestEnv(t)
		env.writeSettings(t, map[string]any{"audit_log_path": env.auditPath, "service_accounts": []string{"svc-bot@example.com"}})
		now := ncFABaseNow
		withStubs(t, now, nil)
		rules := ncFARules(ruleNCMassAccess)
		state := newAlertState()

		writeFile(t, env.auditPath, "")
		env.run(rules, state, now)
		appendFile(t, env.auditPath,
			ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 300, "svc-bot@example.com", "198.51.100.10", uaCurl, nil)+
				ncFAAccessLines(now.Add(-20*time.Minute), time.Second, 300, "svc-app", "198.51.100.11", uaCurl, nil))
		got := env.run(rules, state, now)
		if len(got) != 1 || !strings.Contains(got[0], "svc-app") {
			t.Fatalf("only svc-app (no longer a service account) should fire, got %v", got)
		}
	})
}

// 3. フォルダ数: 50 で出る、49 で出ない。
func TestNCFileAccess_FolderSweepBoundary(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	rules := ncFARules(ruleNCFolderSweep)
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)

	folderPath := func(user string) func(i int) string {
		return func(i int) string { return fmt.Sprintf("/%s/files/案件/%03d/a.pdf", user, i) }
	}
	appendFile(t, env.auditPath,
		ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 50, "alice@example.com", "203.0.113.5", uaBrowser, folderPath("alice@example.com"))+
			ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 49, "bob@example.com", "203.0.113.6", uaBrowser, folderPath("bob@example.com")))
	got := env.run(rules, state, now)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 folder sweep alert, got %v", got)
	}
	if !strings.Contains(got[0], "alice@example.com が直近 60 分で 50 フォルダから取得") {
		t.Fatalf("unexpected message: %q", got[0])
	}
}

// 4. 初めての接続元: 学習期間中は出ない／学習後に新しい IP から 50 件で出る／既知の IP からは出ない。
func TestNCFileAccess_NewIPLearningKnownAndNew(t *testing.T) {
	env := newNCFATestEnv(t)
	t0 := ncFABaseNow
	withStubs(t, t0, nil)
	rules := ncFARules(ruleNCNewIPAccess)
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, t0) // 状態の作成時刻 = t0（学習期間の起点）

	// 学習期間中: bob は新しい IP から 60 件取得しても出ない。alice の IP は学習される。
	t1 := t0.Add(10 * time.Minute)
	appendFile(t, env.auditPath,
		ncFAAccessLines(t1.Add(-5*time.Minute), time.Second, 10, "alice@example.com", "203.0.113.5", uaBrowser, nil)+
			ncFAAccessLines(t1.Add(-5*time.Minute), time.Second, 60, "bob@example.com", "198.51.100.20", uaBrowser, nil))
	if got := env.run(rules, state, t1); len(got) != 0 {
		t.Fatalf("new-IP rule must be silent during the learning period, got %v", got)
	}

	// 学習後（3 日 1 時間後）。
	t2 := t0.Add(3*24*time.Hour + time.Hour)
	appendFile(t, env.auditPath,
		// alice: 既知の IP から 80 件 → 出ない
		ncFAAccessLines(t2.Add(-30*time.Minute), time.Second, 80, "alice@example.com", "203.0.113.5", uaBrowser, nil)+
			// bob: 過去 30 日に使っていない IP から 50 件 → 出る
			ncFAAccessLines(t2.Add(-30*time.Minute), time.Second, 50, "bob@example.com", "192.0.2.77", uaBrowser, nil)+
			// carol: 新しい IP から 49 件 → 出ない（しきい値の 1 つ手前）
			ncFAAccessLines(t2.Add(-30*time.Minute), time.Second, 49, "carol@example.com", "192.0.2.78", uaBrowser, nil))
	got := env.run(rules, state, t2)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 new-IP alert (bob), got %v", got)
	}
	if !strings.Contains(got[0], "bob@example.com が過去 30 日に使っていない接続元から直近 60 分で 50 件取得") ||
		!strings.Contains(got[0], "新しい接続元 192.0.2.77") {
		t.Fatalf("unexpected message: %q", got[0])
	}
}

// 5. 夜間・土日: JST 23:00 の 100 件で出る、平日 JST 14:00 の 100 件では出ない、土曜の日中は出る。
func TestNCFileAccess_OffHours(t *testing.T) {
	cases := []struct {
		name      string
		now       time.Time // 評価時刻（UTC）
		wantAlert bool
	}{
		{"weekday JST 23:30", time.Date(2026, 10, 14, 14, 30, 0, 0, time.UTC), true},
		{"weekday JST 14:30", time.Date(2026, 10, 14, 5, 30, 0, 0, time.UTC), false},
		{"saturday JST 14:30", time.Date(2026, 10, 17, 5, 30, 0, 0, time.UTC), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newNCFATestEnv(t)
			withStubs(t, tc.now, nil)
			rules := ncFARules(ruleNCOffHoursAccess)
			state := newAlertState()

			writeFile(t, env.auditPath, "")
			env.run(rules, state, tc.now)
			// 評価時刻の 30 分前（= JST 23:00 / 14:00）から 100 件。
			appendFile(t, env.auditPath, ncFAAccessLines(tc.now.Add(-30*time.Minute), time.Second, 100, "alice@example.com", "203.0.113.5", uaSync, nil))
			got := env.run(rules, state, tc.now)
			if tc.wantAlert {
				if len(got) != 1 || !strings.Contains(got[0], "夜間・土日（JST 22:00〜06:00・土日）に 100 件取得") || !strings.Contains(got[0], "端末 同期アプリ") {
					t.Fatalf("expected 1 off-hours alert, got %v", got)
				}
			} else if len(got) != 0 {
				t.Fatalf("daytime weekday must not fire, got %v", got)
			}
		})
	}
}

// 6. 公開リンク: 同じ token に 50 回で出る（49 回では出ない）。token は伏せる。
func TestNCFileAccess_PublicLinkBurstMasksToken(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	rules := ncFARules(ruleNCPublicLinkBurst)
	state := newAlertState()

	const tokA = "Zq7XbN3pLm9KsT2" // 50 回（接続元 3 つ）
	const tokB = "Hh4Jj5Kk6Ll7Mm8" // 49 回（出ない）
	const tokC = "Rr2Ss3Tt4Uu5Vv6" // 50 回

	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)

	// 実際の audit.log の形: The shared folder with the token "X" by "Y" has been accessed.
	var b strings.Builder
	for i := 0; i < 50; i++ {
		ts := now.Add(-30*time.Minute + time.Duration(i)*time.Second)
		b.WriteString(ncFALinkLine(ts, tokA, fmt.Sprintf("198.51.100.%d", 1+i%3), "dave@example.com"))
		b.WriteString(ncFALinkLine(ts, tokC, "198.51.100.50", "bob@example.com"))
		if i < 49 {
			b.WriteString(ncFALinkLine(ts, tokB, "198.51.100.60", "dave@example.com"))
		}
	}
	appendFile(t, env.auditPath, b.String())

	got := env.run(rules, state, now)
	if len(got) != 2 {
		t.Fatalf("expected 2 public link alerts (A, C), got %v", got)
	}
	all := strings.Join(got, "\n")
	for _, tok := range []string{tokA, tokB, tokC} {
		if strings.Contains(all, tok) {
			t.Fatalf("raw token %q must not appear in messages: %v", tok, got)
		}
	}
	if countContaining(got, "公開リンク Zq7X…（持ち主 dave@example.com） へ直近 60 分で 50 回アクセス（接続元 3 件") != 1 {
		t.Fatalf("token A should be masked as Zq7X…, got %v", got)
	}
	if countContaining(got, "公開リンク Rr2S…（持ち主 bob@example.com） へ直近 60 分で 50 回アクセス") != 1 {
		t.Fatalf("token C should be masked and show the owner, got %v", got)
	}
	if countContaining(got, "Hh4J") != 0 {
		t.Fatalf("token B (49 accesses) must not fire, got %v", got)
	}
	if countContaining(got, "初動: リンクの持ち主に確認 → 不要なら共有を削除") != 2 {
		t.Fatalf("public link alerts should carry the link first step, got %v", got)
	}

	// token は状態ファイルにも cooldown のキーにも生で残さない。
	raw, err := os.ReadFile(ncFAStatePath())
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{tokA, tokB, tokC} {
		if strings.Contains(string(raw), tok) {
			t.Fatalf("raw token %q must not be stored in the state file", tok)
		}
		for key := range state.LastAlertTime {
			if strings.Contains(key, tok) {
				t.Fatalf("raw token %q must not be used as a cooldown key: %s", tok, key)
			}
		}
	}
}

// 7. 連携アカウントの見知らぬ接続元: 学習後に新しい IP（取得以外の行）で出る。既知の IP では出ない。
func TestNCFileAccess_ServiceAccountNewIP(t *testing.T) {
	env := newNCFATestEnv(t)
	t0 := ncFABaseNow
	withStubs(t, t0, nil)
	rules := ncFARules(ruleNCServiceNewIP)
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, t0)

	// 学習期間中: いつもの接続元と、見知らぬ接続元。どちらも出ない。
	t1 := t0.Add(10 * time.Minute)
	appendFile(t, env.auditPath,
		ncFALoginLine(t1.Add(-time.Minute), "svc-app", "203.0.113.10")+
			ncFALoginLine(t1.Add(-time.Minute), "svc-app", "198.51.100.99"))
	if got := env.run(rules, state, t1); len(got) != 0 {
		t.Fatalf("service new-IP rule must be silent during the learning period, got %v", got)
	}

	// 学習後: 既知の 203.0.113.10 は出ない、新しい 192.0.2.200 はログイン 1 行で出る。
	t2 := t0.Add(3*24*time.Hour + time.Hour)
	appendFile(t, env.auditPath,
		ncFAAccessLines(t2.Add(-10*time.Minute), time.Second, 5, "svc-app", "203.0.113.10", uaCurl, nil)+
			ncFALoginLine(t2.Add(-5*time.Minute), "svc-app", "192.0.2.200"))
	got := env.run(rules, state, t2)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 service new-IP alert, got %v", got)
	}
	if !strings.Contains(got[0], "svc-app が過去 30 日に使っていない接続元 192.0.2.200 から使われた") ||
		!strings.Contains(got[0], "アプリパスワードを再発行") {
		t.Fatalf("unexpected message: %q", got[0])
	}
}

// 連携アカウントの大量取得は既定（しきい値 0）では判定せず、値を入れると判定する。
func TestNCFileAccess_ServiceVolumeNeedsExplicitThreshold(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(ncFARules(ruleNCServiceVolume), state, now)
	appendFile(t, env.auditPath, ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 1000, "svc-app", "198.51.100.10", uaCurl, nil))

	if got := env.run(ncFARules(ruleNCServiceVolume), state, now); len(got) != 0 {
		t.Fatalf("threshold 0 means disabled, got %v", got)
	}
	rules := AlertRules{Rules: map[string]AlertRule{ruleNCServiceVolume: {Enabled: true, Threshold: 1000}}}
	got := env.run(rules, state, now)
	if len(got) != 1 || !strings.Contains(got[0], "svc-app が直近 60 分で 1000 件取得（主な接続元 198.51.100.10・端末 curl）") {
		t.Fatalf("expected service volume alert with threshold 1000, got %v", got)
	}
}

// 8. cooldown: 同じ利用者で続けて評価しても cooldown 内は再発報しない。過ぎれば再び出る。
func TestNCFileAccess_CooldownSuppressesRepeat(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	captured := withStubs(t, now, nil)
	rules := ncFARules(ruleNCMassAccess)
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)

	appendFile(t, env.auditPath, ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 300, "alice@example.com", "203.0.113.5", uaBrowser, nil))
	if got := env.run(rules, state, now); len(got) != 1 {
		t.Fatalf("expected first alert, got %v", got)
	}

	// 5 分後・さらに取得が続いている → 窓の件数はしきい値以上のままだが cooldown 中。
	t1 := now.Add(5 * time.Minute)
	appendFile(t, env.auditPath, ncFAAccessLines(t1.Add(-time.Minute), time.Second, 20, "alice@example.com", "203.0.113.5", uaBrowser, nil))
	if got := env.run(rules, state, t1); len(got) != 0 {
		t.Fatalf("must not re-fire during cooldown, got %v", got)
	}

	// 既定の cooldown（10800 秒）を過ぎ、新たに 300 件 → 再び出る。
	t2 := now.Add(3*time.Hour + 10*time.Minute)
	appendFile(t, env.auditPath, ncFAAccessLines(t2.Add(-20*time.Minute), time.Second, 300, "alice@example.com", "203.0.113.5", uaBrowser, nil))
	if got := env.run(rules, state, t2); len(got) != 1 {
		t.Fatalf("expected alert again after cooldown, got %v", got)
	}
	if len(*captured) != 2 {
		t.Fatalf("sender should be called twice in total, got %v", *captured)
	}
}

// 9. ローテーション（copytruncate）: 切り詰め前に読み残した分を audit.log.1 から拾う。
func TestNCFileAccess_RotationReadsRestFromDotOne(t *testing.T) {
	for _, withDotOne := range []bool{true, false} {
		t.Run(fmt.Sprintf("dot_one=%v", withDotOne), func(t *testing.T) {
			env := newNCFATestEnv(t)
			now := ncFABaseNow
			withStubs(t, now, nil)
			rules := ncFARules(ruleNCMassAccess)
			state := newAlertState()

			// 取得以外の行で offset を大きくしておく。
			var pre strings.Builder
			for i := 0; i < 400; i++ {
				pre.WriteString(ncFALoginLine(now.Add(-50*time.Minute), "dave@example.com", "192.0.2.40"))
			}
			writeFile(t, env.auditPath, pre.String())
			env.run(rules, state, now)
			offset := env.loadState(t).Offsets[env.auditPath]

			// まだ読んでいない 200 件が書かれた後に、logrotate が copytruncate した。
			rest := ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 200, "alice@example.com", "203.0.113.5", uaBrowser, nil)
			appendFile(t, env.auditPath, rest)
			full, err := os.ReadFile(env.auditPath)
			if err != nil {
				t.Fatal(err)
			}
			if withDotOne {
				writeFile(t, env.auditPath+".1", string(full))
			}
			after := ncFAAccessLines(now.Add(-10*time.Minute), time.Second, 100, "alice@example.com", "203.0.113.5", uaBrowser, nil)
			writeFile(t, env.auditPath, after) // 切り詰め＋新しい書き込み
			if int64(len(after)) >= offset {
				t.Fatalf("test setup: new audit.log (%d bytes) must be smaller than the recorded offset (%d)", len(after), offset)
			}

			got := env.run(rules, state, now)
			if withDotOne {
				if len(got) != 1 || !strings.Contains(got[0], "直近 60 分で 300 件取得") {
					t.Fatalf("200 (from .1) + 100 (new) = 300 should fire, got %v", got)
				}
			} else if len(got) != 0 {
				t.Fatalf("without .1 only the 100 new accesses are counted, got %v", got)
			}
			if off := env.loadState(t).Offsets[env.auditPath]; off != int64(len(after)) {
				t.Fatalf("offset after rotation should point to the end of the new file: got %d want %d", off, len(after))
			}
		})
	}
}

// installFakeFileIDs は inode の代わりにテストが決めた ID を返すようにする
// （Windows では inode が取れないので、名前を変える切り替えをこれで模す）。
func installFakeFileIDs(t *testing.T) map[string]uint64 {
	t.Helper()
	ids := map[string]uint64{}
	orig := ncFAFileIDFn
	ncFAFileIDFn = func(p string, _ os.FileInfo) (uint64, bool) {
		id, ok := ids[filepath.Clean(p)]
		return id, ok
	}
	t.Cleanup(func() { ncFAFileIDFn = orig })
	return ids
}

// renameRotate は logrotate の create 方式（名前を .1 に変え、新しいファイルを作る）を模す。
// 名前を変えたファイルは ID（inode）を引き継ぎ、新しいファイルは別の ID になる。
func renameRotate(t *testing.T, ids map[string]uint64, p string, newID uint64, content string) {
	t.Helper()
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	ids[filepath.Clean(p+".1")] = ids[filepath.Clean(p)]
	writeFile(t, p, content)
	ids[filepath.Clean(p)] = newID
}

// captureLog はテスト中のログを捕まえる（行の途中から読んだときの「壊れた行」を検出するため）。
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	orig := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(orig) })
	return buf
}

func ncFAUserCount(t *testing.T, env *ncFATestEnv, uid string) int {
	t.Helper()
	u := env.loadState(t).Users[uid]
	if u == nil {
		return 0
	}
	return ncFAAggregate(u.Buckets).count
}

// 名前を変えて作り直した新ファイルが、記録位置より大きく育ってから読まれる場合
// （logrotate の create 方式）。取りこぼし・重複・行の途中からの読み込みが無いこと。
func TestNCFileAccess_RenameRotationNewFileGrownPastOffset(t *testing.T) {
	env := newNCFATestEnv(t)
	ids := installFakeFileIDs(t)
	logs := captureLog(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	rules := ncFARules() // 判定はせず、集計だけを見る
	state := newAlertState()
	const alice = "alice@example.com"
	access := func(start time.Time, n int) string {
		return ncFAAccessLines(start, time.Second, n, alice, "203.0.113.5", uaBrowser, nil)
	}

	ids[filepath.Clean(env.auditPath)] = 100
	var pre strings.Builder
	for i := 0; i < 400; i++ {
		pre.WriteString(ncFALoginLine(now.Add(-50*time.Minute), "dave@example.com", "192.0.2.40"))
	}
	writeFile(t, env.auditPath, pre.String())
	env.run(rules, state, now) // 初回: 末尾まで進めるだけ

	// 通常の差分読み。
	appendFile(t, env.auditPath, access(now.Add(-45*time.Minute), 50))
	env.run(rules, state, now)
	if got := ncFAUserCount(t, env, alice); got != 50 {
		t.Fatalf("baseline: got %d accesses, want 50", got)
	}
	offset := env.loadState(t).Offsets[env.auditPath]

	// 読む前に 200 件書かれ、その後に名前を変える切り替えが起き、
	// 新しいファイルが記録位置より大きく育った（700 件）。
	appendFile(t, env.auditPath, access(now.Add(-40*time.Minute), 200))
	after := access(now.Add(-30*time.Minute), 700)
	renameRotate(t, ids, env.auditPath, 200, after)
	if int64(len(after)) <= offset {
		t.Fatalf("test setup: new file (%d bytes) must be larger than the recorded offset (%d)", len(after), offset)
	}

	env.run(rules, state, now)
	if got := ncFAUserCount(t, env, alice); got != 50+200+700 {
		t.Fatalf("after rename rotation: got %d accesses, want %d (no loss, no duplicate)", got, 50+200+700)
	}
	if off := env.loadState(t).Offsets[env.auditPath]; off != int64(len(after)) {
		t.Fatalf("offset should point to the end of the new file: got %d want %d", off, len(after))
	}

	// 次の回は新しいファイルの続きだけを読む（.1 を読み直さない）。
	appendFile(t, env.auditPath, access(now.Add(-10*time.Minute), 10))
	env.run(rules, state, now)
	if got := ncFAUserCount(t, env, alice); got != 50+200+700+10 {
		t.Fatalf("next run: got %d accesses, want %d", got, 50+200+700+10)
	}
	if strings.Contains(logs.String(), "skipped lines") {
		t.Fatalf("no line may be read from the middle (broken lines were logged):\n%s", logs.String())
	}
}

// 切り替わりの判定表の残り: inode の保存・.1 が無い・2 回以上の切り替え・inode つきの copytruncate。
func TestNCFileAccess_RotationDecisionMatrix(t *testing.T) {
	const alice = "alice@example.com"
	now := ncFABaseNow
	access := func(start time.Time, n int) string {
		return ncFAAccessLines(start, time.Second, n, alice, "203.0.113.5", uaBrowser, nil)
	}
	// setup は記録位置を大きくしてから 50 件を通常どおり読ませ、記録位置を返す。
	setup := func(t *testing.T, env *ncFATestEnv, ids map[string]uint64) int64 {
		t.Helper()
		ids[filepath.Clean(env.auditPath)] = 100
		var pre strings.Builder
		for i := 0; i < 400; i++ {
			pre.WriteString(ncFALoginLine(now.Add(-50*time.Minute), "dave@example.com", "192.0.2.40"))
		}
		writeFile(t, env.auditPath, pre.String())
		env.run(ncFARules(), newAlertState(), now)
		appendFile(t, env.auditPath, access(now.Add(-45*time.Minute), 50))
		env.run(ncFARules(), newAlertState(), now)
		st := env.loadState(t)
		if id, ok := st.Inodes[env.auditPath]; !ok || id != 100 {
			t.Fatalf("inode of the file being read should be saved: got %d ok=%v", id, ok)
		}
		return st.Offsets[env.auditPath]
	}

	t.Run("renamed and .1 already gone", func(t *testing.T) {
		env := newNCFATestEnv(t)
		ids := installFakeFileIDs(t)
		logs := captureLog(t)
		withStubs(t, now, nil)
		offset := setup(t, env, ids)

		appendFile(t, env.auditPath, access(now.Add(-40*time.Minute), 200))
		after := access(now.Add(-30*time.Minute), 700)
		renameRotate(t, ids, env.auditPath, 200, after)
		if err := os.Remove(env.auditPath + ".1"); err != nil {
			t.Fatal(err)
		}
		if int64(len(after)) <= offset {
			t.Fatalf("test setup: new file must be larger than the offset")
		}
		env.run(ncFARules(), newAlertState(), now)
		// .1 の 200 件は失われるが、新しいファイルは先頭から全部読む（途中から読まない）。
		if got := ncFAUserCount(t, env, alice); got != 50+700 {
			t.Fatalf("got %d, want %d", got, 50+700)
		}
		if strings.Contains(logs.String(), "skipped lines") {
			t.Fatalf("new file must be read from the start:\n%s", logs.String())
		}
	})

	t.Run("rotated twice: .1 is not the previous file", func(t *testing.T) {
		env := newNCFATestEnv(t)
		ids := installFakeFileIDs(t)
		logs := captureLog(t)
		withStubs(t, now, nil)
		setup(t, env, ids)

		// 1 回目の切り替え（前回のファイル id=100 は .1 へ）→ 読まないうちに 2 回目の切り替え。
		appendFile(t, env.auditPath, access(now.Add(-40*time.Minute), 200))
		mid := access(now.Add(-35*time.Minute), 300)
		renameRotate(t, ids, env.auditPath, 150, mid)
		// 2 回目: id=100 は .2 へ（delaycompress で圧縮される世代。ここでは消す）、id=150 が .1 へ。
		if err := os.Rename(env.auditPath+".1", env.auditPath+".2"); err != nil {
			t.Fatal(err)
		}
		after := access(now.Add(-30*time.Minute), 100)
		renameRotate(t, ids, env.auditPath, 200, after)

		env.run(ncFARules(), newAlertState(), now)
		// id=100 の残り 200 件は .2 にあって読めない。.1（id=150）は先頭の指紋が前回のファイルと
		// 違うので読まない（F11: 指紋が一致する .1 だけを読む）。新しいファイルは 0 から。
		if got := ncFAUserCount(t, env, alice); got != 50+100 {
			t.Fatalf("got %d, want %d", got, 50+100)
		}
		if !strings.Contains(logs.String(), "is not the file read last time") {
			t.Fatalf("an unmatched .1 should be logged:\n%s", logs.String())
		}
		if strings.Contains(logs.String(), "skipped lines") {
			t.Fatalf("no line may be read from the middle:\n%s", logs.String())
		}
	})

	t.Run("copytruncate with inodes", func(t *testing.T) {
		env := newNCFATestEnv(t)
		ids := installFakeFileIDs(t)
		withStubs(t, now, nil)
		offset := setup(t, env, ids)

		appendFile(t, env.auditPath, access(now.Add(-40*time.Minute), 200))
		full, err := os.ReadFile(env.auditPath)
		if err != nil {
			t.Fatal(err)
		}
		// copytruncate: .1 はコピー（別の inode）、audit.log は同じ inode のまま切り詰め。
		writeFile(t, env.auditPath+".1", string(full))
		ids[filepath.Clean(env.auditPath+".1")] = 300
		after := access(now.Add(-30*time.Minute), 100)
		writeFile(t, env.auditPath, after)
		if int64(len(after)) >= offset {
			t.Fatalf("test setup: truncated file must be smaller than the offset")
		}
		env.run(ncFARules(), newAlertState(), now)
		if got := ncFAUserCount(t, env, alice); got != 50+200+100 {
			t.Fatalf("got %d, want %d", got, 50+200+100)
		}
	})
}

// 実際の識別子の取り方: Linux 等では inode が取れ、Windows では取れない（サイズだけで判定する）。
func TestNCFAFileIDFromInfo(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	writeFile(t, p, "x\n")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := ncFAFileIDFromInfo(fi)
	if runtime.GOOS == "windows" {
		if ok {
			t.Fatalf("windows: inode should not be available, got %d", id)
		}
		return
	}
	if !ok || id == 0 {
		t.Fatalf("%s: inode should be available, got id=%d ok=%v", runtime.GOOS, id, ok)
	}
	q := p + ".new"
	writeFile(t, q, "y\n")
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(q, p); err != nil {
		t.Fatal(err)
	}
	fi2, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if id2, _ := ncFAFileIDFromInfo(fi2); id2 == id {
		t.Fatalf("a recreated file should have a different inode")
	}
}

// 10. 60 分より古いイベントは数えない（読み込み時も、実行をまたいだ後も）。
func TestNCFileAccess_WindowBoundary(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	rules := ncFARules(ruleNCMassAccess)
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)

	// 61〜66 分前の 300 件 → 窓の外なので出ない。
	appendFile(t, env.auditPath, ncFAAccessLines(now.Add(-66*time.Minute), time.Second, 300, "alice@example.com", "203.0.113.5", uaBrowser, nil))
	if got := env.run(rules, state, now); len(got) != 0 {
		t.Fatalf("events older than 60 minutes must not be counted, got %v", got)
	}

	// bob: 30 分前に 200 件（窓の中・しきい値未満）。
	appendFile(t, env.auditPath, ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 200, "bob@example.com", "203.0.113.6", uaBrowser, nil))
	if got := env.run(rules, state, now); len(got) != 0 {
		t.Fatalf("200 accesses must not fire, got %v", got)
	}

	// 40 分後: さっきの 200 件は 70 分前になって窓から外れる。新たな 100 件だけ → 出ない。
	t1 := now.Add(40 * time.Minute)
	appendFile(t, env.auditPath, ncFAAccessLines(t1.Add(-5*time.Minute), time.Second, 100, "bob@example.com", "203.0.113.6", uaBrowser, nil))
	if got := env.run(rules, state, t1); len(got) != 0 {
		t.Fatalf("aged-out buckets must not be counted, got %v", got)
	}

	// 対照: さらに 200 件で窓の中が 300 件 → 出る。
	appendFile(t, env.auditPath, ncFAAccessLines(t1.Add(-4*time.Minute), time.Second, 200, "bob@example.com", "203.0.113.6", uaBrowser, nil))
	got := env.run(rules, state, t1)
	if len(got) != 1 || !strings.Contains(got[0], "bob@example.com が直近 60 分で 300 件取得") {
		t.Fatalf("300 accesses inside the window should fire, got %v", got)
	}
}

// 11. 壊れた JSON 行・空行・時刻の読めない行は飛ばす。
func TestNCFileAccess_SkipsBrokenAndEmptyLines(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	rules := ncFARules(ruleNCMassAccess)
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)

	var b strings.Builder
	for i := 0; i < 300; i++ {
		b.WriteString(ncFAAccessLine(now.Add(-30*time.Minute+time.Duration(i)*time.Second), "alice@example.com", "203.0.113.5", uaBrowser, fmt.Sprintf("/alice@example.com/files/営業/a%d.pdf", i), i))
		switch i % 4 {
		case 0:
			b.WriteString("this is not json\n")
		case 1:
			b.WriteString("\n   \n")
		case 2:
			b.WriteString(`{"time":"2026-10-14T04:40:00+00:00","user":"alice@example.com","message":"File with id "` + "\n")
		case 3:
			b.WriteString(`{"time":"not a time","user":"alice@example.com","remoteAddr":"203.0.113.5","message":"File with id \"1\" accessed: \"/alice@example.com/files/x.pdf\""}` + "\n")
		}
	}
	appendFile(t, env.auditPath, b.String())
	got := env.run(rules, state, now)
	if len(got) != 1 || !strings.Contains(got[0], "直近 60 分で 300 件取得") {
		t.Fatalf("exactly the 300 valid lines should be counted, got %v", got)
	}
}

// 後から過去分を抱えて現れたファイルは、その時点を初回として扱う（状態ファイルも先に作らない）。
func TestNCFileAccess_FileAppearingLaterSkipsBacklog(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	rules := ncFARules(ruleNCMassAccess)
	state := newAlertState()

	if got := env.run(rules, state, now); len(got) != 0 {
		t.Fatalf("missing file must not fire, got %v", got)
	}
	if _, err := os.Stat(ncFAStatePath()); !os.IsNotExist(err) {
		t.Fatalf("state file must not be created while audit.log is missing (err=%v)", err)
	}

	writeFile(t, env.auditPath, ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 500, "alice@example.com", "203.0.113.5", uaBrowser, nil))
	if got := env.run(rules, state, now); len(got) != 0 {
		t.Fatalf("backlog of a file that appeared later must not fire, got %v", got)
	}

	appendFile(t, env.auditPath, ncFAAccessLines(now.Add(-10*time.Minute), time.Second, 300, "alice@example.com", "203.0.113.5", uaBrowser, nil))
	if got := env.run(rules, state, now); len(got) != 1 {
		t.Fatalf("lines appended after the file appeared should be counted, got %v", got)
	}
}

// 1 回に読む行数の上限を超えた分は次回に読む（取りこぼさない）。
func TestNCFileAccess_ReadLimitContinuesNextRun(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	orig := ncFAMaxLinesPerRun
	ncFAMaxLinesPerRun = 100
	t.Cleanup(func() { ncFAMaxLinesPerRun = orig })

	rules := AlertRules{Rules: map[string]AlertRule{ruleNCMassAccess: {Enabled: true, Threshold: 250}}}
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)
	appendFile(t, env.auditPath, ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 250, "alice@example.com", "203.0.113.5", uaBrowser, nil))

	for i, want := range []int{0, 0, 1} {
		got := env.run(rules, state, now)
		if len(got) != want {
			t.Fatalf("run %d: expected %d alerts, got %v", i+1, want, got)
		}
		if want == 1 && !strings.Contains(got[0], "250 件取得") {
			t.Fatalf("all 250 lines should eventually be counted, got %v", got)
		}
	}
	fi, err := os.Stat(env.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if off := env.loadState(t).Offsets[env.auditPath]; off != fi.Size() {
		t.Fatalf("offset should reach EOF after 3 runs: got %d want %d", off, fi.Size())
	}
}

// 書きかけの最終行（改行なし）は読まずに次回へ回す。
func TestNCFileAccess_PartialLastLineIsReadNextRun(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	rules := AlertRules{Rules: map[string]AlertRule{ruleNCMassAccess: {Enabled: true, Threshold: 3}}}
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)

	line := ncFAAccessLine(now.Add(-time.Minute), "alice@example.com", "203.0.113.5", uaBrowser, "/alice@example.com/files/a.pdf", 1)
	appendFile(t, env.auditPath, line+line+line[:40])
	if got := env.run(rules, state, now); len(got) != 0 {
		t.Fatalf("partial line must not be counted yet, got %v", got)
	}
	appendFile(t, env.auditPath, line[40:])
	if got := env.run(rules, state, now); len(got) != 1 {
		t.Fatalf("completed line should be counted on the next run, got %v", got)
	}
}

// 壊れた任意設定ファイルは既定値で動く（パスは nextcloud_dir から、サービスアカウントは無し）。
func TestNCFileAccess_BrokenSettingsFallsBackToDefaults(t *testing.T) {
	env := newNCFATestEnv(t)
	writeFile(t, filepath.Join(env.dir, "data", "json", "nc_file_access.json"), "{broken")
	env.cfg.Paths.NextcloudDir = filepath.Join(env.dir, "nc")
	now := ncFABaseNow
	withStubs(t, now, nil)
	rules := ncFARules(ruleNCMassAccess)
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)
	appendFile(t, env.auditPath,
		ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 300, "svc-app", "198.51.100.10", uaCurl, nil)+
			ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 300, "alice@example.com", "203.0.113.5", uaAndroid, nil))
	got := env.run(rules, state, now)
	if len(got) != 2 || countContaining(got, "svc-app") != 1 || countContaining(got, "alice@example.com") != 1 || countContaining(got, "端末 スマホ") != 1 {
		t.Fatalf("defaults should apply (audit.log under nextcloud_dir, no service account), got %v", got)
	}
}

// 壊れた状態ファイルは作り直し（次の 1 回は末尾まで進めるだけ）、null を含む状態でも落ちない。
func TestNCFileAccess_BrokenOrNullStateDoesNotPanic(t *testing.T) {
	t.Run("broken json starts over", func(t *testing.T) {
		env := newNCFATestEnv(t)
		now := ncFABaseNow
		withStubs(t, now, nil)
		writeFile(t, ncFAStatePath(), "{not json")
		writeFile(t, env.auditPath, ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 300, "alice@example.com", "203.0.113.5", uaBrowser, nil))
		if got := env.run(ncFARules(ruleNCMassAccess), newAlertState(), now); len(got) != 0 {
			t.Fatalf("a rebuilt state must fast-forward instead of firing on the backlog, got %v", got)
		}
	})

	t.Run("null entries are dropped", func(t *testing.T) {
		env := newNCFATestEnv(t)
		now := ncFABaseNow
		withStubs(t, now, nil)
		writeFile(t, env.auditPath, "")
		st := map[string]any{
			"version":    1,
			"created_at": now.Add(-time.Hour),
			"offsets":    map[string]int64{env.auditPath: 0},
			"users":      map[string]any{"alice@example.com": map[string]any{"b": []any{nil}}, "bob@example.com": nil},
			"links":      map[string]any{"deadbeef": nil},
		}
		b, _ := json.Marshal(st)
		writeFile(t, ncFAStatePath(), string(b))
		appendFile(t, env.auditPath, ncFAAccessLines(now.Add(-30*time.Minute), time.Second, 300, "alice@example.com", "203.0.113.5", uaBrowser, nil))
		if got := env.run(ncFARules(ruleNCMassAccess), newAlertState(), now); len(got) != 1 {
			t.Fatalf("expected 1 alert after dropping null entries, got %v", got)
		}
	})
}

func TestNCAuditLogPathPriority(t *testing.T) {
	cfg := &config.AppConfig{}
	if got := ncAuditLogPath(cfg, ncFileAccessSettings{}); got != ncFAAuditLogDefaultPath {
		t.Fatalf("default path: got %q", got)
	}
	cfg.Paths.NextcloudDir = filepath.Join("srv", "nc")
	if got, want := ncAuditLogPath(cfg, ncFileAccessSettings{}), filepath.Join("srv", "nc", "data", "audit.log"); got != want {
		t.Fatalf("nextcloud_dir path: got %q want %q", got, want)
	}
	if got := ncAuditLogPath(cfg, ncFileAccessSettings{AuditLogPath: " /data/nc/audit.log "}); got != "/data/nc/audit.log" {
		t.Fatalf("explicit audit_log_path should win: got %q", got)
	}
	if got := ncAuditLogPath(nil, ncFileAccessSettings{}); got != ncFAAuditLogDefaultPath {
		t.Fatalf("nil cfg: got %q", got)
	}
}

// [alerts].state_file が /tmp を向いていても、集計の状態は data/json に置く（再起動で学習を失わない）。
func TestNCFAStateIgnoresAlertStateFileDir(t *testing.T) {
	env := newNCFATestEnv(t)
	tmpDir := t.TempDir()
	env.cfg.Alerts.StateFile = filepath.Join(tmpDir, "sab_alert_state.json")
	writeFile(t, env.auditPath, "")
	env.run(ncFARules(ruleNCMassAccess), newAlertState(), time.Date(2026, 10, 16, 5, 0, 0, 0, time.UTC))

	if want := filepath.Join(env.dir, "data", "json", "nc_file_access_state.json"); ncFAStatePath() != want {
		t.Fatalf("state path: got %q want %q", ncFAStatePath(), want)
	}
	if _, err := os.Stat(ncFAStatePath()); err != nil {
		t.Fatalf("state should be written under data/json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "nc_file_access_state.json")); !os.IsNotExist(err) {
		t.Fatalf("state must not follow [alerts].state_file into its directory (err=%v)", err)
	}
}

func TestNCFADeviceClass(t *testing.T) {
	cases := map[string]string{
		uaSync:                            "同期アプリ",
		uaAndroid:                         "スマホ",
		uaIOS:                             "スマホ",
		uaBrowser:                         "ブラウザ",
		uaCurl:                            "curl",
		"rclone/v1.65.0":                  "rclone",
		"python-requests/2.31 x":          "python-requests",
		"":                                "不明",
		"evil\x1bbot":                     "evil?bot",
		strings.Repeat("x", 100):          strings.Repeat("x", 40) + "…",
		"Microsoft-WebDAV-MiniRedir/10.0": "Microsoft-WebDAV-MiniRedir",
	}
	for ua, want := range cases {
		if got := ncFADeviceClass(ua); got != want {
			t.Errorf("ncFADeviceClass(%q) = %q, want %q", ua, got, want)
		}
	}
}

func TestNCFAMaskToken(t *testing.T) {
	cases := map[string]string{
		"Zq7XbN3pLm9KsT2": "Zq7X…",
		"abcd":            "ab…",
		"a":               "…",
	}
	for tok, want := range cases {
		if got := ncFAMaskToken(tok); got != want {
			t.Errorf("ncFAMaskToken(%q) = %q, want %q", tok, got, want)
		}
	}
}

// 通知は 4000 文字以内に収め、ログ由来の改行で行を増やさない。
func TestNCFileAccess_MessageBoundedAndSanitized(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	rules := AlertRules{Rules: map[string]AlertRule{ruleNCMassAccess: {Enabled: true, Threshold: 2}}}
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)
	longUser := strings.Repeat("u", 5000) + "@example.com"
	evilUA := "bad\nagent " + strings.Repeat("y", 5000)
	appendFile(t, env.auditPath,
		ncFAAccessLine(now.Add(-time.Minute), longUser, "203.0.113.5", evilUA, "/x/files/a.pdf", 1)+
			ncFAAccessLine(now.Add(-time.Minute), longUser, "203.0.113.5", evilUA, "/x/files/b.pdf", 2))
	got := env.run(rules, state, now)
	if len(got) != 1 {
		t.Fatalf("expected 1 alert, got %v", got)
	}
	if n := len([]rune(got[0])); n > 4000 {
		t.Fatalf("message must be within 4000 chars, got %d", n)
	}
	if strings.Count(got[0], "\n") != 1 {
		t.Fatalf("only the first-step line break is allowed, got %q", got[0])
	}
}

func TestNCFAParsers(t *testing.T) {
	if p, ok := ncFAParseAccess(`File with id "123" accessed: "/alice@example.com/files/営業/見積/a.pdf"`); !ok || p != "/alice@example.com/files/営業/見積/a.pdf" {
		t.Fatalf("quoted access line: ok=%v p=%q", ok, p)
	}
	if p, ok := ncFAParseAccess(`File with id 123 accessed: /bob@example.com/files/a.pdf`); !ok || p != "/bob@example.com/files/a.pdf" {
		t.Fatalf("unquoted access line: ok=%v p=%q", ok, p)
	}
	if _, ok := ncFAParseAccess(`File written to: "/alice@example.com/files/a.pdf"`); ok {
		t.Fatalf("non-access line must not match")
	}
	// 実機の 2 つの形（folder / file、持ち主つき、末尾のピリオドは有無とも）。
	for _, line := range []string{
		`The shared folder with the token "Rr2Ss3Tt4Uu5Vv6" by "bob@example.com" has been accessed.`,
		`The shared file with the token "Rr2Ss3Tt4Uu5Vv6" by "bob@example.com" has been accessed`,
	} {
		if tok, owner, ok := ncFAParsePublicLink(line); !ok || tok != "Rr2Ss3Tt4Uu5Vv6" || owner != "bob@example.com" {
			t.Fatalf("public link line %q: ok=%v tok=%q owner=%q", line, ok, tok, owner)
		}
	}
	// 実機に無い形・行の途中に文言があるだけの行は受けない（F1）。
	for _, line := range []string{
		`The shared folder with the token "Zq7XbN3pLm9KsT2" has been accessed.`,
		`Login attempt: "The shared folder with the token FAKEtok by x has been accessed"`,
		`File written to: "/a/The shared folder with the token "T" by "u" has been accessed.txt"`,
		`The shared calendar with the token "T" by "u" has been accessed.`,
	} {
		if _, _, ok := ncFAParsePublicLink(line); ok {
			t.Fatalf("must not be treated as a public link line: %q", line)
		}
	}
}

func TestNCFAIPUnit(t *testing.T) {
	cases := map[string]string{
		"203.0.113.5":                      "203.0.113.5",
		"::ffff:203.0.113.5":               "203.0.113.5",
		"2001:db8:1:2::abcd":               "2001:db8:1:2::/64",
		"2001:db8:1:2:aaaa:bbbb:cccc:dddd": "2001:db8:1:2::/64",
		"fe80::1%eth0":                     "fe80::/64",
		"not-an-ip":                        "not-an-ip",
	}
	for in, want := range cases {
		if got := ncFAIPUnit(in); got != want {
			t.Errorf("ncFAIPUnit(%q) = %q, want %q", in, got, want)
		}
	}
}

// F11: 状態に先頭の指紋（512 バイトまでの SHA-256 と長さ）が残る。短いファイルは育つと伸ばす。
func TestNCFileAccess_HeadFingerprintIsSaved(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	writeFile(t, env.auditPath, "")
	env.run(ncFARules(), newAlertState(), now)
	if h, ok := env.loadState(t).Heads[env.auditPath]; !ok || h.Len != 0 {
		t.Fatalf("empty file: head = %+v ok=%v", h, ok)
	}
	appendFile(t, env.auditPath, ncFAAccessLines(now.Add(-time.Minute), time.Second, 10, "alice@example.com", "203.0.113.5", uaBrowser, nil))
	env.run(ncFARules(), newAlertState(), now)
	h, ok := env.loadState(t).Heads[env.auditPath]
	if !ok || h.Len != ncFAHeadBytes || len(h.Hash) != 64 {
		t.Fatalf("head should cover the first %d bytes: %+v ok=%v", ncFAHeadBytes, h, ok)
	}
	if got := ncFAUserCount(t, env, "alice@example.com"); got != 10 {
		t.Fatalf("growing a short file must not be treated as a rotation: got %d", got)
	}
}

// 壊れた状態ファイルはログに 1 行出す（学習期間と接続元の履歴は最初からになる。判断済み）。
func TestNCFileAccess_BrokenStateIsLogged(t *testing.T) {
	env := newNCFATestEnv(t)
	logs := captureLog(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	writeFile(t, ncFAStatePath(), "{not json")
	writeFile(t, env.auditPath, "")
	env.run(ncFARules(), newAlertState(), now)
	if n := strings.Count(logs.String(), "is broken, starting over"); n != 1 {
		t.Fatalf("a broken state file should be logged once, got %d:\n%s", n, logs.String())
	}
}

func TestNCFAPruneCooldowns(t *testing.T) {
	now := ncFABaseNow
	state := newAlertState()
	state.LastAlertTime["nc_mass_access:alice@example.com"] = now.Add(-8 * 24 * time.Hour)
	state.LastAlertTime["nc_mass_access:bob@example.com"] = now.Add(-time.Hour)
	state.LastAlertTime["nc_user_created:local:carol"] = now.Add(-100 * 24 * time.Hour)
	ncFAPruneCooldowns(state, now)
	if _, ok := state.LastAlertTime["nc_mass_access:alice@example.com"]; ok {
		t.Fatalf("old nc_file_access cooldown key should be pruned")
	}
	if _, ok := state.LastAlertTime["nc_mass_access:bob@example.com"]; !ok {
		t.Fatalf("recent cooldown key must be kept")
	}
	if _, ok := state.LastAlertTime["nc_user_created:local:carol"]; !ok {
		t.Fatalf("other rules' keys must not be touched")
	}
}
