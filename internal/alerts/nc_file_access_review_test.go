package alerts

// レビューで指摘された点の再現テスト。
// fixture はすべて合成値（example.com・文書用 IP・2001:db8::/32）。

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// 公開リンクの文言を含むだけの行（ログイン名・ファイル名・user 付き）は公開リンクとして数えない。
func TestNCFileAccess_F1_PublicLinkRequiresExactLine(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	rules := ncFARules(ruleNCPublicLinkBurst)
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)

	var fake strings.Builder
	for i := 0; i < 60; i++ {
		ts := now.Add(-30*time.Minute + time.Duration(i)*time.Second)
		// ログイン名に文言を入れた行（user は空）
		fake.WriteString(ncFARecord(ts, "", "198.51.100.7", uaBrowser,
			`Login attempt: "The shared folder with the token FAKEtok by 情報システム部（対応不要） has been accessed"`))
		// 利用者が付けたファイル名に同じ文言を入れた行（user あり・なし）
		fake.WriteString(ncFARecord(ts, "alice@example.com", "203.0.113.5", uaBrowser,
			`File written to: "/alice@example.com/files/The shared folder with the token "FAKEtk2" by "bob@example.com" has been accessed.txt"`))
		fake.WriteString(ncFARecord(ts, "", "203.0.113.5", uaBrowser,
			`File renamed: "/alice@example.com/files/a.txt" to: "The shared file with the token "FAKEtk3" by "bob@example.com" has been accessed."`))
		// 本物の形だが user が入っている行
		fake.WriteString(ncFARecord(ts, "carol@example.com", "198.51.100.8", uaBrowser,
			`The shared folder with the token "FAKEtk4" by "carol@example.com" has been accessed.`))
	}
	appendFile(t, env.auditPath, fake.String())
	if got := env.run(rules, state, now); len(got) != 0 {
		t.Fatalf("lines that only contain the public link wording must not fire, got %v", got)
	}

	// 本物の形（user は空 / --、folder と file）は数える。
	var real strings.Builder
	for i := 0; i < 50; i++ {
		ts := now.Add(-20*time.Minute + time.Duration(i)*time.Second)
		if i%2 == 0 {
			real.WriteString(ncFARecord(ts, "", "198.51.100.9", uaBrowser, `The shared file with the token "Zq7XbN3pLm9KsT2" by "bob@example.com" has been accessed.`))
		} else {
			real.WriteString(ncFALinkLine(ts, "Zq7XbN3pLm9KsT2", "198.51.100.9", "bob@example.com"))
		}
	}
	appendFile(t, env.auditPath, real.String())
	got := env.run(rules, state, now)
	if len(got) != 1 || !strings.Contains(got[0], "公開リンク Zq7X…（持ち主 bob@example.com） へ直近 60 分で 50 回アクセス") {
		t.Fatalf("the real public link line should fire once, got %v", got)
	}
}

// 1 回の評価で出す通知は、ルールごとに 5 件＋まとめ 1 件まで。
func TestNCFileAccess_F2_CapsAlertsPerRule(t *testing.T) {
	t.Run("public links", func(t *testing.T) {
		env := newNCFATestEnv(t)
		now := ncFABaseNow
		captured := withStubs(t, now, nil)
		rules := ncFARules(ruleNCPublicLinkBurst)
		state := newAlertState()

		writeFile(t, env.auditPath, "")
		env.run(rules, state, now)
		var b strings.Builder
		for tok := 0; tok < 100; tok++ {
			for i := 0; i < 50; i++ {
				ts := now.Add(-30*time.Minute + time.Duration(i)*time.Second)
				b.WriteString(ncFALinkLine(ts, fmt.Sprintf("Tok%03dSynthetic", tok), "198.51.100.20", "bob@example.com"))
			}
		}
		appendFile(t, env.auditPath, b.String())
		got := env.run(rules, state, now)
		if len(got) > 6 {
			t.Fatalf("at most 5 alerts + 1 summary per rule per evaluation, got %d", len(got))
		}
		if countContaining(got, "ほか 95 件（同じルール）") != 1 {
			t.Fatalf("the rest should be summarised in one alert, got %v", got)
		}
		if len(*captured) != len(got) {
			t.Fatalf("sender calls (%d) should match returned alerts (%d)", len(*captured), len(got))
		}
		// 同じ回の続き（次の評価）でまとめが繰り返されない。
		if again := env.run(rules, state, now.Add(5*time.Minute)); len(again) != 0 {
			t.Fatalf("summary and summarised items should be under cooldown, got %v", again)
		}
	})

	t.Run("users", func(t *testing.T) {
		env := newNCFATestEnv(t)
		now := ncFABaseNow
		withStubs(t, now, nil)
		rules := ncFARules(ruleNCMassAccess)
		state := newAlertState()

		writeFile(t, env.auditPath, "")
		env.run(rules, state, now)
		var b strings.Builder
		for u := 0; u < 12; u++ {
			b.WriteString(ncFAAccessLines(now.Add(-30*time.Minute), 100*time.Millisecond, 300, fmt.Sprintf("u%04d@example.com", 1001+u), "203.0.113.5", uaBrowser, nil))
		}
		appendFile(t, env.auditPath, b.String())
		got := env.run(rules, state, now)
		if len(got) != 6 || countContaining(got, "ほか 7 件（同じルール）") != 1 {
			t.Fatalf("expected 5 alerts + 1 summary of 7, got %d: %v", len(got), got)
		}
	})
}

// audit.log が読めない（無い以外の理由）ときは毎回ログに 1 行出す。
func TestNCFileAccess_F3_UnreadableAuditLogIsLogged(t *testing.T) {
	env := newNCFATestEnv(t)
	logs := captureLog(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	if err := os.MkdirAll(env.auditPath, 0o755); err != nil { // ファイルの代わりにディレクトリがある
		t.Fatal(err)
	}
	rules := ncFARules(ruleNCMassAccess)
	state := newAlertState()
	env.run(rules, state, now)
	env.run(rules, state, now.Add(5*time.Minute))
	if n := strings.Count(logs.String(), "cannot read audit log"); n != 2 {
		t.Fatalf("an unreadable audit.log should be logged on every run, got %d:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), filepath.Base(env.auditPath)) {
		t.Fatalf("the log should name the path:\n%s", logs.String())
	}

	// ファイルが無いだけなら黙っている（Nextcloud の無いホスト）。
	env2 := newNCFATestEnv(t)
	logs2 := captureLog(t)
	env2.run(rules, newAlertState(), now)
	if strings.Contains(logs2.String(), "cannot read audit log") {
		t.Fatalf("a missing audit.log must stay quiet:\n%s", logs2.String())
	}
}

// 評価時刻より 5 分以上先の行は数えない（窓に残り続けて発報し続けるのを防ぐ）。
func TestNCFileAccess_F4_FutureLinesAreDropped(t *testing.T) {
	env := newNCFATestEnv(t)
	logs := captureLog(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	rules := ncFARules(ruleNCMassAccess)
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)
	appendFile(t, env.auditPath,
		ncFAAccessLines(now.Add(10*time.Minute), 100*time.Millisecond, 300, "alice@example.com", "203.0.113.5", uaBrowser, nil)+
			ncFAAccessLines(now.Add(4*time.Minute), 100*time.Millisecond, 300, "bob@example.com", "203.0.113.6", uaBrowser, nil))
	got := env.run(rules, state, now)
	if len(got) != 1 || !strings.Contains(got[0], "bob@example.com") {
		t.Fatalf("only bob (4 minutes ahead, within tolerance) should fire, got %v", got)
	}
	if ncFAUserCount(t, env, "alice@example.com") != 0 {
		t.Fatalf("lines 10 minutes in the future must not be kept")
	}
	if !strings.Contains(logs.String(), "future 300") {
		t.Fatalf("dropped future lines should be counted in the skipped-lines log:\n%s", logs.String())
	}
}

// 窓の開始より前に始まる 1 分刻みは数えない（窓が 61 分にならない）。
func TestNCFileAccess_F5_WindowIsAtMost60Minutes(t *testing.T) {
	env := newNCFATestEnv(t)
	t0 := time.Date(2026, 10, 14, 4, 10, 0, 0, time.UTC)
	withStubs(t, t0, nil)
	rules := ncFARules()
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, t0)
	appendFile(t, env.auditPath,
		ncFAAccessLines(time.Date(2026, 10, 14, 4, 5, 0, 0, time.UTC), 100*time.Millisecond, 300, "alice@example.com", "203.0.113.5", uaBrowser, nil)+
			ncFAAccessLines(time.Date(2026, 10, 14, 4, 6, 0, 0, time.UTC), 100*time.Millisecond, 10, "bob@example.com", "203.0.113.6", uaBrowser, nil))
	env.run(rules, state, t0)
	if got := ncFAUserCount(t, env, "alice@example.com"); got != 300 {
		t.Fatalf("setup: alice should be counted at t0, got %d", got)
	}

	// 05:05:30 の窓は 04:05:30 から。04:05 台の 1 分刻みは窓の開始より前に始まるので数えない。
	t1 := time.Date(2026, 10, 14, 5, 5, 30, 0, time.UTC)
	env.run(rules, state, t1)
	if got := ncFAUserCount(t, env, "alice@example.com"); got != 0 {
		t.Fatalf("the minute bucket starting before the window must not be counted, got %d", got)
	}
	if got := ncFAUserCount(t, env, "bob@example.com"); got != 10 {
		t.Fatalf("04:06 is inside the window and should still be counted, got %d", got)
	}
}

// 行区切り・段落区切り・書式制御（RLO 等）も通知文から除く。
func TestNCFASanitize_F6_StripsLineAndFormatChars(t *testing.T) {
	got := ncFASanitize("a\u2028b\u2029c\u202Ed\u200Be\x07f", 100)
	if got != "a?b?c?d?e?f" {
		t.Fatalf("ncFASanitize = %q", got)
	}
}

// 「初めての接続元」は IPv6 を /64、IPv4 をアドレスそのもので見る。
func TestNCFileAccess_F7_NewIPUsesIPv6Slash64(t *testing.T) {
	env := newNCFATestEnv(t)
	t0 := ncFABaseNow
	withStubs(t, t0, nil)
	rules := ncFARules(ruleNCNewIPAccess, ruleNCServiceNewIP)
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, t0)
	t1 := t0.Add(10 * time.Minute)
	appendFile(t, env.auditPath,
		ncFAAccessLines(t1.Add(-5*time.Minute), time.Second, 5, "bob@example.com", "2001:db8:1:2::10", uaBrowser, nil)+
			ncFAAccessLines(t1.Add(-5*time.Minute), time.Second, 5, "carol@example.com", "2001:db8:3:4::10", uaBrowser, nil)+
			ncFAAccessLines(t1.Add(-5*time.Minute), time.Second, 5, "dave@example.com", "192.0.2.10", uaBrowser, nil)+
			ncFALoginLine(t1.Add(-time.Minute), "svc-app", "2001:db8:5:5::1"))
	env.run(rules, state, t1)

	t2 := t0.Add(3*24*time.Hour + time.Hour)
	appendFile(t, env.auditPath,
		// bob: 一時アドレスが変わっただけ（同じ /64）→ 出ない
		ncFAAccessLines(t2.Add(-30*time.Minute), time.Second, 50, "bob@example.com", "2001:db8:1:2::abcd", uaBrowser, nil)+
			// carol: 別の /64 → 出る
			ncFAAccessLines(t2.Add(-30*time.Minute), time.Second, 50, "carol@example.com", "2001:db8:9:9::1", uaBrowser, nil)+
			// dave: IPv4 はアドレスそのもの → 隣のアドレスでも出る
			ncFAAccessLines(t2.Add(-30*time.Minute), time.Second, 50, "dave@example.com", "192.0.2.11", uaBrowser, nil)+
			// 連携アカウント: 同じ /64 → 出ない、別の /64 → 出る
			ncFALoginLine(t2.Add(-5*time.Minute), "svc-app", "2001:db8:5:5::2")+
			ncFALoginLine(t2.Add(-5*time.Minute), "svc-app", "2001:db8:6:6::1"))
	got := env.run(rules, state, t2)
	if len(got) != 3 {
		t.Fatalf("expected carol, dave and svc-app (2001:db8:6:6::1), got %d: %v", len(got), got)
	}
	if countContaining(got, "bob@example.com") != 0 || countContaining(got, "2001:db8:5:5::2") != 0 {
		t.Fatalf("addresses in an already used /64 must not be treated as new, got %v", got)
	}
	if countContaining(got, "新しい接続元 2001:db8:9:9::1") != 1 || countContaining(got, "接続元 2001:db8:6:6::1 から使われた") != 1 {
		t.Fatalf("the message should show the actual address, got %v", got)
	}
}

// alert_state.json の cooldown キーに利用者 ID・接続元を生で入れない。
func TestNCFileAccess_F8_CooldownKeysAreHashed(t *testing.T) {
	env := newNCFATestEnv(t)
	t0 := ncFABaseNow
	withStubs(t, t0, nil)
	rules := ncFARules(ruleNCMassAccess, ruleNCServiceNewIP)
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, t0)
	t1 := t0.Add(3*24*time.Hour + time.Hour)
	appendFile(t, env.auditPath,
		ncFAAccessLines(t1.Add(-30*time.Minute), time.Second, 300, "alice@example.com", "203.0.113.5", uaBrowser, nil)+
			ncFALoginLine(t1.Add(-5*time.Minute), "svc-app", "198.51.100.30"))
	if got := env.run(rules, state, t1); len(got) != 2 {
		t.Fatalf("setup: expected 2 alerts, got %v", got)
	}
	keyRe := regexp.MustCompile(`^nc_[a-z_]+:[0-9a-f]{16}$`)
	n := 0
	for key := range state.LastAlertTime {
		if !strings.HasPrefix(key, "nc_mass_access:") && !strings.HasPrefix(key, "nc_service_new_ip:") {
			continue
		}
		n++
		if !keyRe.MatchString(key) {
			t.Fatalf("cooldown key should be <rule>:<16 hex>, got %q", key)
		}
		for _, raw := range []string{"alice", "example.com", "svc-app", "203.0.113.5", "198.51.100.30"} {
			if strings.Contains(key, raw) {
				t.Fatalf("cooldown key %q must not contain %q", key, raw)
			}
		}
	}
	if n != 2 {
		t.Fatalf("expected 2 cooldown keys, got %d", n)
	}
	// 7 日を過ぎたハッシュのキーも掃除される。
	for key := range state.LastAlertTime {
		state.LastAlertTime[key] = t1.Add(-8 * 24 * time.Hour)
	}
	ncFAPruneCooldowns(state, t1)
	if len(state.LastAlertTime) != 0 {
		t.Fatalf("hashed keys should be pruned after 7 days, left %v", state.LastAlertTime)
	}
}

// ローテーションの端のケース（inode の使い回し・手の切り詰め・inode が取れない・別物の .1）。
func TestNCFileAccess_F11_RotationEdgeCases(t *testing.T) {
	const alice = "alice@example.com"
	now := ncFABaseNow
	access := func(start time.Time, n int) string {
		return ncFAAccessLines(start, time.Second, n, alice, "203.0.113.5", uaBrowser, nil)
	}
	// prepare は記録位置を大きくしてから 50 件を通常どおり読ませ、記録位置を返す。
	prepare := func(t *testing.T, env *ncFATestEnv) int64 {
		t.Helper()
		var pre strings.Builder
		for i := 0; i < 400; i++ {
			pre.WriteString(ncFALoginLine(now.Add(-50*time.Minute), "dave@example.com", "192.0.2.40"))
		}
		writeFile(t, env.auditPath, pre.String())
		env.run(ncFARules(), newAlertState(), now)
		appendFile(t, env.auditPath, access(now.Add(-45*time.Minute), 50))
		env.run(ncFARules(), newAlertState(), now)
		return env.loadState(t).Offsets[env.auditPath]
	}
	noMidLine := func(t *testing.T, logs fmt.Stringer) {
		t.Helper()
		if strings.Contains(logs.String(), "skipped lines") {
			t.Fatalf("no line may be read from the middle:\n%s", logs.String())
		}
	}

	t.Run("inode reused by the new file", func(t *testing.T) {
		env := newNCFATestEnv(t)
		ids := installFakeFileIDs(t)
		logs := captureLog(t)
		withStubs(t, now, nil)
		ids[filepath.Clean(env.auditPath)] = 100
		offset := prepare(t, env)
		appendFile(t, env.auditPath, access(now.Add(-40*time.Minute), 200))
		after := access(now.Add(-30*time.Minute), 700)
		renameRotate(t, ids, env.auditPath, 100, after) // 新しいファイルが同じ inode 番号を使った
		if int64(len(after)) <= offset {
			t.Fatalf("setup: new file must be larger than the offset")
		}
		env.run(ncFARules(), newAlertState(), now)
		if got := ncFAUserCount(t, env, alice); got != 50+200+700 {
			t.Fatalf("got %d, want %d", got, 50+200+700)
		}
		noMidLine(t, logs)
	})

	t.Run("manual truncation in create mode", func(t *testing.T) {
		env := newNCFATestEnv(t)
		ids := installFakeFileIDs(t)
		logs := captureLog(t)
		withStubs(t, now, nil)
		ids[filepath.Clean(env.auditPath)] = 100
		// 前日の .1（中身は別物、サイズは大きい）
		writeFile(t, env.auditPath+".1", strings.Repeat(ncFALoginLine(now.Add(-26*time.Hour), "erin@example.com", "192.0.2.50"), 800))
		ids[filepath.Clean(env.auditPath+".1")] = 90
		offset := prepare(t, env)
		appendFile(t, env.auditPath, access(now.Add(-40*time.Minute), 200))
		after := access(now.Add(-30*time.Minute), 700)
		writeFile(t, env.auditPath, after) // 手で切り詰めた後に育った（inode は同じ）
		if int64(len(after)) <= offset {
			t.Fatalf("setup: new content must be larger than the offset")
		}
		env.run(ncFARules(), newAlertState(), now)
		// 切り詰めで消えた 200 件は戻らない。前日の .1 は読まない。新しい中身は先頭から全部。
		if got := ncFAUserCount(t, env, alice); got != 50+700 {
			t.Fatalf("got %d, want %d", got, 50+700)
		}
		noMidLine(t, logs)
	})

	t.Run("no inode available, renamed file grown past the offset", func(t *testing.T) {
		env := newNCFATestEnv(t)
		ids := installFakeFileIDs(t) // 空のまま = inode が取れない
		logs := captureLog(t)
		withStubs(t, now, nil)
		offset := prepare(t, env)
		appendFile(t, env.auditPath, access(now.Add(-40*time.Minute), 200))
		after := access(now.Add(-30*time.Minute), 700)
		renameRotate(t, ids, env.auditPath, 0, after)
		delete(ids, filepath.Clean(env.auditPath))
		delete(ids, filepath.Clean(env.auditPath+".1"))
		if int64(len(after)) <= offset {
			t.Fatalf("setup: new file must be larger than the offset")
		}
		env.run(ncFARules(), newAlertState(), now)
		if got := ncFAUserCount(t, env, alice); got != 50+200+700 {
			t.Fatalf("got %d, want %d", got, 50+200+700)
		}
		noMidLine(t, logs)
	})

	t.Run(".1 that is not ours is not read", func(t *testing.T) {
		env := newNCFATestEnv(t)
		installFakeFileIDs(t)
		withStubs(t, now, nil)
		offset := prepare(t, env)
		// audit.log は切り詰められて小さい。.1 は記録位置より大きいが別物（先頭が違う）。
		other := strings.Repeat(ncFALoginLine(now.Add(-26*time.Hour), "erin@example.com", "192.0.2.50"), 500) +
			access(now.Add(-35*time.Minute), 120)
		writeFile(t, env.auditPath+".1", other)
		if int64(len(other)) < offset {
			t.Fatalf("setup: .1 must be at least as large as the offset")
		}
		writeFile(t, env.auditPath, access(now.Add(-30*time.Minute), 10))
		env.run(ncFARules(), newAlertState(), now)
		if got := ncFAUserCount(t, env, alice); got != 50+10 {
			t.Fatalf("got %d, want %d (the unrelated .1 must not be read)", got, 50+10)
		}
	})
}
