package alerts

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// nc_mass_delete（大量削除）のテスト。ルール ID は定数ではなく文字列で書く
// （ルールを入れる前のコードでもコンパイルでき、失敗として確かめられるようにするため）。
const ncMassDeleteRule = "nc_mass_delete"

func ncFADeleteLine(ts time.Time, user, ip, ua, filePath string, id int) string {
	return ncFARecord(ts, user, ip, ua, fmt.Sprintf(`File with id "%d" deleted: "%s"`, id, filePath))
}

func ncFADeleteLines(start time.Time, step time.Duration, n int, user, ip, ua string) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		p := fmt.Sprintf("/%s/files/営業/見積/d%d.pdf", user, i)
		b.WriteString(ncFADeleteLine(start.Add(time.Duration(i)*step), user, ip, ua, p, 5000+i))
	}
	return b.String()
}

// 取得を 1 件もしていない利用者（同期ソフトが削除だけをした形）でも、実行をまたいで数えて
// しきい値ちょうど（300）で 1 回だけ出る。299 では出ない。
func TestNCMassDelete_DeleteOnlyUserBoundaryAcrossRuns(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	captured := withStubs(t, now, nil)
	rules := ncFARules(ncMassDeleteRule)
	state := newAlertState()

	// 初回は溜まっている分を読み飛ばす（取得ルールと同じ）。
	writeFile(t, env.auditPath, ncFADeleteLines(now.Add(-40*time.Minute), time.Second, 500, "alice@example.com", "203.0.113.5", uaBrowser))
	if got := env.run(rules, state, now); len(got) != 0 {
		t.Fatalf("first run must not fire for the backlog, got %v", got)
	}

	appendFile(t, env.auditPath, ncFADeleteLines(now.Add(-20*time.Minute), time.Second, 299, "alice@example.com", "203.0.113.5", uaBrowser))
	if got := env.run(rules, state, now); len(got) != 0 {
		t.Fatalf("299 deletions must not fire, got %v", got)
	}

	appendFile(t, env.auditPath, ncFADeleteLine(now.Add(-time.Minute), "alice@example.com", "203.0.113.5", uaBrowser, "/alice@example.com/files/営業/last.pdf", 9999))
	got := env.run(rules, state, now)
	if len(got) != 1 {
		t.Fatalf("300 deletions must fire once, got %d: %v", len(got), got)
	}
	want := "Nextcloud 大量削除: alice@example.com が直近 60 分で 300 件削除（主な接続元 203.0.113.5）(alpha) 窓 13:05〜14:05\n" +
		"初動: 本人確認 → occ user:disable alice@example.com → 監査ログで範囲確定"
	if got[0] != want {
		t.Fatalf("unexpected message:\n got: %q\nwant: %q", got[0], want)
	}
	if len(*captured) != 1 || !strings.HasPrefix((*captured)[0], ncMassDeleteRule+"|") {
		t.Fatalf("sender should be called once with nc_mass_delete, got %v", *captured)
	}
}

// 削除は取得の件数・接続元には混ざらない（取得のルールを有効にしても削除で出ない）。
func TestNCMassDelete_DoesNotFeedAccessRules(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	rules := ncFARules(ruleNCMassAccess, ruleNCNewIPAccess, ruleNCFolderSweep, ruleNCOffHoursAccess)
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)
	appendFile(t, env.auditPath, ncFADeleteLines(now.Add(-30*time.Minute), time.Second, 1000, "alice@example.com", "203.0.113.5", uaBrowser))
	if got := env.run(rules, state, now); len(got) != 0 {
		t.Fatalf("deletions must not fire access rules, got %v", got)
	}
}

// 削除の行でも、ゴミ箱からの復元や削除と無関係な文言は数えない。
func TestNCMassDelete_OnlyCountsDeletedLines(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	rules := ncFARules(ncMassDeleteRule)
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)
	var b strings.Builder
	for i := 0; i < 400; i++ {
		ts := now.Add(-30*time.Minute + time.Duration(i)*time.Second)
		b.WriteString(ncFARecord(ts, "alice@example.com", "203.0.113.5", uaBrowser, fmt.Sprintf(`File "/files/営業/r%d.pdf" restored from trash bin.`, i)))
		b.WriteString(ncFARecord(ts, "alice@example.com", "203.0.113.5", uaBrowser, fmt.Sprintf(`Cache entry inserted for fileid "%d", path "trash/x" on storageid "1"`, i)))
		b.WriteString(ncFARecord(ts, "alice@example.com", "203.0.113.5", uaBrowser, fmt.Sprintf(`File with id "%d" renamed: "a deleted: b"`, i)))
	}
	appendFile(t, env.auditPath, b.String())
	if got := env.run(rules, state, now); len(got) != 0 {
		t.Fatalf("non-delete lines must not be counted, got %v", got)
	}
}

// 連携アカウント（夜間の原本削除など）は対象外。ほかの利用者は出る。
func TestNCMassDelete_ServiceAccountExcluded(t *testing.T) {
	env := newNCFATestEnv(t) // svc-app が連携アカウント
	now := ncFABaseNow
	withStubs(t, now, nil)
	rules := ncFARules(ncMassDeleteRule)
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)
	appendFile(t, env.auditPath,
		ncFADeleteLines(now.Add(-30*time.Minute), time.Second, 400, "svc-app", "198.51.100.10", uaCurl)+
			ncFADeleteLines(now.Add(-20*time.Minute), time.Second, 300, "bob@example.com", "203.0.113.9", uaBrowser))
	got := env.run(rules, state, now)
	if len(got) != 1 || !strings.Contains(got[0], "bob@example.com") || countContaining(got, "svc-app") != 0 {
		t.Fatalf("only bob should fire, got %v", got)
	}
}

// 窓（60 分）より前の削除は数えない。cooldown 中は同じ利用者を繰り返し通知しない。
func TestNCMassDelete_WindowAndCooldown(t *testing.T) {
	env := newNCFATestEnv(t)
	now := ncFABaseNow
	withStubs(t, now, nil)
	rules := ncFARules(ncMassDeleteRule)
	state := newAlertState()

	writeFile(t, env.auditPath, "")
	env.run(rules, state, now)
	appendFile(t, env.auditPath, ncFADeleteLines(now.Add(-90*time.Minute), time.Second, 400, "alice@example.com", "203.0.113.5", uaBrowser))
	if got := env.run(rules, state, now); len(got) != 0 {
		t.Fatalf("deletions older than the window must not fire, got %v", got)
	}

	appendFile(t, env.auditPath, ncFADeleteLines(now.Add(-30*time.Minute), time.Second, 300, "alice@example.com", "203.0.113.5", uaBrowser))
	if got := env.run(rules, state, now); len(got) != 1 {
		t.Fatalf("300 deletions in window must fire once, got %v", got)
	}
	// 同じ窓のまま 5 分後にもう 1 回評価しても、cooldown 中は出ない。
	if got := env.run(rules, state, now.Add(5*time.Minute)); len(got) != 0 {
		t.Fatalf("cooldown must suppress the repeat, got %v", got)
	}
}
