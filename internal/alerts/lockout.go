package alerts

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// lockoutEvent は account_lockout JSONL の 1 レコード。
// 旧 cmd/alerts の LockoutEvent と同一スキーマ（data/nc_extract/lockout_events.jsonl）。
type lockoutEvent struct {
	Timestamp string `json:"timestamp"`
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	IP        string `json:"ip"`
}

// lockoutLogPath は account_lockout JSONL のパスを返す。
// 旧 cmd/alerts のハードコード "/home/sab/data/nc_extract/lockout_events.jsonl" を // secrets-scan: allow
// SabPath（SAB_BASE_DIR 起点）に置き換える。
func lockoutLogPath(_ *config.AppConfig) string {
	return sab.SabPath("data/nc_extract/lockout_events.jsonl")
}

// evaluateAccountLockout は account_lockout JSONL を offset 方式で読み、
// 同一アカウントのロックアウトを集約（dedupe）し、cooldown を効かせて発報する。
//
// 旧実装は last_check_time より新しい各イベント毎に無条件 sendAlert していたため、
// 同じアカウントが連続でロックアウトすると大量のアラートが出ていた（shouldAlert を
// 通さず last_alert_time も更新しない不整合）。さらに tail はリングバッファ(2000)で、
// 2 チェック間に 2000 件超出ると取りこぼしていた。本実装はアカウント単位に集約して
// 「N events」とまとめ、ファイル末尾オフセット方式で取りこぼしを無くし、cooldown で
// 再発報を抑止する。
func evaluateAccountLockout(logPath string, rules AlertRules, state *AlertState) []string {
	const ruleID = "account_lockout"
	rule, defined := rules.Rules[ruleID]
	// オフセットは常に進めて取りこぼしを防ぐ。ルール無効でも読み飛ばしのため tail はする。
	prev := state.Offsets[logPath]
	events, next := readLockoutTail(logPath, prev)
	state.Offsets[logPath] = next
	if !defined || !rule.Enabled {
		return nil
	}

	// アカウント単位に集約（dedupe）。出現順を保持する。
	counts := map[string]int{}
	lastIP := map[string]string{}
	var order []string
	for _, ev := range events {
		acct := ev.Username
		if acct == "" {
			acct = ev.UserID
		}
		if acct == "" {
			continue
		}
		if _, seen := counts[acct]; !seen {
			order = append(order, acct)
		}
		counts[acct]++
		if ev.IP != "" {
			lastIP[acct] = ev.IP
		}
	}

	now := nowFn()
	var out []string
	for _, acct := range order {
		key := ruleID + ":" + acct
		// account_lockout は sustainSec を持たない（即時集約発報 + cooldown）。
		if shouldAlert(key, 0, rule.CooldownSec, state, now) {
			msg := fmt.Sprintf("アカウントロックアウト: %s (%d 件)", acct, counts[acct])
			if ip := lastIP[acct]; ip != "" {
				msg += fmt.Sprintf(" (IP: %s)", ip)
			}
			out = append(out, fire(rules, ruleID, msg))
		}
	}
	return out
}

// readLockoutTail は account_lockout JSONL を offset ベースで読み、
// パース成功したイベントを返す。パース不能行はスキップする（取りこぼし防止のため
// offset は最後まで進める）。
func readLockoutTail(path string, prevOffset int64) ([]lockoutEvent, int64) {
	f, err := os.Open(path)
	if err != nil {
		return nil, prevOffset
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, prevOffset
	}
	size := fi.Size()
	start := prevOffset
	if start > size || start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, 0); err != nil {
		return nil, prevOffset
	}

	var events []lockoutEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var ev lockoutEvent
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		events = append(events, ev)
	}
	return events, size
}
