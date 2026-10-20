package alerts

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/nclog"
)

// ruleNCUserCreated / ruleNCUserFirstLogin は notification_rules.go の
// AlertRuleDefs に定義済みのルール ID。
const (
	ruleNCUserCreated    = "nc_user_created"
	ruleNCUserFirstLogin = "nc_user_first_login"
)

// ncPendingUserTTL は「作成検出済みだが初回ログイン未検出」の uid を
// AlertState.PendingNCUsers に保持しておく最大期間。これを超えたら初回ログインの
// 突き合わせをあきらめて破棄する（未ログインのまま無期限に増え続けるのを防ぐ）。
const ncPendingUserTTL = 30 * 24 * time.Hour

// ncAgentIDPattern は agent_id 全体の厳格バリデータ（C7: agentid-path-no-sanitize）。
// internal/agentstore.agentIDPattern / core/monitor.agentIDPattern と同一規則
// （"<テナント ID>-<以降>"。例: alpha-vps-host1）。
// internal/alerts は core/monitor を import できない（依存方向の都合）ため自前で保持する。
var ncAgentIDPattern = regexp.MustCompile(`^[a-z0-9_]+-[a-z0-9_][a-z0-9_-]*$`)

// ncLogLine は nextcloud.jsonl / agents/<id>/{audit,nextcloud_login}.jsonl の
// 1 レコードのうち、判定に使うフィールドだけを取り出す最小デコード対象。
type ncLogLine struct {
	TS   string `json:"ts"`
	User string `json:"user"`
	Msg  string `json:"msg"`
}

// ncSource は 1 つの Nextcloud（Monitor 自身、または Nextcloud 連携ありの Agent 1 台）を表す。
type ncSource struct {
	scope string   // AlertState（PendingNCUsers・cooldown key）で使うスコープ識別子。"local" または agent_id。
	label string   // 通知文に出す表示（テナント ID または agent_id）。
	paths []string // 読み取り対象 JSONL のフルパス。
}

// ncLocalJSONLPath は Monitor 自身の Nextcloud（Agent 経由ではない）が書く
// data/logs/nextcloud.jsonl のパス。core/monitor.ncJSONLPath()/ncAuditJSONLPath() の
// agentID=="" のケースと同一（ログイン・作成イベントが 1 ファイルに混在する）。
func ncLocalJSONLPath() string {
	return sab.SabPath("data/logs/nextcloud.jsonl")
}

// ncAgentJSONLPath は Agent の Nextcloud イベント JSONL パスを返す。
// agent_id を厳格パターンで検証し、合致しない場合や base（data/logs/agents）配下から
// 外れる場合は ok=false（読み取り対象から除外。書き込み側の agentstore.EventJSONL と
// 異なり、読み取りでは隔離ファイルへフォールバックせず単に無視する）。
// kind は "audit"（audit.log 由来。User created を含む）または "nextcloud_login"
// （nextcloud.log 由来。ログインイベントを含む）。
func ncAgentJSONLPath(agentID, kind string) (string, bool) {
	id := strings.TrimSpace(agentID)
	if !ncAgentIDPattern.MatchString(id) {
		return "", false
	}
	base := sab.SabPath("data/logs/agents")
	joined := filepath.Clean(filepath.Join(base, id, kind+".jsonl"))
	baseClean := filepath.Clean(base)
	if joined != baseClean && !strings.HasPrefix(joined, baseClean+string(filepath.Separator)) {
		return "", false
	}
	return joined, true
}

// ncSources は評価対象の Nextcloud 一覧を返す（Monitor 自身 + capability
// "module.nextcloud" を持つ Agent）。順序を安定させるため agent_id でソートする。
func ncSources(cfg *config.AppConfig) []ncSource {
	localLabel := "local"
	if cfg != nil {
		if t := strings.TrimSpace(cfg.VendorLicense.TenantID); t != "" {
			localLabel = t
		}
	}
	out := []ncSource{{scope: "local", label: localLabel, paths: []string{ncLocalJSONLPath()}}}

	if cfg == nil {
		return out
	}
	ids := make([]string, 0, len(cfg.Agents))
	for id := range cfg.Agents {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		hasNC := false
		for _, c := range cfg.AgentCapabilities(id) {
			if c == "module.nextcloud" {
				hasNC = true
				break
			}
		}
		if !hasNC {
			continue
		}
		auditPath, ok1 := ncAgentJSONLPath(id, "audit")
		loginPath, ok2 := ncAgentJSONLPath(id, "nextcloud_login")
		if !ok1 || !ok2 {
			continue
		}
		out = append(out, ncSource{scope: id, label: id, paths: []string{auditPath, loginPath}})
	}
	return out
}

// readNCTail は Nextcloud イベント JSONL を offset ベースで読む（lockout.go の
// readLockoutTail / resource.go の readResourceTail と同型）。
//
// 3 つ目の戻り値は「このファイルを実際に読めたか」。読めなかった場合
// （ファイル未生成・stat / seek 失敗）は false を返し、呼び出し側は
// AlertState.Offsets へ記録しない。記録してしまうと、後からそのファイルが
// 過去分を抱えて出現したときに「一度見たファイル」と誤認し、
// offset 0 から全件を発報してしまう（Agent を後から追加した場合に起きる。
// Agent の初回レポートは手元のログ全体を含むため）。
func readNCTail(path string, prevOffset int64) ([]ncLogLine, int64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, prevOffset, false
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, prevOffset, false
	}
	size := fi.Size()
	start := prevOffset
	if start > size || start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, 0); err != nil {
		return nil, prevOffset, false
	}

	var lines []ncLogLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var l ncLogLine
		if json.Unmarshal(sc.Bytes(), &l) != nil {
			continue
		}
		lines = append(lines, l)
	}
	return lines, size, true
}

// evaluateNCUserEvents は Nextcloud の「新規ユーザー作成」「新規ユーザーの初回ログイン」を
// 評価する（evaluateAccountLockout と同型）。判定そのものは nclog（共有パッケージ）の
// 純粋関数を使い、ここでは読み取り（offset tail）・状態管理・発報だけを行う。
//
// 読み取り先は複数ある: Monitor 自身の data/logs/nextcloud.jsonl（作成・ログインが
// 1 ファイルに混在）と、Nextcloud 連携ありの Agent ごとの
// data/logs/agents/<agent_id>/{audit,nextcloud_login}.jsonl（作成はaudit、ログインは
// nextcloud_login に分かれる）。AlertState.Offsets はファイルパスごとに独立して持つ。
//
// 初回実行時（そのパスを AlertState.Offsets で一度も見ていないとき）は、オフセットを
// ファイル末尾まで進めるだけで発報しない。素直に offset=0 から読むと、保持されている
// 全期間分の「User created」が新規ユーザー作成として一斉に流れてしまうため。
//
// 初回ログインは作成と同じ評価タイミングとは限らないため、作成を検出した uid は
// AlertState.PendingNCUsers に scope（"local" または agent_id）+ uid 単位で覚えておき、
// 以後の評価で一致する Login successful が来た時点で初回ログインとして発報する。
// ncPendingUserTTL を超えて未ログインの uid は破棄する。
func evaluateNCUserEvents(cfg *config.AppConfig, rules AlertRules, state *AlertState) []string {
	createdRule, createdDefined := rules.Rules[ruleNCUserCreated]
	firstLoginRule, firstLoginDefined := rules.Rules[ruleNCUserFirstLogin]

	now := nowFn()
	var out []string

	for _, src := range ncSources(cfg) {
		var createdEvents []struct {
			Time string
			UID  string
		}
		var loginEvents []struct {
			Time string
			UID  string
		}

		for _, path := range src.paths {
			prevOffset, seenBefore := state.Offsets[path]
			lines, next, readable := readNCTail(path, prevOffset)
			if !readable {
				// まだ存在しない（または読めない）。ここで記録すると、後から
				// 過去分を抱えて出現したときに全件を発報してしまう。
				continue
			}
			state.Offsets[path] = next
			if !seenBefore {
				// 初回評価: このファイルは今回はじめて見た。末尾まで進めるだけで
				// 発報対象にしない（保持されている過去分の一斉発報を防ぐ）。
				continue
			}
			for _, l := range lines {
				if uid := nclog.ExtractUserCreated(l.Msg); uid != "" {
					createdEvents = append(createdEvents, struct {
						Time string
						UID  string
					}{Time: l.TS, UID: uid})
					continue
				}
				if nclog.ExtractLoginResult(l.Msg) == "success" {
					uid := strings.TrimSpace(l.User)
					if uid == "" {
						uid = nclog.ExtractLoginUserFromMessage(l.Msg)
					}
					if uid == "" {
						continue
					}
					loginEvents = append(loginEvents, struct {
						Time string
						UID  string
					}{Time: l.TS, UID: uid})
				}
			}
		}

		for _, ev := range createdEvents {
			if createdDefined && createdRule.Enabled {
				key := ruleNCUserCreated + ":" + src.scope + ":" + ev.UID
				if shouldAlert(key, 0, createdRule.CooldownSec, state, now) {
					out = append(out, fire(rules, ruleNCUserCreated, ncUserMessage("Nextcloud 新規ユーザー作成", ev.UID, src.label, ev.Time)))
				}
			}

			createdAt := now
			if t, ok := nclog.ParseTime(ev.Time); ok {
				createdAt = t
			}
			state.PendingNCUsers[src.scope+"|"+ev.UID] = createdAt
		}

		for _, ev := range loginEvents {
			pendingKey := src.scope + "|" + ev.UID
			createdAt, pending := state.PendingNCUsers[pendingKey]
			if !pending {
				continue
			}
			if t, ok := nclog.ParseTime(ev.Time); ok && t.Before(createdAt) {
				// ログの並び順の乱れ等で作成より前に見えるログインは対象にしない。
				continue
			}
			// 初回ログインとして消費する（以後の 2 回目以降のログインは対象外）。
			delete(state.PendingNCUsers, pendingKey)

			if firstLoginDefined && firstLoginRule.Enabled {
				key := ruleNCUserFirstLogin + ":" + pendingKey
				if shouldAlert(key, 0, firstLoginRule.CooldownSec, state, now) {
					out = append(out, fire(rules, ruleNCUserFirstLogin, ncUserMessage("Nextcloud 新規ユーザー初回ログイン", ev.UID, src.label, ev.Time)))
				}
			}
		}
	}

	for key, createdAt := range state.PendingNCUsers {
		if now.Sub(createdAt) > ncPendingUserTTL {
			delete(state.PendingNCUsers, key)
		}
	}

	return out
}

// ncUserMessage は通知文を組み立てる。どの Nextcloud（テナント/Agent）の誰の話かが
// 受け取った側に分かるよう、label（テナント ID または agent_id）・uid・時刻を必ず入れる。
func ncUserMessage(label, uid, scopeLabel, ts string) string {
	msg := fmt.Sprintf("%s: %s (%s)", label, uid, scopeLabel)
	if ts != "" {
		msg += " " + ts
	}
	return msg
}
