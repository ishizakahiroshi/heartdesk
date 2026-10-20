package agentstore

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

// agentIDPattern は agent_id 全体の厳格バリデータ（C7: agentid-path-no-sanitize）。
// 形式は "<テナント ID>-<以降>"。テナント ID は小文字英数字とアンダースコア（ハイフンを含まない）、
// 以降は小文字英数字・ハイフン・アンダースコア（先頭はハイフン不可）。
// 例: alpha-vps-host1 / t101-vps-host1 / tenant_b-rental-host-2。
// monitor.agentIDPattern と同一規則。
// agentstore は monitor をインポートできない（依存方向の都合）ため自前で保持する。
var agentIDPattern = regexp.MustCompile(`^[a-z0-9_]+-[a-z0-9_][a-z0-9_-]*$`)

// EventJSONL は agent イベントの JSONL ファイルパスを返す。
//
// C7（agentid-path-no-sanitize）: agent_id を厳格パターンで検証し、合致しない場合は
// base 配下の "events__invalid.jsonl" へ隔離する（パストラバーサルで base 外へ抜けることを防ぐ）。
// さらに filepath.Clean + base 接頭辞チェックで base 配下に収まることを保証する。
func EventJSONL(agentID string) string {
	base := heartdesk.Path("data/logs/agents")
	name := "events_" + agentID + ".jsonl"
	if !agentIDPattern.MatchString(strings.TrimSpace(agentID)) {
		name = "events__invalid.jsonl"
	}
	joined := filepath.Clean(filepath.Join(base, name))
	baseClean := filepath.Clean(base)
	if joined != baseClean && !strings.HasPrefix(joined, baseClean+string(filepath.Separator)) {
		// 念のための最終防壁: base 外へ抜けたら隔離ファイルへ。
		return filepath.Join(baseClean, "events__invalid.jsonl")
	}
	return joined
}
