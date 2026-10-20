package target

import (
	"fmt"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"strings"
)

type Mode string

const (
	ModeLocal    Mode = "local"
	ModePrimary  Mode = "primary-agent"
	ModeRemote   Mode = "remote-agent"
	ModeSnapshot Mode = "snapshot-readonly"
)

type Context struct {
	AgentID string
	Mode    Mode
}

// Resolve は agentID を Context に解決する。
//
// C-039（target-resolve-tenant-boundary）: 呼び出し側に tenant 境界の表明を
// 強制するため、必ず expectedTenantID（現在のセッション/リクエストが属する
// tenant_id）を受け取る。agentID プレフィックス（"<tenant_id>-<type>-<name>"）
// から抽出した tenant_id と expectedTenantID が一致しない場合はエラーを返し、
// cross-tenant 漏洩経路ができないようにする。
//
// expectedTenantID が空文字の場合は tenant チェックを行わず、agentID も
// 空（default_agent）であれば ModeLocal を返す（シングルテナント運用や
// 起動時の boot context 用途）。それ以外で expectedTenantID が空のときは
// 明示的にエラーを返し、暗黙の境界スキップを禁止する。
func Resolve(agentID string, expectedTenantID string, cfg *config.AppConfig) (Context, error) {
	id := strings.TrimSpace(agentID)
	if id == "" || id == "default_agent" {
		id = strings.TrimSpace(cfg.UI.DefaultAgent)
		if id == "" {
			return Context{Mode: ModeLocal}, nil
		}
	}
	agent, ok := cfg.Agents[id]
	if !ok {
		return Context{}, fmt.Errorf("unknown agent: %s", id)
	}
	// C-039: tenant 境界チェック。expectedTenantID が指定されている場合のみ
	// 検証する（空文字は「呼び出し元が tenant 文脈を持たない」ことを明示）。
	if expected := strings.TrimSpace(expectedTenantID); expected != "" {
		actual := tenantIDFromAgentID(id)
		if actual == "" {
			return Context{}, fmt.Errorf("agent_id has no tenant prefix: %s", id)
		}
		if actual != expected {
			return Context{}, fmt.Errorf("agent_id tenant mismatch: agent=%s expected_tenant=%s", id, expected)
		}
	}
	if agent.IsPrimary {
		return Context{AgentID: id, Mode: ModePrimary}, nil
	}
	if strings.EqualFold(agent.AgentType, "rental") {
		return Context{AgentID: id, Mode: ModeSnapshot}, nil
	}
	return Context{AgentID: id, Mode: ModeRemote}, nil
}

// tenantIDFromAgentID は "<tenant_id>-<type>-<name>" 形式の agent_id から
// tenant_id を抽出する。形式が一致しない場合は空文字を返す。
//
// 同名の関数が core/monitor 側にもあるが、target パッケージから core/monitor
// に依存させない（target は internal/config のみ参照する低レイヤ）ため、
// ここに同一ロジックを最小実装で持つ。
func tenantIDFromAgentID(agentID string) string {
	idx := strings.Index(agentID, "-")
	if idx <= 0 {
		return ""
	}
	return agentID[:idx]
}
