package monitor

import (
	"net/http"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
)

// enforceAgentTenantBoundary は ?agent=<agent_id> のテナント越境を防ぐ統一ヘルパ。
//
// dispatchAPI / dispatchAction /
// APICard はいずれも ?agent=<agent_id> を受けて該当 agent の SQLite/JSONL を
// 読み書きするため、isValidAgentID のパス安全性チェックだけでなく
// 「セッションのテナントと agent_id 先頭の tenant prefix が一致するか」も検証する。
// 集約 Monitor（例: テナント beta が別テナント alpha の agent_report を
// 受け取る構成）では、alpha 系の操作者が ?agent=beta-vps-host1 を
// 渡すと他テナントのログ/イベントを読み出せてしまう。これを防ぐ。
// また action_registry.isMonitorActionAllowed が tenant == nil でフェイルオープン
// しないことも、ここの検証で担保する。
//
// 仕様:
//   - agentID が空（= ローカル Monitor 本体扱い）: 常に許可（true）
//   - agentID が isValidAgentID を通らない: false（呼び出し側で 400 を返している前提）
//   - セッションが取得できない: false（fail-closed）
//   - sess.Role == vendor_staff: 常に許可（クロステナント運用が設計上必要）
//   - tenantIDFromAgentID(agentID) == sess.TenantID: 許可
//   - 上記以外（sess.TenantID 未設定含む）: false（fail-closed）
//
// 呼び出し側は false 時に HTTP 403 を返すこと。本関数はレスポンスを書かない。
func enforceAgentTenantBoundary(r *http.Request, agentID string) bool {
	sess, ok := auth.DefaultSessionManager().SessionFromRequest(r)
	if !ok {
		// セッションなしでも agentID が空（ローカル）なら通す。
		// それ以外は fail-closed。
		return strings.TrimSpace(agentID) == ""
	}
	return checkAgentTenantBoundary(sess.Role, sess.TenantID, agentID)
}

// checkAgentTenantBoundary は enforceAgentTenantBoundary の純粋ロジック部。
// セッション情報を引数で受け取るためテストしやすい。
func checkAgentTenantBoundary(sessRole, sessTenantID, agentID string) bool {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return true
	}
	if !isValidAgentID(agentID) {
		return false
	}
	if auth.Role(auth.NormalizeRole(sessRole)) == auth.RoleVendorStaff {
		return true
	}
	sessTenant := strings.TrimSpace(sessTenantID)
	if sessTenant == "" {
		return false
	}
	agentTenant := tenantIDFromAgentID(agentID)
	if agentTenant == "" {
		return false
	}
	return agentTenant == sessTenant
}
