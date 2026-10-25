package monitor

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/internal/audit"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/authz"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
	"github.com/ishizakahiroshi/heartdesk/internal/scheduler"
)

// ---- POST アクションディスパッチャ ----

// actionRequiredComponent はアクションが属する config.toml [components] のコンポーネント名を
// 定義する。ここに載せたアクションは、そのコンポーネントが無効のとき個別ハンドラを書き換えず
// 「unknown action」404 で塞がれる。初期値は空（navmeta の cardRequiredComponents と同じ考え方）。
var actionRequiredComponent = map[string]string{}

// dispatchAction は POST ?api=xxx に応じたアクションを実行する
func (h *Handler) dispatchAction(w http.ResponseWriter, r *http.Request, api string) {
	// 無効化されたコンポーネントに属するアクションは、CSRF/認可判定より前に
	// 「unknown action」404 で塞ぐ（fail-closed）。既存の「unknown action」既定分岐
	// （本関数末尾の default ケース）と同じ応答形にして、コンポーネント無効時は
	// そもそもアクションが存在しないのと区別が付かないようにする。
	if component, ok := actionRequiredComponent[api]; ok && !h.appCfg.ComponentEnabled(component) {
		writeActionError(w, "unknown action: "+api, http.StatusNotFound)
		return
	}

	event := "ACTION_" + strings.ToUpper(strings.TrimSpace(api))
	user := middleware.GetUser(r.Context())
	role := middleware.GetRole(r.Context())

	// X-Requested-With は XHR 強制の付随策であり、CSRF の正規防御は
	// auth.VerifyCSRF（RequireScreen ミドルウェア内）に一本化されている。
	// dispatchAction は router.go → main.go の RequireScreen(ScreenMonitor) 配下で
	// 呼ばれるため CSRF は既に検証済みだが、将来この関数を認可ミドルウェア外で
	// 再利用しても CSRF が抜けないよう、ここでも冪等に VerifyCSRF を明示実行する
	// 多重防御とする。
	if r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
		writeActionError(w, "不正なリクエスト", http.StatusForbidden)
		audit.LogRequest(r, event, user, role, "fail", "不正なリクエスト", map[string]string{
			"http_status": strconv.Itoa(http.StatusForbidden),
		})
		return
	}
	if err := auth.VerifyCSRF(r); err != nil {
		writeActionError(w, "CSRF トークンが不正です", http.StatusForbidden)
		audit.LogRequest(r, event, user, role, "fail", "CSRF トークンが不正です", map[string]string{
			"http_status": strconv.Itoa(http.StatusForbidden),
		})
		return
	}
	// Vendor Console 専用アクションは ScreenVendor を持つセッションのみ許可。認可判定を requireVendorScreen に集約。
	if isVendorAction(api) {
		if !requireVendorScreen(w, r) {
			audit.LogRequest(r, event, user, role, "fail", "Vendor Console へのアクセス権限がありません", map[string]string{
				"http_status": strconv.Itoa(http.StatusForbidden),
			})
			return
		}
	}
	// セッション欠落時は action ACL をスキップせず fail-closed。
	session, ok := auth.DefaultSessionManager().SessionFromRequest(r)
	if !ok {
		writeActionError(w, "ログインが必要です", http.StatusUnauthorized)
		audit.LogRequest(r, event, user, role, "fail", "セッションなし", map[string]string{
			"http_status": strconv.Itoa(http.StatusUnauthorized),
		})
		return
	}
	if !isMonitorActionAllowed(r, session, api) {
		writeActionError(w, "このアカウントでは実行できない操作です", http.StatusForbidden)
		audit.LogRequest(r, event, user, role, "fail", "このアカウントでは実行できない操作です", map[string]string{
			"http_status": strconv.Itoa(http.StatusForbidden),
		})
		return
	}
	actionKey := normalizeMonitorActionKey(api)
	targetAgentID := strings.TrimSpace(r.URL.Query().Get("agent"))
	// action API も ?agent= を受けるため、agent_id 形式の厳格検証と
	// tenant 越境チェックをローカル agent の同視化より前に実施する。
	// 従来は isMonitorActionAllowed 内で tenant == nil の場合にフェイルオープン
	// していたが、enforceAgentTenantBoundary で fail-closed に統一する。
	if targetAgentID != "" && !isValidAgentID(targetAgentID) {
		writeActionError(w, "agent_id 形式が不正です", http.StatusBadRequest)
		audit.LogRequest(r, event, user, role, "fail", "agent_id 形式が不正です", map[string]string{
			"http_status": strconv.Itoa(http.StatusBadRequest),
			"agent_id":    targetAgentID,
		})
		return
	}
	if targetAgentID != "" && !enforceAgentTenantBoundary(r, targetAgentID) {
		writeActionError(w, "このテナントではこの agent を操作できません", http.StatusForbidden)
		audit.LogRequest(r, event, user, role, "fail", "tenant 境界外の agent_id", map[string]string{
			"http_status": strconv.Itoa(http.StatusForbidden),
			"agent_id":    targetAgentID,
		})
		return
	}
	// heartdesk 自身のサーバー（is_primary = true の agent）はローカル実行と同等なので agentID="" 扱いにする。
	// それ以外の agent は、ここで "" にしない（遠隔の agent への操作が heartdesk のサーバーで実行されるのを防ぐ）。
	if h.appCfg.IsLocalAgent(targetAgentID) {
		targetAgentID = ""
	}
	if targetAgentID != "" && isAgentUnsupportedAction(actionKey) {
		seen := GetAgentLastSeenByID(targetAgentID)
		msg := "agent 指定での操作APIは未対応です（deploy/SSH 手順を使用してください）"
		reportedType := ""
		if seen != nil {
			reportedType = seen.AgentType
		}
		if h.appCfg.EffectiveAgentType(targetAgentID, reportedType) == "rental" {
			msg = "rental agent は read-only のため、この操作は実行できません"
		}
		writeActionError(w, msg, http.StatusForbidden)
		audit.LogRequest(r, event, user, role, "fail", msg, map[string]string{
			"http_status": strconv.Itoa(http.StatusForbidden),
			"agent_id":    targetAgentID,
		})
		return
	}

	aw := &actionAuditWriter{ResponseWriter: w, statusCode: http.StatusOK}

	// multipart/form-data のため Content-Type を先にセットしない
	if api == "upload_avatar" {
		h.actionUploadAvatar(aw, r)
		logActionAudit(r, event, user, role, aw.statusCode, aw.body.String())
		return
	}

	aw.Header().Set("Content-Type", "application/json; charset=utf-8")
	if jobID, ok := scheduler.ResolveOnDemandJobID(api); ok {
		h.actionRunSchedulerJob(aw, r, api, jobID)
		logActionAudit(r, event, user, role, aw.statusCode, aw.body.String())
		return
	}

	if endpoint, ok := endpointByName(extensionRegistry.Actions, api); ok {
		h.dispatchExtension(aw, r, endpoint)
		logActionAudit(r, event, user, role, aw.statusCode, aw.body.String())
		return
	}
	switch api {
	// --- アラート設定の保存アクション ---
	case "save_alert_rules":
		h.actionSaveAlertRules(aw, r)
	case "save_alert_recipients":
		h.actionSaveAlertRecipients(aw, r)
	// --- Services アクション ---
	case "maintenance_on":
		h.actionSetMaintenance(aw, r, true)
	case "maintenance_off":
		h.actionSetMaintenance(aw, r, false)
	case "nc_repair":
		h.actionNCRepair(aw, r)
	case "restart_heartdesk":
		h.actionRestartHeartdesk(aw, r)
	case "reboot":
		h.actionReboot(aw, r)
	// --- Updates アクション ---
	case "apt_update":
		h.actionAptUpdate(aw, r)
	case "apt_upgrade":
		h.actionAptUpgrade(aw, r)
	case "apt_full_upgrade":
		h.actionAptFullUpgrade(aw, r)
	case "toggle_auto_update":
		h.actionToggleAutoUpdate(aw, r)
	// --- fail2ban・IP・ユーザー管理・ホワイトリストのアクション ---
	case "fail2ban_ban":
		h.actionFail2banBan(aw, r)
	case "fail2ban_unban":
		h.actionFail2banUnban(aw, r)
	case "ip_add":
		h.actionIPAdd(aw, r)
	case "ip_remove":
		h.actionIPRemove(aw, r)
	case "ip_rename":
		h.actionIPRename(aw, r)
	case "ip_changetype":
		h.actionIPChangeType(aw, r)
	case "user_mgmt_create":
		CreateUser(aw, r)
	case "user_mgmt_save":
		SaveAuthzPolicy(aw, r)
	case "user_mgmt_reset":
		ResetAuthzPolicy(aw, r)
	case "user_mgmt_delete":
		DeleteUser(aw, r)
	case "wl_add":
		h.actionWLAdd(aw, r)
	case "wl_remove":
		h.actionWLRemove(aw, r)
	// --- プロフィール ---
	case "update_profile_name":
		h.actionUpdateProfileName(aw, r)
	case "update_password":
		h.actionUpdatePassword(aw, r)
	case "totp_generate":
		h.actionTOTPGenerate(aw, r)
	case "totp_enable":
		h.actionTOTPEnable(aw, r)
	case "totp_disable":
		h.actionTOTPDisable(aw, r)
	// --- セキュリティ系アクション ---
	case "highscore_dismiss":
		h.actionHighScoreDismiss(aw, r)
	case "highscore_ban":
		h.actionHighScoreBan(aw, r)
	case "bulk_ban":
		h.actionBulkBan(aw, r)
	// --- agent memo ---
	case "agent_memo_save":
		h.actionAgentMemo(aw, r)
	case "vendor_license_issue":
		h.actionVendorLicenseIssue(aw, r)
	case "vendor_license_revoke":
		h.actionVendorLicenseRevoke(aw, r)
	case "vendor_license_offline_generate":
		h.actionVendorLicenseOfflineGenerate(aw, r)
	case "vendor_license_rotation_generate":
		h.actionVendorLicenseRotationGenerate(aw, r)
	default:
		writeActionError(aw, "unknown action: "+api, http.StatusNotFound)
	}
	logActionAudit(r, event, user, role, aw.statusCode, aw.body.String())
}

type actionAuditWriter struct {
	http.ResponseWriter
	statusCode int
	body       bytes.Buffer
}

func (w *actionAuditWriter) WriteHeader(status int) {
	w.statusCode = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *actionAuditWriter) Write(p []byte) (int, error) {
	_, _ = w.body.Write(p)
	return w.ResponseWriter.Write(p)
}

func logActionAudit(r *http.Request, event, user, role string, statusCode int, responseBody string) {
	result := "success"
	if statusCode >= http.StatusBadRequest {
		result = "fail"
	}
	msg := strings.TrimSpace(responseBody)
	if msg != "" {
		var res ActionResponse
		if err := json.Unmarshal([]byte(msg), &res); err == nil && strings.TrimSpace(res.Message) != "" {
			msg = res.Message
		}
	}
	if len(msg) > 500 {
		msg = msg[:500]
	}
	audit.LogRequest(r, event, user, role, result, msg, map[string]string{
		"http_status": strconv.Itoa(statusCode),
	})
}

func normalizeMonitorActionKey(api string) string {
	key := strings.ToLower(strings.TrimSpace(api))
	switch key {
	case "wl_add":
		return "ip_add"
	case "wl_remove":
		return "ip_remove"
	default:
		return key
	}
}

func isMonitorActionAllowed(r *http.Request, sess auth.Session, api string) bool {
	key := normalizeMonitorActionKey(api)
	if key == "" {
		return false
	}
	allowed := auth.ActionAllowed(sess.ActionPermissions, sess.Role, key)
	if !allowed {
		return false
	}
	agentID := strings.TrimSpace(r.URL.Query().Get("agent"))
	if agentID == "" {
		return allowed
	}
	// URL host から解決した tenant が nil でもフェイルオープン
	// しないよう、agent_id から導出した tenant_id を fallback として使う。
	// 上流の dispatchAction で enforceAgentTenantBoundary により agent と session
	// のテナント一致は別途強制されている（vendor_staff のみ bypass）。
	tenantID := ""
	if tenant := routing.GetTenantByRequest(r); tenant != nil {
		tenantID = strings.TrimSpace(tenant.TenantID)
	}
	if tenantID == "" {
		tenantID = tenantIDFromAgentID(agentID)
	}
	if tenantID == "" {
		return allowed
	}
	actionsTenants := authz.ActionsTenants()
	te, ok := actionsTenants.Tenants[tenantID]
	if !ok {
		return allowed
	}
	ae, ok := te.Agents[agentID]
	if !ok {
		return allowed
	}
	if v, ok := authz.ActionPolicyValue(ae.Actions, key); ok {
		return v
	}
	return allowed
}

func isAgentUnsupportedAction(actionKey string) bool {
	switch actionKey {
	case "reboot", "restart_heartdesk",
		"maintenance_on", "maintenance_off", "nc_repair",
		"apt_update", "apt_upgrade", "apt_full_upgrade", "toggle_auto_update",
		"fail2ban_ban", "fail2ban_unban",
		"ip_add", "ip_remove", "ip_rename", "ip_changetype",
		"highscore_ban", "highscore_dismiss", "bulk_ban",
		"backup_run", "ssl_renew":
		return true
	default:
		return false
	}
}
