package monitor

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	vendorconsole "github.com/ishizakahiroshi/heartdesk/core/vendor_console"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc/store"
)

func (h *Handler) actionVendorLicenseIssue(w http.ResponseWriter, r *http.Request) {
	if auth.Role(middleware.GetRole(r.Context())) != auth.RoleVendorStaff {
		writeActionError(w, "forbidden", http.StatusForbidden)
		return
	}
	agentID := strings.TrimSpace(r.FormValue("agent_id"))
	if agentID == "" {
		writeActionError(w, "agent_id が指定されていません", http.StatusBadRequest)
		return
	}
	idx := strings.Index(agentID, "-")
	if idx < 1 {
		writeActionError(w, "不正な agent_id 形式（<tenant_id>-<name> が必要）", http.StatusBadRequest)
		return
	}
	tenantID := agentID[:idx]

	lst, ok := currentLedgerStore()
	if !ok {
		writeActionError(w, "台帳が利用できません（DB 未初期化）", http.StatusServiceUnavailable)
		return
	}

	licenseKey := vendorconsole.GenerateLicenseKey(h.appCfg, agentID, tenantID)

	actor := "unknown"
	if u := middleware.GetUser(r.Context()); u != "" {
		actor = u
	}
	entry := store.LedgerEntry{
		Action:   "issue",
		TenantID: tenantID,
		AgentID:  agentID,
		Actor:    &actor,
	}
	if licenseKey != "" {
		entry.KeyPrefix = ledgerPtr(tenantID + "." + agentID + ".")
	}
	if err := lst.AppendLedger(r.Context(), tenantID, entry); err != nil {
		log.Printf("ERROR: vendor_license_issue: ledger append: %v", err)
		writeActionError(w, "台帳書き込みエラー: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":          true,
		"message":     agentID + " のライセンスキーを発行しました（このキーは一度だけ表示されます）",
		"license_key": licenseKey,
	})
}

func (h *Handler) actionVendorLicenseRevoke(w http.ResponseWriter, r *http.Request) {
	if auth.Role(middleware.GetRole(r.Context())) != auth.RoleVendorStaff {
		writeActionError(w, "forbidden", http.StatusForbidden)
		return
	}
	agentID := strings.TrimSpace(r.FormValue("agent_id"))
	reason := strings.TrimSpace(r.FormValue("reason"))
	if agentID == "" {
		writeActionError(w, "agent_id が指定されていません", http.StatusBadRequest)
		return
	}
	tenantID := ""
	if idx := strings.Index(agentID, "-"); idx > 0 {
		tenantID = agentID[:idx]
	}

	lst, ok := currentLedgerStore()
	if !ok {
		writeActionError(w, "台帳が利用できません（DB 未初期化）", http.StatusServiceUnavailable)
		return
	}

	actor := "unknown"
	if u := middleware.GetUser(r.Context()); u != "" {
		actor = u
	}
	if err := lst.AppendLedger(r.Context(), tenantID, store.LedgerEntry{
		Action:   "revoke",
		TenantID: tenantID,
		AgentID:  agentID,
		Actor:    &actor,
		Reason:   ledgerPtr(reason),
	}); err != nil {
		log.Printf("ERROR: vendor_license_revoke: ledger append: %v", err)
		writeActionError(w, "台帳書き込みエラー: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeActionOK(w, agentID+" を失効させました")
}

func (h *Handler) actionVendorLicenseOfflineGenerate(w http.ResponseWriter, r *http.Request) {
	if auth.Role(middleware.GetRole(r.Context())) != auth.RoleVendorStaff {
		writeActionError(w, "forbidden", http.StatusForbidden)
		return
	}
	agentID := strings.TrimSpace(r.FormValue("agent_id"))
	if agentID == "" {
		writeActionError(w, "agent_id が指定されていません", http.StatusBadRequest)
		return
	}
	expiryDays, _ := strconv.Atoi(r.FormValue("expiry_days"))
	if expiryDays <= 0 {
		expiryDays = 365
	}
	graceDays, _ := strconv.Atoi(r.FormValue("grace_days"))
	if graceDays <= 0 {
		graceDays = 7
	}
	maxAgents, _ := strconv.Atoi(r.FormValue("max_agents"))
	if maxAgents <= 0 {
		maxAgents = 1
	}

	fileData, err := vendorconsole.IssueOfflineLicenseJWT(h.appCfg, agentID, expiryDays, graceDays, maxAgents)
	if err != nil {
		log.Printf("ERROR: vendor_license_offline_generate: error: %v", err)
		writeActionError(w, "ライセンス生成エラー: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if fileData == nil {
		writeActionError(w, "署名鍵が設定されていません（secrets.toml の active_kid を確認してください）", http.StatusServiceUnavailable)
		return
	}

	if lst, ok := currentLedgerStore(); ok {
		tenantID := agentID
		if idx := strings.Index(agentID, "-"); idx > 0 {
			tenantID = agentID[:idx]
		}
		actor := "unknown"
		if u := middleware.GetUser(r.Context()); u != "" {
			actor = u
		}
		_ = lst.AppendLedger(r.Context(), tenantID, store.LedgerEntry{
			Action:   "offline_issue",
			TenantID: tenantID,
			AgentID:  agentID,
			Actor:    &actor,
		})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":       true,
		"message":  agentID + " のオフラインライセンスを発行しました",
		"data":     base64.StdEncoding.EncodeToString(fileData),
		"filename": "license_" + agentID + ".hdlic",
	})
}

func (h *Handler) actionVendorLicenseRotationGenerate(w http.ResponseWriter, r *http.Request) {
	if auth.Role(middleware.GetRole(r.Context())) != auth.RoleVendorStaff {
		writeActionError(w, "forbidden", http.StatusForbidden)
		return
	}
	actor := "unknown"
	if u := middleware.GetUser(r.Context()); u != "" {
		actor = u
	}
	kid, pubB64, privB64, err := vendorconsole.GenerateSigningKeyPair()
	if err != nil {
		writeActionError(w, "鍵生成エラー: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("INFO: vendor_license_rotation_generate: kid=%s actor=%s", kid, actor)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":       true,
		"message":  "新しい署名鍵を生成しました（kid=" + kid + "）",
		"kid":      kid,
		"pub_b64":  pubB64,
		"priv_b64": privB64,
	})
}
