package auth

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/internal/auditdb"
)

// TenantAuditLog は tenant_admin 向けの監査ログ閲覧エンドポイント。
//
// C8（audit-vendor-staff-only-tenant-admin-no-audit）: auditdb.Query を呼ぶが、
// Tenant はセッションの TenantID をサーバー側で強制注入し、クライアント指定の
// tenant パラメータは一切信用しない（リクエスト改ざんで他テナントを指定しても無視）。
// これにより tenant_admin は自テナントの監査ログのみ閲覧でき、テナント境界を強制する。
// 全テナント横断は従来どおり vendor_staff 限定の AdminAuditLog を使う。
func (h *HTTPHandler) TenantAuditLog(w http.ResponseWriter, r *http.Request) {
	sess, ok := DefaultSessionManager().SessionFromRequest(r)
	if !ok {
		http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
		return
	}
	role := Role(NormalizeRole(sess.Role))
	if role != RoleTenantAdmin && role != RoleVendorStaff {
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}
	tenantID := strings.TrimSpace(sess.TenantID)
	if tenantID == "" {
		// セッションにテナントが無い場合は他テナント混入を防ぐため拒否（fail-close）。
		http.Error(w, "403 Forbidden: no tenant context", http.StatusForbidden)
		return
	}

	limit := 200
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}

	// Tenant はサーバー側（セッション）から強制注入。クライアントの tenant 指定は使わない。
	res, err := auditdb.Query(auditdb.QueryParams{
		Tenant: tenantID,
		Limit:  limit,
	})
	if err != nil {
		http.Error(w, "503 Service Unavailable: audit store unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"tenant": tenantID,
		"total":  res.Total,
		"logs":   res.Logs,
	})
}
