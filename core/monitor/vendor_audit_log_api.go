package monitor

import (
	"net/http"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/internal/auditdb"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
)

type vendorAuditLogResp struct {
	auditdb.QueryResult
	Tenants []string `json:"tenants"`
}

// GetVendorAuditLog は ?api=vendor_audit_log に応答する。
// vendor_staff ロール以外は {"error":"forbidden"} を返す。
func GetVendorAuditLog(r *http.Request, appCfg *config.AppConfig) interface{} {
	if auth.Role(middleware.GetRole(r.Context())) != auth.RoleVendorStaff {
		return map[string]interface{}{"error": "forbidden"}
	}
	if !AuditAggregatedEnabled() {
		return map[string]interface{}{"error": "audit_aggregated not enabled on this server"}
	}

	q := r.URL.Query()
	limit := parseIntParam(q.Get("limit"), 100)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset := parseIntParam(q.Get("offset"), 0)
	if offset < 0 {
		offset = 0
	}

	params := auditdb.QueryParams{
		Tenant: strings.TrimSpace(q.Get("tenant")),
		Agent:  strings.TrimSpace(q.Get("agent_id")),
		User:   strings.TrimSpace(q.Get("user")),
		Event:  strings.TrimSpace(q.Get("event")),
		From:   strings.TrimSpace(q.Get("from")),
		To:     strings.TrimSpace(q.Get("to")),
		Limit:  limit,
		Offset: offset,
	}

	result, err := auditdb.Query(params)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	tenants, _ := auditdb.ListDistinctTenants()
	if tenants == nil {
		tenants = []string{}
	}

	return vendorAuditLogResp{QueryResult: result, Tenants: tenants}
}
