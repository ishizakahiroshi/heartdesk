package monitor

import (
	"net/http"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/auditdb"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
)

type vendorDashboardRecentEntry struct {
	Ts       string `json:"ts"`
	Action   string `json:"action"`
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id"`
	Actor    string `json:"actor"`
	Reason   string `json:"reason,omitempty"`
}

type vendorDashboardResp struct {
	TenantCount        int                          `json:"tenant_count"`
	AgentCount         int                          `json:"agent_count"`
	ActiveLicenseCount int                          `json:"active_license_count"`
	RevokedCount       int                          `json:"revoked_count"`
	Audit24hCount      int64                        `json:"audit_24h_count"`
	RecentLedger       []vendorDashboardRecentEntry `json:"recent_ledger"`
}

func GetVendorDashboard(r *http.Request, appCfg *config.AppConfig) interface{} {
	if auth.Role(middleware.GetRole(r.Context())) != auth.RoleVendorStaff {
		return map[string]interface{}{"error": "forbidden"}
	}

	lst, ok := currentLedgerStore()
	if !ok {
		return map[string]interface{}{"error": "ledger unavailable (DB 未初期化)"}
	}

	entries, err := lst.ListLedgerAcrossTenants(r.Context())
	if err != nil {
		return map[string]interface{}{"error": "ledger: " + err.Error()}
	}

	revokedCount := 0
	activeCount := 0
	for _, e := range entries {
		if e.Action == "revoke" {
			revokedCount++
		} else if e.Action == "issue" {
			activeCount++
		}
	}
	// active = issued - revoked（簡易）
	if activeCount > revokedCount {
		activeCount -= revokedCount
	}

	recent := entries
	if len(recent) > 10 {
		recent = recent[:10]
	}
	recentOut := make([]vendorDashboardRecentEntry, 0, len(recent))
	for _, e := range recent {
		recentOut = append(recentOut, vendorDashboardRecentEntry{
			Ts:       e.Timestamp.In(heartdesk.JST()).Format(time.RFC3339),
			Action:   e.Action,
			TenantID: e.TenantID,
			AgentID:  e.AgentID,
			Actor:    ledgerStr(e.Actor),
			Reason:   ledgerStr(e.Reason),
		})
	}

	var audit24h int64
	if auditdb.Enabled() {
		from24h := time.Now().Add(-24 * time.Hour).In(heartdesk.JST()).Format(time.RFC3339)
		res, _ := auditdb.Query(auditdb.QueryParams{From: from24h, Limit: 1})
		audit24h = res.Total
	}

	// テナント数・Agent数は config + agentLastSeen から集計（台帳ではなく実態ベース）
	tenantsResp := buildVendorTenantsResp(appCfg)
	tenantCount := len(tenantsResp.Tenants)
	agentCount := 0
	for _, t := range tenantsResp.Tenants {
		agentCount += len(t.Agents)
	}

	return vendorDashboardResp{
		TenantCount:        tenantCount,
		AgentCount:         agentCount,
		ActiveLicenseCount: activeCount,
		RevokedCount:       revokedCount,
		Audit24hCount:      audit24h,
		RecentLedger:       recentOut,
	}
}
