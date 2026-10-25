package monitor

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
	"github.com/ishizakahiroshi/heartdesk/internal/nclog"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
)

type vendorNcOverviewRow struct {
	AgentID     string `json:"agent_id"`
	AgentLabel  string `json:"agent_label"`
	TenantID    string `json:"tenant_id"`
	TenantName  string `json:"tenant_name,omitempty"`
	Errors24h   int    `json:"errors_24h"`
	Warnings24h int    `json:"warnings_24h"`
	DiskPct     string `json:"disk_pct"`
}

type vendorNcOverviewResp struct {
	Rows []vendorNcOverviewRow `json:"rows"`
}

func GetVendorNcOverview(r *http.Request, appCfg *config.AppConfig) interface{} {
	if auth.Role(middleware.GetRole(r.Context())) != auth.RoleVendorStaff {
		return map[string]string{"error": "forbidden"}
	}
	if appCfg == nil {
		return vendorNcOverviewResp{Rows: []vendorNcOverviewRow{}}
	}

	diskByAgent := map[string]string{}
	for _, item := range getAgentOverviewForConfig(appCfg, string(auth.RoleVendorStaff), "") {
		diskByAgent[item.AgentID] = item.DiskPct
	}

	var rows []vendorNcOverviewRow
	for agentID, agentCfg := range appCfg.Agents {
		caps := appCfg.AgentCapabilities(agentID)
		hasNC := false
		for _, c := range caps {
			if c == "module.nextcloud" {
				hasNC = true
				break
			}
		}
		if !hasNC {
			continue
		}

		tenantID := tenantIDFromAgentIDVendor(agentID)
		tenantName := ""
		if tc := routing.GetTenantByID(tenantID); tc != nil {
			tenantName = tc.Name
		}
		errors24h, warnings24h := countNcLogLevels24h(agentID)
		label := agentCfg.AgentLabel
		if label == "" {
			label = agentID
		}

		rows = append(rows, vendorNcOverviewRow{
			AgentID:     agentID,
			AgentLabel:  label,
			TenantID:    tenantID,
			TenantName:  tenantName,
			Errors24h:   errors24h,
			Warnings24h: warnings24h,
			DiskPct:     diskByAgent[agentID],
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].TenantID != rows[j].TenantID {
			return rows[i].TenantID < rows[j].TenantID
		}
		return rows[i].AgentID < rows[j].AgentID
	})

	if rows == nil {
		rows = []vendorNcOverviewRow{}
	}
	return vendorNcOverviewResp{Rows: rows}
}

func countNcLogLevels24h(agentID string) (errors, warnings int) {
	cutoff := time.Now().Add(-24 * time.Hour)
	_ = ScanJSONL[NCEvent](ncJSONLPath(agentID), func(ev NCEvent) bool {
		if ev.TS == "" {
			return true
		}
		ts, ok := nclog.ParseTime(ev.TS)
		if !ok || ts.Before(cutoff) {
			return true
		}
		switch strings.ToLower(ev.Level) {
		case "error", "fatal":
			errors++
		case "warning":
			warnings++
		}
		return true
	})
	return
}
