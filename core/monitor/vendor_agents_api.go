package monitor

import (
	"net/http"
	"sort"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
)

type vendorAgentRow struct {
	AgentID    string `json:"agent_id"`
	TenantID   string `json:"tenant_id"`
	Label      string `json:"label"`
	AgentType  string `json:"agent_type"`
	ReceivedAt string `json:"received_at"`
	MinutesAgo int    `json:"minutes_ago"`
	HasData    bool   `json:"has_data"`
	Status     string `json:"status"` // "ok" | "warn" | "alert" | "unknown"
}

type vendorAgentsResp struct {
	Agents []vendorAgentRow `json:"agents"`
}

func GetVendorAgents(r *http.Request, appCfg *config.AppConfig) interface{} {
	if auth.Role(middleware.GetRole(r.Context())) != auth.RoleVendorStaff {
		return map[string]interface{}{"error": "forbidden"}
	}

	agentMap := map[string]vendorAgentRow{}

	if appCfg != nil {
		for agentID, cfg := range appCfg.Agents {
			label := cfg.AgentLabel
			if label == "" {
				label = agentID
			}
			agentMap[agentID] = vendorAgentRow{
				AgentID:   agentID,
				TenantID:  tenantIDFromAgentIDVendor(agentID),
				Label:     label,
				AgentType: cfg.AgentType,
				Status:    "unknown",
			}
		}
	}

	// agentLastSeen にいるが config にないエージェントも追加
	for _, seen := range agentLastSeenSnapshot() {
		if _, exists := agentMap[seen.AgentID]; !exists {
			agentMap[seen.AgentID] = vendorAgentRow{
				AgentID:   seen.AgentID,
				TenantID:  tenantIDFromAgentIDVendor(seen.AgentID),
				Label:     seen.AgentLabel,
				AgentType: seen.AgentType,
			}
		}
	}

	// 最終報告状況を反映
	agents := make([]vendorAgentRow, 0, len(agentMap))
	for _, row := range agentMap {
		if seen := GetAgentLastSeenByID(row.AgentID); seen != nil {
			cell := vendorTenantsAgentCell{
				AgentID:   row.AgentID,
				Label:     row.Label,
				AgentType: row.AgentType,
			}
			cell = applyLastSeen(cell, seen)
			row.ReceivedAt = cell.ReceivedAt
			row.MinutesAgo = cell.MinutesAgo
			row.HasData = cell.HasData
			row.Status = cell.Status
			if cell.Label != "" {
				row.Label = cell.Label
			}
			if cell.AgentType != "" {
				row.AgentType = cell.AgentType
			}
		}
		agents = append(agents, row)
	}

	sort.Slice(agents, func(i, j int) bool {
		if agents[i].TenantID != agents[j].TenantID {
			return agents[i].TenantID < agents[j].TenantID
		}
		return agents[i].AgentID < agents[j].AgentID
	})

	return vendorAgentsResp{Agents: agents}
}
