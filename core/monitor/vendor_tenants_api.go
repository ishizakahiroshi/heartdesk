package monitor

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
)

type vendorTenantsAgentCell struct {
	AgentID    string `json:"agent_id"`
	Label      string `json:"label"`
	AgentType  string `json:"agent_type"`
	ReceivedAt string `json:"received_at"`
	MinutesAgo int    `json:"minutes_ago"`
	HasData    bool   `json:"has_data"`
	Status     string `json:"status"` // "ok" | "warn" | "alert" | "unknown"
}

type vendorTenantRow struct {
	ID     string                   `json:"id"`
	Name   string                   `json:"name,omitempty"`
	Agents []vendorTenantsAgentCell `json:"agents"`
}

type vendorTenantsResp struct {
	Tenants []vendorTenantRow `json:"tenants"`
}

func GetVendorTenants(_ *http.Request, appCfg *config.AppConfig) interface{} {
	return buildVendorTenantsResp(appCfg)
}

func GetVendorTenantsForRequest(r *http.Request, appCfg *config.AppConfig) interface{} {
	if auth.Role(middleware.GetRole(r.Context())) != auth.RoleVendorStaff {
		return map[string]interface{}{"error": "forbidden"}
	}
	return buildVendorTenantsResp(appCfg)
}

func buildVendorTenantsResp(appCfg *config.AppConfig) vendorTenantsResp {
	// テナント → Agent のマッピングを構築
	tenantAgents := map[string][]vendorTenantsAgentCell{}

	if appCfg != nil {
		for agentID, agentCfg := range appCfg.Agents {
			tenantID := tenantIDFromAgentIDVendor(agentID)
			if tenantID == "" {
				continue
			}
			cell := agentCellFromConfig(agentID, agentCfg)
			tenantAgents[tenantID] = append(tenantAgents[tenantID], cell)
		}
	}

	// agentLastSeen にいるが config にない Agent も追加
	for _, seen := range agentLastSeenSnapshot() {
		tenantID := tenantIDFromAgentIDVendor(seen.AgentID)
		if tenantID == "" {
			continue
		}
		found := false
		for _, cell := range tenantAgents[tenantID] {
			if cell.AgentID == seen.AgentID {
				found = true
				break
			}
		}
		if !found {
			tenantAgents[tenantID] = append(tenantAgents[tenantID], vendorTenantsAgentCell{
				AgentID:   seen.AgentID,
				Label:     seen.AgentLabel,
				AgentType: seen.AgentType,
			})
		}
	}

	// 各セルに最終報告状況を反映
	for tenantID, cells := range tenantAgents {
		for i, cell := range cells {
			if seen := GetAgentLastSeenByID(cell.AgentID); seen != nil {
				cells[i] = applyLastSeen(cell, seen)
			}
		}
		sort.Slice(cells, func(i, j int) bool {
			return cells[i].AgentID < cells[j].AgentID
		})
		tenantAgents[tenantID] = cells
	}

	// テナント一覧をソート
	tenantIDs := make([]string, 0, len(tenantAgents))
	for tid := range tenantAgents {
		tenantIDs = append(tenantIDs, tid)
	}
	sort.Strings(tenantIDs)

	rows := make([]vendorTenantRow, 0, len(tenantIDs))
	for _, tid := range tenantIDs {
		name := ""
		if tc := routing.GetTenantByID(tid); tc != nil {
			name = tc.Name
		}
		rows = append(rows, vendorTenantRow{ID: tid, Name: name, Agents: tenantAgents[tid]})
	}
	return vendorTenantsResp{Tenants: rows}
}

func agentCellFromConfig(agentID string, cfg config.AgentConfig) vendorTenantsAgentCell {
	label := cfg.AgentLabel
	if label == "" {
		label = agentID
	}
	return vendorTenantsAgentCell{
		AgentID:   agentID,
		Label:     label,
		AgentType: cfg.AgentType,
		Status:    "unknown",
	}
}

func applyLastSeen(cell vendorTenantsAgentCell, seen *AgentLastSeen) vendorTenantsAgentCell {
	if seen.AgentLabel != "" && cell.Label == "" {
		cell.Label = seen.AgentLabel
	}
	if seen.AgentType != "" && cell.AgentType == "" {
		cell.AgentType = seen.AgentType
	}
	cell.ReceivedAt = seen.ReceivedAt
	cell.MinutesAgo = seen.MinutesAgo
	cell.HasData = seen.ReceivedAt != ""

	t, err := time.Parse(time.RFC3339, seen.ReceivedAt)
	if err != nil || t.IsZero() {
		cell.Status = "unknown"
		return cell
	}
	switch {
	case seen.MinutesAgo < 5:
		cell.Status = "ok"
	case seen.MinutesAgo < 30:
		cell.Status = "warn"
	default:
		cell.Status = "alert"
	}
	return cell
}

// agentLastSeenSnapshot は agentLastSeen マップのスナップショットを返す。
func agentLastSeenSnapshot() []*AgentLastSeen {
	agentLastSeenMu.RLock()
	defer agentLastSeenMu.RUnlock()
	out := make([]*AgentLastSeen, 0, len(agentLastSeen))
	for _, v := range agentLastSeen {
		cp := *v
		out = append(out, &cp)
	}
	return out
}

func tenantIDFromAgentIDVendor(agentID string) string {
	idx := strings.Index(agentID, "-")
	if idx <= 0 {
		return ""
	}
	return agentID[:idx]
}
