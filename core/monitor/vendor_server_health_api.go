package monitor

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
)

// vendorServerHealthRow は Vendor Console 「サーバー健全性」カードの 1 行。
type vendorServerHealthRow struct {
	AgentID        string   `json:"agent_id"`
	TenantID       string   `json:"tenant_id"`
	Label          string   `json:"label"`
	SSLDays        int      `json:"ssl_days"`
	SSLExpiry      string   `json:"ssl_expiry"`
	SSLUnavailable bool     `json:"ssl_unavailable"`
	KernelOutdated bool     `json:"kernel_outdated"`
	KernelCurrent  string   `json:"kernel_current"`
	KernelLatest   string   `json:"kernel_latest"`
	HeldCount      int      `json:"held_count"`
	HeldPackages   []string `json:"held_packages,omitempty"`
	UpdateCount    int      `json:"update_count"`
	HasData        bool     `json:"has_data"`
	HasUpdatesData bool     `json:"has_updates_data"`
}

type vendorServerHealthResp struct {
	Rows []vendorServerHealthRow `json:"rows"`
}

// GetVendorServerHealth は Vendor Console 向けに全 VPS エージェントの
// SSL 残日数・カーネル更新状況・apt hold 状態を集約して返す。
func GetVendorServerHealth(r *http.Request, appCfg *config.AppConfig) interface{} {
	if auth.Role(middleware.GetRole(r.Context())) != auth.RoleVendorStaff {
		return map[string]interface{}{"error": "forbidden"}
	}

	// 対象エージェント一覧（config に登録済みの VPS のみ）
	type agentEntry struct {
		agentID string
		label   string
	}
	var entries []agentEntry

	if appCfg != nil {
		for agentID, cfg := range appCfg.Agents {
			if config.NormalizeAgentType(cfg.AgentType) != "vps" {
				continue
			}
			label := cfg.AgentLabel
			if label == "" {
				label = agentID
			}
			entries = append(entries, agentEntry{agentID: agentID, label: label})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		ti := tenantIDFromAgentIDVendor(entries[i].agentID)
		tj := tenantIDFromAgentIDVendor(entries[j].agentID)
		if ti != tj {
			return ti < tj
		}
		return entries[i].agentID < entries[j].agentID
	})

	rows := make([]vendorServerHealthRow, 0, len(entries))
	for _, e := range entries {
		row := vendorServerHealthRow{
			AgentID:  e.agentID,
			TenantID: tenantIDFromAgentIDVendor(e.agentID),
			Label:    e.label,
		}

		// HasData: agentLastSeen に存在するか
		if seen := GetAgentLastSeenByID(e.agentID); seen != nil {
			row.HasData = true
		}

		// SSL collector データ
		if raw, ok := GetAgentLatestCollector(e.agentID, "ssl"); ok && len(raw) > 0 && string(raw) != "null" {
			var ssl struct {
				SSLExpiry string `json:"ssl_expiry"`
				SSLDays   int    `json:"ssl_days"`
			}
			if err := json.Unmarshal(raw, &ssl); err == nil {
				row.SSLDays = ssl.SSLDays
				row.SSLExpiry = ssl.SSLExpiry
			}
		} else {
			row.SSLUnavailable = true
		}

		// updates collector データ（カーネル・held）
		if raw, ok := GetAgentLatestCollector(e.agentID, "updates"); ok && len(raw) > 0 && string(raw) != "null" {
			var u UpdatesData
			if err := json.Unmarshal(raw, &u); err == nil {
				row.HasUpdatesData = true
				row.KernelOutdated = u.KernelOutdated
				row.KernelCurrent = u.KernelCurrent
				row.KernelLatest = u.KernelLatest
				row.HeldCount = u.HeldCount
				row.HeldPackages = u.HeldPackages
				row.UpdateCount = u.UpdateCount
			}
		}

		rows = append(rows, row)
	}

	return vendorServerHealthResp{Rows: rows}
}
