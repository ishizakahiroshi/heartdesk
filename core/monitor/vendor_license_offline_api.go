package monitor

import (
	"net/http"
	"sort"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
)

type vendorLicenseOfflineConfigResp struct {
	Agents     []string `json:"agents"`
	ExpiryDays int      `json:"expiry_days"`
	GraceDays  int      `json:"grace_days"`
	MaxAgents  int      `json:"max_agents"`
}

func GetVendorLicenseOfflineConfig(r *http.Request, appCfg *config.AppConfig) interface{} {
	if auth.Role(middleware.GetRole(r.Context())) != auth.RoleVendorStaff {
		return map[string]string{"error": "forbidden"}
	}
	agents := make([]string, 0)
	if appCfg != nil {
		for id := range appCfg.Agents {
			agents = append(agents, id)
		}
		sort.Strings(agents)
	}
	return vendorLicenseOfflineConfigResp{
		Agents:     agents,
		ExpiryDays: 365,
		GraceDays:  7,
		MaxAgents:  1,
	}
}
