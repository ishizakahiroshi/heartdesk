package monitor

import (
	"net/http"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc/store"
)

type vendorLicensesResp struct {
	Entries []vendorLicenseEntry `json:"entries"`
	Total   int                  `json:"total"`
}

type vendorLicenseEntry struct {
	Ts        string `json:"ts"`
	Action    string `json:"action"`
	TenantID  string `json:"tenant_id"`
	AgentID   string `json:"agent_id"`
	KID       string `json:"kid"`
	KeyPrefix string `json:"key_prefix"`
	Actor     string `json:"actor"`
	Reason    string `json:"reason"`
}

func GetVendorLicenses(r *http.Request, _ *config.AppConfig) interface{} {
	if auth.Role(middleware.GetRole(r.Context())) != auth.RoleVendorStaff {
		return map[string]string{"error": "forbidden"}
	}
	lst, ok := currentLedgerStore()
	if !ok {
		return map[string]string{"error": "ledger unavailable (DB 未初期化)"}
	}

	tenantFilter := r.URL.Query().Get("tenant")
	actionFilter := r.URL.Query().Get("action")

	var src []store.LedgerEntry
	var err error
	if tenantFilter != "" {
		src, err = lst.ListLedger(r.Context(), tenantFilter)
	} else {
		src, err = lst.ListLedgerAcrossTenants(r.Context())
	}
	if err != nil {
		return map[string]string{"error": err.Error()}
	}

	result := make([]vendorLicenseEntry, 0, len(src))
	for _, e := range src {
		if actionFilter != "" && e.Action != actionFilter {
			continue
		}
		result = append(result, vendorLicenseEntry{
			Ts:        e.Timestamp.Format("2006-01-02 15:04:05"),
			Action:    e.Action,
			TenantID:  e.TenantID,
			AgentID:   e.AgentID,
			KID:       ledgerStr(e.KID),
			KeyPrefix: ledgerStr(e.KeyPrefix),
			Actor:     ledgerStr(e.Actor),
			Reason:    ledgerStr(e.Reason),
		})
	}

	return vendorLicensesResp{Entries: result, Total: len(result)}
}
