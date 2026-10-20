package monitor

import (
	"net/http"
	"strings"
	"time"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
)

type vendorLicenseAuditEntry struct {
	Ts        string `json:"ts"`
	Action    string `json:"action"`
	TenantID  string `json:"tenant_id"`
	AgentID   string `json:"agent_id"`
	KID       string `json:"kid"`
	KeyPrefix string `json:"key_prefix"`
	Actor     string `json:"actor"`
	Reason    string `json:"reason,omitempty"`
}

type vendorLicenseAuditResp struct {
	Total   int                       `json:"total"`
	Limit   int                       `json:"limit"`
	Offset  int                       `json:"offset"`
	Entries []vendorLicenseAuditEntry `json:"entries"`
}

func GetVendorLicenseAudit(r *http.Request, _ *config.AppConfig) interface{} {
	if auth.Role(middleware.GetRole(r.Context())) != auth.RoleVendorStaff {
		return map[string]interface{}{"error": "forbidden"}
	}

	lst, ok := currentLedgerStore()
	if !ok {
		return map[string]interface{}{"error": "ledger unavailable (DB 未初期化)"}
	}

	all, err := lst.ListLedgerAcrossTenants(r.Context())
	if err != nil {
		return map[string]interface{}{"error": "ledger: " + err.Error()}
	}

	q := r.URL.Query()
	filterUser := strings.TrimSpace(q.Get("user"))
	filterAction := strings.TrimSpace(q.Get("action"))
	filterFrom := strings.TrimSpace(q.Get("from"))
	filterTo := strings.TrimSpace(q.Get("to"))
	limit := parseIntParam(q.Get("limit"), 50)
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset := parseIntParam(q.Get("offset"), 0)
	if offset < 0 {
		offset = 0
	}

	var fromTime, toTime time.Time
	if filterFrom != "" {
		fromTime, _ = time.Parse(time.RFC3339, filterFrom)
	}
	if filterTo != "" {
		toTime, _ = time.Parse(time.RFC3339, filterTo)
	}

	var filtered []vendorLicenseAuditEntry
	for _, e := range all {
		if filterAction != "" && e.Action != filterAction {
			continue
		}
		if filterUser != "" && !strings.Contains(strings.ToLower(ledgerStr(e.Actor)), strings.ToLower(filterUser)) {
			continue
		}
		if !fromTime.IsZero() && e.Timestamp.Before(fromTime) {
			continue
		}
		if !toTime.IsZero() && e.Timestamp.After(toTime) {
			continue
		}
		filtered = append(filtered, vendorLicenseAuditEntry{
			Ts:        e.Timestamp.In(sab.JST()).Format(time.RFC3339),
			Action:    e.Action,
			TenantID:  e.TenantID,
			AgentID:   e.AgentID,
			KID:       ledgerStr(e.KID),
			KeyPrefix: ledgerStr(e.KeyPrefix),
			Actor:     ledgerStr(e.Actor),
			Reason:    ledgerStr(e.Reason),
		})
	}

	total := len(filtered)
	end := offset + limit
	if end > total {
		end = total
	}
	page := filtered
	if offset < total {
		page = filtered[offset:end]
	} else {
		page = []vendorLicenseAuditEntry{}
	}

	return vendorLicenseAuditResp{
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		Entries: page,
	}
}
