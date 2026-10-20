package monitor

import (
	"encoding/json"
	"net/http"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
)

// requireVendorStaff は vendor_staff 以外を 403 で弾く共通ガード。
// 弾いた場合は true を返す（呼び出し元は即 return すること）。
func requireVendorStaff(w http.ResponseWriter, r *http.Request) bool {
	role := middleware.GetRole(r.Context())
	if auth.Role(role) != auth.RoleVendorStaff {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ActionResponse{OK: false, Message: "この操作には vendor_staff 権限が必要です"})
		return true
	}
	return false
}
