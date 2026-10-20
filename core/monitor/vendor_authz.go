package monitor

import (
	"net/http"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
)

// Vendor Console の認可を 1 箇所に集約する。
// 認可は ScreenVendor（access_screens 由来。既定で vendor_staff のみ付与）で判定し、
// GET 系 API（map{"error":"forbidden"} を json.Encode すると HTTP 200 になってしまう）を
// 含めて実 HTTP 403 を返せるようにする。

// isVendorAPI は GET ?api=xxx が Vendor Console 専用 API かを返す。
func isVendorAPI(api string) bool {
	return strings.HasPrefix(api, "vendor_")
}

// isVendorAction は POST ?api=xxx が Vendor Console 専用アクションかを返す。
func isVendorAction(api string) bool {
	return strings.HasPrefix(api, "vendor_license_")
}

// requireVendorScreen は現在のセッションが Vendor Console（ScreenVendor）へ
// アクセスできるかを判定する。アクセス不可なら HTTP 403 を書き込み false を返す。
// 認可可否の単一判定経路（vendor-role-check-duplication 解消の中核）。
func requireVendorScreen(w http.ResponseWriter, r *http.Request) bool {
	if vendorRequestAllowed(r) {
		return true
	}
	http.Error(w, "403 Forbidden: Vendor Console へのアクセス権限がありません", http.StatusForbidden)
	return false
}

// vendorRequestAllowed は ResponseWriter を持たないデータ取得関数（GetVendorXxx）からも
// 呼べる認可ヘルパ。ScreenVendor を持つ場合のみ true。セッションが取れない場合は
// ミドルウェアが付与した role が vendor_staff かで後方互換的に判定する。
func vendorRequestAllowed(r *http.Request) bool {
	if sess, ok := auth.DefaultSessionManager().SessionFromRequest(r); ok {
		return auth.AllowsVendor(sess.AccessScreens)
	}
	return auth.Role(middleware.GetRole(r.Context())) == auth.RoleVendorStaff
}
