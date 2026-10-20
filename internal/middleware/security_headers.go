package middleware

import (
	"net/http"

	"github.com/ishizakahiroshi/heartdesk/internal/httpsec"
)

// SecurityHeadersReportOnlyCSP は HTML 応答へ多層防御として付与する
// Content-Security-Policy-Report-Only の雛形。
//
// C2（no-csp-security-headers）対応。inline onclick / innerHTML が多数あるため
// 厳格な script-src はまだ enforce できない。まずは Report-Only で違反を棚卸しし、
// 棚卸し完了後に Content-Security-Policy へ昇格させる段取りとする。
//
// frame-ancestors 'self' だけは enforce 側（X-Frame-Options）でも担保しているため
// Report-Only にも含め、将来 enforce へ移す際の整合を取る。
const SecurityHeadersReportOnlyCSP = httpsec.SecurityHeadersReportOnlyCSP

// SetHTMLSecurityHeaders は HTML 応答に共通のセキュリティヘッダを付与する。
//
// C2（no-csp-security-headers）対応の共通ヘルパ。HTML を返す各ハンドラが
// Content-Type を設定する箇所で呼び出す（JSON / CSV 応答には適用しないこと。
// CSV の nosniff は export.go が独自に付与しており本ヘルパとは別系統）。
//
// enforce するもの:
//
//	X-Frame-Options: SAMEORIGIN        — クリックジャッキング対策（frame-ancestors 'self' 相当）
//	X-Content-Type-Options: nosniff    — MIME スニッフィング抑止
//	Referrer-Policy: strict-origin-when-cross-origin
//	Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()
//	Cross-Origin-Opener-Policy: same-origin
//
// CSP は Report-Only の雛形のみ付与する（厳格化は違反棚卸し後）。
//
// 後続章（親 C3 のアーキ再編で internal/httpx 化予定）がそのまま流用できるよう
// 自己完結・副作用なしにしてある。
func SetHTMLSecurityHeaders(w http.ResponseWriter) {
	httpsec.SetHTMLSecurityHeaders(w)
}
