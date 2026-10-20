package httpsec

import "net/http"

// SecurityHeadersReportOnlyCSP is the shared Report-Only CSP for HTML pages.
//
// Inline handlers and innerHTML rendering still exist in several legacy cards,
// so script-src stays Report-Only until that inventory is cleaned up.
const SecurityHeadersReportOnlyCSP = "default-src 'self'; " +
	"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"frame-ancestors 'self'; " +
	"base-uri 'self'; " +
	"form-action 'self'"

// SetHTMLSecurityHeaders applies the common security headers for HTML pages.
func SetHTMLSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Content-Security-Policy-Report-Only", SecurityHeadersReportOnlyCSP)
}
