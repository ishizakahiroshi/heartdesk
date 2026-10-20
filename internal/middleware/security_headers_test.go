package middleware

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSetHTMLSecurityHeaders は C2（no-csp-security-headers）の enforce ヘッダと
// Report-Only CSP 雛形が付与されることを確認する。
func TestSetHTMLSecurityHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	SetHTMLSecurityHeaders(w)

	tests := []struct {
		header string
		want   string
	}{
		{"X-Frame-Options", "SAMEORIGIN"},
		{"X-Content-Type-Options", "nosniff"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
		{"Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()"},
		{"Cross-Origin-Opener-Policy", "same-origin"},
	}
	for _, tt := range tests {
		if got := w.Header().Get(tt.header); got != tt.want {
			t.Errorf("%s = %q, want %q", tt.header, got, tt.want)
		}
	}

	csp := w.Header().Get("Content-Security-Policy-Report-Only")
	if csp == "" {
		t.Fatal("Content-Security-Policy-Report-Only must be set")
	}
	if !strings.Contains(csp, "frame-ancestors 'self'") {
		t.Errorf("Report-Only CSP should contain frame-ancestors 'self', got %q", csp)
	}
	// enforce 側で厳格 script-src を強制していないこと（inline 多数のため Report-Only どまり）。
	if w.Header().Get("Content-Security-Policy") != "" {
		t.Error("Content-Security-Policy (enforce) must not be set yet")
	}
}
