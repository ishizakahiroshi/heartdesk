package auth

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
)

func testHTTPHandler(t *testing.T) *HTTPHandler {
	t.Helper()
	t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
	tmpl := template.Must(template.New("").Parse(
		`{{define "login"}}ok{{end}}` +
			`{{define "settings_password"}}ok{{end}}` +
			`{{define "settings_2fa"}}ok{{end}}`,
	))
	routes := routing.Config{
		MonitorBase:          "/monitor",
		StaticBase:           "/static",
		LoginPath:            "/login",
		SettingsPasswordPath: "/settings/password",
		Settings2FAPath:      "/settings/2fa",
	}
	return NewHTTPHandler(tmpl, routes, config.CardsConfig{}, config.SystemInfoData{})
}

func requireHTMLSecurityHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	tests := map[string]string{
		"X-Frame-Options":            "SAMEORIGIN",
		"X-Content-Type-Options":     "nosniff",
		"Referrer-Policy":            "strict-origin-when-cross-origin",
		"Cross-Origin-Opener-Policy": "same-origin",
	}
	for header, want := range tests {
		if got := w.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
	if got := w.Header().Get("Content-Security-Policy-Report-Only"); got == "" {
		t.Fatal("Content-Security-Policy-Report-Only must be set")
	}
}

func TestLoginHTMLHasSecurityHeaders(t *testing.T) {
	h := testHTTPHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()

	h.Login(w, r)

	requireHTMLSecurityHeaders(t, w)
}

func TestSettingsHTMLHasSecurityHeaders(t *testing.T) {
	h := testHTTPHandler(t)
	csrfToken, err := newCSRFToken()
	if err != nil {
		t.Fatalf("newCSRFToken: %v", err)
	}
	sessionID := injectSession(t, csrfToken)

	tests := []struct {
		name string
		path string
		call func(http.ResponseWriter, *http.Request)
	}{
		{"password", "/settings/password", h.SettingsPassword},
		{"2fa", "/settings/2fa", h.Settings2FA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tt.path, nil)
			r.AddCookie(&http.Cookie{Name: defaultSessionCookieName, Value: sessionID})
			w := httptest.NewRecorder()

			tt.call(w, r)

			requireHTMLSecurityHeaders(t, w)
		})
	}
}
