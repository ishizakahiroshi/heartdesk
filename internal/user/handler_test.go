package user

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
)

func TestServeHTMLEscapesUserAndSetsSecurityHeaders(t *testing.T) {
	h := NewHandler()
	r := httptest.NewRequest(http.MethodGet, "/module/nextcloud/user/", nil)
	r = r.WithContext(context.WithValue(r.Context(), middleware.UserKey, `<script>alert(1)</script>`))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	body := w.Body.String()
	if strings.Contains(body, `<script>alert(1)</script>`) {
		t.Fatalf("response contains unescaped user value: %s", body)
	}
	if !strings.Contains(body, `&lt;script&gt;alert(1)&lt;/script&gt;`) {
		t.Fatalf("response does not contain escaped user value: %s", body)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("X-Frame-Options = %q, want SAMEORIGIN", got)
	}
	if got := w.Header().Get("Content-Security-Policy-Report-Only"); got == "" {
		t.Fatal("Content-Security-Policy-Report-Only must be set")
	}
}
