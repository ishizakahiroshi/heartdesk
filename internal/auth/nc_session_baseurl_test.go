package auth

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
)

// Nextcloud の Cookie は Path=/nextcloud で発行されるので、ボタンの行き先が /login の下だと
// ブラウザが Cookie を送らず、ログイン済みでも「Nextcloud にログインしてから」と案内されてしまう。
func TestLoginPageNCLinkIsUnderNextcloudPath(t *testing.T) {
	t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
	tmpl := template.Must(template.New("").Parse(`{{define "login"}}{{.NCSessionPath}}{{end}}`))
	routes := routing.Config{MonitorBase: "/monitor", StaticBase: "/static", LoginPath: "/login"}
	h := NewHTTPHandler(tmpl, routes, config.CardsConfig{}, config.SystemInfoData{})

	r := httptest.NewRequest(http.MethodGet, "/login?next=/monitor/", nil)
	w := httptest.NewRecorder()
	h.renderLogin(w, r, "", "")

	body := w.Body.String()
	if !strings.HasPrefix(body, "/nextcloud/") {
		t.Fatalf("NC login link = %q, want a path under /nextcloud/ so the browser sends Nextcloud cookies", body)
	}
	if !strings.Contains(body, "next=") {
		t.Fatalf("NC login link = %q, want next= to be carried over", body)
	}
}

// サブドメイン方式のテナントで base_host だけを使うと別ホストへ問い合わせてしまう
// （Nextcloud のログインが 404 で失敗した実例がある）。
func TestNCBaseURLForTenant(t *testing.T) {
	cases := []struct {
		name string
		tc   *routing.TenantConfig
		want string
	}{
		{"subdomain tenant uses slug host", &routing.TenantConfig{TenantSlug: "drive", RoutingMode: "subdomain", BaseHost: "example.com"}, "https://drive.example.com/nextcloud"},
		{"path tenant uses base host", &routing.TenantConfig{TenantSlug: "heartdesk", RoutingMode: "path", BaseHost: "nc.example.net"}, "https://nc.example.net/nextcloud"},
		{"nil tenant", nil, ""},
		{"host not buildable", &routing.TenantConfig{RoutingMode: "subdomain", BaseHost: "example.com"}, ""},
	}
	for _, c := range cases {
		if got := ncBaseURLForTenant(c.tc); got != c.want {
			t.Errorf("%s: ncBaseURLForTenant() = %q, want %q", c.name, got, c.want)
		}
	}
}
