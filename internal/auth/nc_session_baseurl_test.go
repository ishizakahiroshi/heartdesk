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
	link := ncSessionLinkFor("https://nc.example.net/nextcloud", "/monitor/")
	if !strings.HasPrefix(link, "/nextcloud/") {
		t.Fatalf("NC login link = %q, want a path under /nextcloud/ so the browser sends Nextcloud cookies", link)
	}
	if !strings.Contains(link, "next=") {
		t.Fatalf("NC login link = %q, want next= to be carried over", link)
	}
}

// Nextcloud のベース URL が導けないとき（テナント未設定）は、押すと 404 になるボタンを出さない。
func TestLoginPageHidesNCLinkWhenNotConfigured(t *testing.T) {
	if got := ncSessionLinkFor("", "/monitor/"); got != "" {
		t.Fatalf("ncSessionLinkFor(empty base) = %q, want empty", got)
	}

	// 画面全体でも空になる（HEARTDESK_TENANT_ID 未設定 = 最小構成）。
	t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
	t.Setenv("HEARTDESK_TENANT_ID", "")
	tmpl := template.Must(template.New("").Parse(`{{define "login"}}[{{.NCSessionPath}}]{{end}}`))
	routes := routing.Config{MonitorBase: "/monitor", StaticBase: "/static", LoginPath: "/login"}
	h := NewHTTPHandler(tmpl, routes, config.CardsConfig{}, config.SystemInfoData{})

	w := httptest.NewRecorder()
	h.renderLogin(w, httptest.NewRequest(http.MethodGet, "/login?next=/monitor/", nil), "", "")
	if body := w.Body.String(); body != "[]" {
		t.Fatalf("login page NCSessionPath = %q, want empty when no tenant is configured", body)
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
