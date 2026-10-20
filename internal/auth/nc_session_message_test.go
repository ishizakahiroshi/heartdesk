package auth

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
)

// ncMessageTestHandler は login テンプレートにエラー文言だけを出すハンドラを返す。
func ncMessageTestHandler(t *testing.T) *HTTPHandler {
	t.Helper()
	t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
	tmpl := template.Must(template.New("").Parse(`{{define "login"}}{{.Error}}{{end}}`))
	routes := routing.Config{MonitorBase: "/monitor", StaticBase: "/static", LoginPath: "/login"}
	return NewHTTPHandler(tmpl, routes, config.CardsConfig{}, config.SystemInfoData{})
}

// swapNCMessageTestStore は DefaultStore をテスト専用の中身へ差し替える。
func swapNCMessageTestStore(t *testing.T, users map[string]User) {
	t.Helper()
	old := DefaultStore()
	defaultStore = &UserStore{
		path:     filepath.Join(t.TempDir(), "users.toml"),
		users:    cloneUsers(users),
		loadedAt: time.Now(),
	}
	t.Cleanup(func() { defaultStore = old })
}

func ncMessageTestLogin(t *testing.T, h *HTTPHandler, uid string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// 実際の問い合わせ先は OCS v2 なので、成功時の statuscode は 200。
		w.Write([]byte(`{"ocs":{"meta":{"status":"ok","statuscode":200},"data":{"id":"` + uid + `"}}}`))
	}))
	defer srv.Close()

	r := httptest.NewRequest(http.MethodGet, "/login/nc", nil)
	r.Header.Set("Cookie", "oc_sessionPassphrase=abc")
	w := httptest.NewRecorder()
	h.loginNCWithBase(w, r, srv.URL)
	return w.Body.String()
}

// Nextcloud には入れているが heartdesk に登録の無い人へ「入力内容を確認してください」を出さない
// （何も入力していないのにその文言が出ると、壊れているように見えるため）。
func TestLoginNCUnregisteredShowsDedicatedMessage(t *testing.T) {
	h := ncMessageTestHandler(t)
	swapNCMessageTestStore(t, nil)

	body := ncMessageTestLogin(t, h, "nextcloud-only-user")

	if !strings.Contains(body, ncNotRegisteredError) {
		t.Fatalf("body = %q, want dedicated not-registered message", body)
	}
	if strings.Contains(body, genericLoginError) {
		t.Fatalf("body = %q, must not show the password-form message", body)
	}
}

// 無効化されたユーザーは従来どおり共通文言のまま。
func TestLoginNCDisabledKeepsGenericMessage(t *testing.T) {
	h := ncMessageTestHandler(t)
	swapNCMessageTestStore(t, map[string]User{
		"disabled-user": {
			ID:            "disabled-user",
			Username:      "disabled-user",
			Role:          string(RoleTenantUser),
			Disabled:      true,
			AccessScreens: []string{string(ScreenMonitor)},
		},
	})

	body := ncMessageTestLogin(t, h, "disabled-user")

	if !strings.Contains(body, genericLoginError) {
		t.Fatalf("body = %q, want generic login error", body)
	}
}
