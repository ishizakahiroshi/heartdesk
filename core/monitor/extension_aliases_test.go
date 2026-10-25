package monitor

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	heartdesk "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/authz"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
)

func TestBuiltinEndpointAliasesValidateByKind(t *testing.T) {
	for _, ext := range []Extensions{
		{APIs: []Endpoint{{Name: "legacy_history", CardID: navmeta.CardSecLoginHistory, AliasFor: "login_history"}}},
		{Exports: []Endpoint{{Name: "LEGACY_history", CardID: navmeta.CardSecLoginHistory, AliasFor: "login_history"}}},
	} {
		if err := ValidateExtensions(ext); err != nil {
			t.Fatalf("same-kind builtin alias rejected: %v", err)
		}
	}
	for _, ext := range []Extensions{
		{APIs: []Endpoint{{Name: "legacy_api", CardID: navmeta.CardSecLoginHistory, AliasFor: "restart_heartdesk"}}},
		{Exports: []Endpoint{{Name: "legacy_export", CardID: navmeta.CardSecLoginHistory, AliasFor: "resources"}}},
		{APIs: []Endpoint{{Name: "legacy_api", CardID: navmeta.CardSecLoginHistory, AliasFor: "vendor_unknown"}}},
		{APIs: []Endpoint{{Name: "legacy_api", CardID: navmeta.CardSecLoginHistory, AliasFor: "another_extension"}}},
	} {
		if err := ValidateExtensions(ext); err == nil {
			t.Fatal("unknown, extension or cross-kind alias accepted")
		}
	}
}

func TestBuiltinEndpointAliasesRepeatTargetAuthorization(t *testing.T) {
	if os.Getenv("HEARTDESK_TEST_ENDPOINT_ALIASES") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestBuiltinEndpointAliasesRepeatTargetAuthorization$", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), "HEARTDESK_TEST_ENDPOINT_ALIASES=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return
	}
	root := t.TempDir()
	heartdesk.ConfigureEnvironment(map[string]string{"HEARTDESK_BASE_DIR": root, "HEARTDESK_CONFIG_DIR": root, "HEARTDESK_USERS_TOML": filepath.Join(root, "users.toml")})
	if err := authz.ConfigureCardAliases(map[string]string{"legacy-card": navmeta.CardSecLoginHistory}); err != nil {
		t.Fatal(err)
	}
	ext := Extensions{
		APIs: []Endpoint{
			{Name: "legacy_history", CardID: navmeta.CardSecServices, AliasFor: "login_history"},
			{Name: "legacy_users", CardID: navmeta.CardSecServices, AliasFor: "user_mgmt"},
			{Name: "legacy_extra_gate", CardID: navmeta.CardSecServices, AliasFor: "login_history", AllActions: []string{"example_gate"}},
		},
		Exports: []Endpoint{
			{Name: "LEGACY_history", CardID: navmeta.CardSecServices, AliasFor: "login_history"},
			{Name: "legacy_all", CardID: navmeta.CardSecServices, AliasFor: "all"},
		},
	}
	if err := ConfigureExtensions(ext); err != nil {
		t.Fatal(err)
	}
	// Configuration adds private dispatch metadata to copied slices only.
	if ext.APIs[0].kind != "" || ext.Exports[0].kind != "" {
		t.Fatal("caller endpoint slices mutated")
	}
	apiCalls, exportCalls, privilegedCalls := 0, 0, 0
	monitorSimpleAPIByName["login_history"] = func() interface{} { apiCalls++; return map[string]bool{"synthetic": true} }
	vendorOnlySimpleAPIByName["user_mgmt"] = func() interface{} { privilegedCalls++; return map[string]bool{"synthetic": true} }
	exportHandlers["login_history"] = func(w http.ResponseWriter) { exportCalls++; _, _ = w.Write([]byte("synthetic export")) }
	exportHandlers["all"] = func(w http.ResponseWriter) { privilegedCalls++; _, _ = w.Write([]byte("synthetic all")) }
	for _, role := range []string{"vendor_staff", "tenant_user"} {
		if err := auth.DefaultStore().AddUser(role, role, role, "synthetic-password"); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.AppConfig{}
	h := NewHandler(template.New(""), routing.Current(), config.SystemInfoData{}, cfg)
	request := func(query string, defaults map[string]string, authenticated bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "http://example.com/monitor/?"+query, nil)
		r.RemoteAddr = "192.0.2.1:1"
		r.Header.Set("User-Agent", "synthetic-client")
		if authenticated {
			u, _ := auth.DefaultStore().GetUser("tenant_user")
			u.AccessScreens = []string{"monitor"}
			cards := config.CardsConfig{DefaultMode: "full", Defaults: defaults}
			s, err := auth.DefaultSessionManager().Create(u, "192.0.2.1", "synthetic-client", cards, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			r.AddCookie(&http.Cookie{Name: "heartdesk_session_v2", Value: s.ID})
		}
		w := httptest.NewRecorder()
		middleware.RequireScreen(auth.ScreenMonitor)(h).ServeHTTP(w, r)
		return w
	}
	for _, query := range []string{"api=legacy_history", "export=LEGACY_history"} {
		if w := request(query, nil, true); w.Code != 200 {
			t.Fatalf("allowed alias %s: %d %s", query, w.Code, w.Body.String())
		}
		for _, hidden := range []string{"legacy-card", navmeta.CardSecLoginHistory, navmeta.CardSecServices} {
			if w := request(query, map[string]string{hidden: "hidden"}, true); w.Code != 403 {
				t.Fatalf("alias %s bypassed hidden %s: %d", query, hidden, w.Code)
			}
		}
		if w := request(query+"&agent=beta-vps-example", nil, true); w.Code != 403 {
			t.Fatalf("alias bypassed tenant boundary: %d", w.Code)
		}
		if w := request(query, nil, false); w.Code == 200 {
			t.Fatal("unauthenticated alias succeeded")
		}
	}
	for _, query := range []string{"api=legacy_users", "export=legacy_all", "api=legacy_extra_gate"} {
		if w := request(query, nil, true); w.Code != 403 {
			t.Fatalf("alias bypassed target privilege or alias extra permission: %s %d", query, w.Code)
		}
	}
	if apiCalls != 1 || exportCalls != 1 || privilegedCalls != 0 {
		t.Fatalf("blocked alias reached a handler: api=%d export=%d privileged=%d", apiCalls, exportCalls, privilegedCalls)
	}
}
