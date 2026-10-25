package monitor

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	heartdesk "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
)

func TestR2LegacyAuthorization(t *testing.T) {
	// Session, environment and card registries are process-scoped. Follow the
	// existing endpoint-alias tests and isolate this synthetic fixture.
	if os.Getenv("HEARTDESK_TEST_R2_AUTHORIZATION") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestR2LegacyAuthorization$", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), "HEARTDESK_TEST_R2_AUTHORIZATION=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return
	}
	root := t.TempDir()
	heartdesk.ConfigureEnvironment(map[string]string{
		"HEARTDESK_BASE_DIR":            root,
		"HEARTDESK_DATA_DIR":            filepath.Join(root, "data"),
		"HEARTDESK_CONFIG_DIR":          root,
		"HEARTDESK_USERS_TOML":          filepath.Join(root, "users.toml"),
		"HEARTDESK_SESSION_COOKIE_NAME": "heartdesk_session_v2",
		"HEARTDESK_CSRF_COOKIE_NAME":    "heartdesk_csrf",
	})
	if err := auth.DefaultStore().AddUser("r2-reader", "Synthetic reader", "tenant_user", "synthetic-password"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.AppConfig{} // No credentials: local R2 returns before network or exec.
	h := NewHandler(template.New(""), routing.Current(), config.SystemInfoData{}, cfg)
	protected := middleware.RequireScreen(auth.ScreenMonitor)(h)
	request := func(method, query, mode string, authenticated, csrf bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "http://example.com/monitor/?"+query, nil)
		r.RemoteAddr = "192.0.2.1:1"
		r.Header.Set("User-Agent", "synthetic-client")
		r.Header.Set("X-Requested-With", "XMLHttpRequest")
		if authenticated {
			u, ok := auth.DefaultStore().GetUser("r2-reader")
			if !ok {
				t.Fatal("synthetic user missing")
			}
			u.AccessScreens = []string{"monitor"}
			cards := config.CardsConfig{DefaultMode: "full", Defaults: map[string]string{navmeta.CardSecR2: mode}}
			s, err := auth.DefaultSessionManager().Create(u, "192.0.2.1", "synthetic-client", cards, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			defer auth.DefaultSessionManager().Delete(s.ID)
			r.AddCookie(&http.Cookie{Name: "heartdesk_session_v2", Value: s.ID})
			if csrf {
				r.AddCookie(&http.Cookie{Name: "heartdesk_csrf", Value: s.CSRFToken})
				r.Header.Set("X-CSRF-Token", s.CSRFToken)
			}
		}
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		name, agent, mode string
		authenticated     bool
		status            int
	}{
		{"hidden same tenant", "alpha-vps-host1", "hidden", true, 403},
		{"hidden missing agent", "", "hidden", true, 403},
		{"visible same tenant", "alpha-vps-host1", "full", true, 200},
		{"visible missing agent stays local", "", "full", true, 200},
		{"foreign tenant", "beta-vps-host1", "full", true, 403},
		{"malformed agent", "..%2Fhost", "full", true, 400},
		{"anonymous", "alpha-vps-host1", "full", false, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var results []*httptest.ResponseRecorder
			for _, endpoint := range []string{"api=r2_metrics", "r2_metrics=1"} {
				w := request(http.MethodGet, endpoint+"&agent="+tc.agent, tc.mode, tc.authenticated, false)
				if w.Code != tc.status {
					t.Fatalf("%s: status=%d want=%d body=%s", endpoint, w.Code, tc.status, w.Body.String())
				}
				results = append(results, w)
			}
			if results[0].Body.String() != results[1].Body.String() || results[0].Header().Get("Content-Type") != results[1].Header().Get("Content-Type") {
				t.Fatal("legacy and canonical response contracts differ")
			}
			if tc.status == http.StatusOK {
				var got R2MetricsData
				if err := json.Unmarshal(results[1].Body.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if want := GetR2Metrics(cfg, tc.agent); !reflect.DeepEqual(got, want) {
					t.Fatalf("metrics payload changed: got=%+v want=%+v", got, want)
				}
			}
		})
	}
	// Preserve the legacy method contract, rather than redirecting POST to the
	// canonical action dispatcher. Real middleware still owns method and CSRF.
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if w := request(method, "r2_metrics=1", "full", true, true); w.Code != 200 {
			t.Fatalf("legacy %s with valid session/CSRF: %d %s", method, w.Code, w.Body.String())
		}
		if w := request(method, "r2_metrics=1", "hidden", true, true); w.Code != 403 {
			t.Fatalf("legacy hidden %s: %d", method, w.Code)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if w := request(method, "r2_metrics=1", "full", true, false); w.Code != 403 {
			t.Fatalf("legacy %s without CSRF: %d", method, w.Code)
		}
	}
	if w := request(http.MethodTrace, "r2_metrics=1", "full", true, true); w.Code != 405 {
		t.Fatalf("unknown legacy method: %d", w.Code)
	}
	// Exercise a component association through the existing startup registry
	// hook. This is isolated test metadata, not an extension API collision.
	meta, ok := navmeta.MonitorCardByAPIKey("r2_metrics")
	if !ok {
		t.Fatal("R2 card metadata missing")
	}
	navmeta.RegisterCard(meta, "Synthetic R2", "synthetic", 0, []string{"monitor"}, nil, "synthetic-r2")
	cfg.Components = map[string]bool{"synthetic-r2": false}
	for _, endpoint := range []string{"api=r2_metrics", "r2_metrics=1"} {
		for _, mode := range []string{"full", "hidden"} {
			if w := request(http.MethodGet, endpoint, mode, true, false); w.Code != 404 {
				t.Fatalf("disabled component %s/%s: %d", endpoint, mode, w.Code)
			}
		}
	}
	cfg.Components["synthetic-r2"] = true
	for _, endpoint := range []string{"api=r2_metrics", "r2_metrics=1"} {
		if w := request(http.MethodGet, endpoint, "full", true, false); w.Code != 200 {
			t.Fatalf("enabled component %s: %d", endpoint, w.Code)
		}
		if w := request(http.MethodGet, endpoint, "hidden", true, false); w.Code != 403 {
			t.Fatalf("enabled component bypassed card gate %s: %d", endpoint, w.Code)
		}
	}
}
