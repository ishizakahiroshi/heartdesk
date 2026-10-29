package monitor

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	heartdesk "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
)

func TestInventoryAPIRequiresCardAndTenantScope(t *testing.T) {
	if os.Getenv("HEARTDESK_TEST_INVENTORY_AUTH") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestInventoryAPIRequiresCardAndTenantScope$", "-test.timeout=60s")
		cmd.Env = append(os.Environ(), "HEARTDESK_TEST_INVENTORY_AUTH=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return
	}
	root := t.TempDir()
	heartdesk.ConfigureEnvironment(map[string]string{"HEARTDESK_BASE_DIR": root, "HEARTDESK_CONFIG_DIR": root, "HEARTDESK_USERS_TOML": filepath.Join(root, "users.toml")})
	if err := auth.DefaultStore().AddUser("reader", "Synthetic reader", "tenant_user", "synthetic-password"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.AppConfig{Agents: map[string]config.AgentConfig{"alpha-vps-fixture": {IsPrimary: true}}}
	h := NewHandler(template.New(""), routing.Current(), config.SystemInfoData{}, cfg)
	protected := middleware.RequireScreen(auth.ScreenMonitor)(h)
	for _, tc := range []struct {
		agent, mode string
		auth        bool
		want        int
	}{
		{"alpha-vps-fixture", "full", true, 200}, {"beta-vps-fixture", "full", true, 403}, {"alpha-vps-fixture", "hidden", true, 403}, {"../fixture", "full", true, 400}, {"", "full", true, 400}, {"alpha-vps-fixture", "full", false, 401},
	} {
		r := httptest.NewRequest("GET", "http://example.com/monitor/?api=inventory&agent="+tc.agent, nil)
		r.RemoteAddr = "192.0.2.1:1"
		r.Header.Set("User-Agent", "synthetic-client")
		r.Header.Set("X-Requested-With", "XMLHttpRequest")
		if tc.auth {
			u, _ := auth.DefaultStore().GetUser("reader")
			u.AccessScreens = []string{"monitor"}
			s, err := auth.DefaultSessionManager().Create(u, "192.0.2.1", "synthetic-client", config.CardsConfig{DefaultMode: "full", Defaults: map[string]string{navmeta.CardSecUpdates: tc.mode}}, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			defer auth.DefaultSessionManager().Delete(s.ID)
			r.AddCookie(&http.Cookie{Name: "heartdesk_session_v2", Value: s.ID})
		}
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("agent=%s mode=%s auth=%v got=%d want=%d", tc.agent, tc.mode, tc.auth, w.Code, tc.want)
		}
		if w.Code == 200 && !strings.Contains(w.Body.String(), `"agent_id":"alpha-vps-fixture"`) {
			t.Fatal("primary host lost its reported inventory identity")
		}
	}
}
