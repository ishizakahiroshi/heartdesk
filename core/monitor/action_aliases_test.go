package monitor

import (
	heartdesk "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/authz"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestActionPermissionAliasesPreservePolicyAcrossDispatch(t *testing.T) {
	if os.Getenv("HEARTDESK_TEST_ACTION_ALIASES") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestActionPermissionAliasesPreservePolicyAcrossDispatch$")
		cmd.Env = append(os.Environ(), "HEARTDESK_TEST_ACTION_ALIASES=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return
	}
	root := t.TempDir()
	heartdesk.ConfigureEnvironment(map[string]string{"HEARTDESK_BASE_DIR": root, "HEARTDESK_CONFIG_DIR": filepath.Join(root, "config"), "HEARTDESK_USERS_TOML": filepath.Join(root, "config", "users.toml")})
	for _, cycle := range []map[string]string{{"a": "a"}, {"a": "b", "b": "a"}, {"a": "b", "b": "c", "c": "a"}} {
		if authz.ValidateActionPermissionAliases(cycle) == nil {
			t.Fatal("cyclic policy alias accepted")
		}
	}
	aliases := map[string]string{"restart_heartdesk": "example_restart"}
	if err := authz.ConfigureActionPermissionAliases(aliases); err != nil {
		t.Fatal(err)
	}
	aliases["restart_heartdesk"] = "caller_mutation"
	if authz.CanonicalActionKey("restart_heartdesk") != "example_restart" {
		t.Fatal("alias map not copied")
	}
	if authz.ConfigureActionPermissionAliases(nil) == nil {
		t.Fatal("alias configuration changed")
	}
	if err := ConfigureExtensions(Extensions{Actions: []Endpoint{{Name: "example_restart", CardID: navmeta.CardSecServices, AliasFor: "restart_heartdesk"}}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		in   authz.MergeActionsInput
		want bool
	}{
		{authz.MergeActionsInput{RoleDefaults: map[string]bool{"restart_heartdesk": true}}, true},
		{authz.MergeActionsInput{RoleDefaults: map[string]bool{"restart_heartdesk": true}, TenantActions: map[string]bool{"example_restart": false}}, false},
		{authz.MergeActionsInput{RoleDefaults: map[string]bool{"restart_heartdesk": false}, TenantActions: map[string]bool{"example_restart": true}}, true},
		{authz.MergeActionsInput{TenantActions: map[string]bool{"example_restart": true}, AgentActions: map[string]bool{"restart_heartdesk": false}}, false},
		{authz.MergeActionsInput{TenantActions: map[string]bool{"example_restart": false}, AgentActions: map[string]bool{"restart_heartdesk": true}}, true},
		{authz.MergeActionsInput{TenantActions: map[string]bool{"example_restart": true}, UserDeny: []string{"restart_heartdesk"}}, false},
		{authz.MergeActionsInput{TenantActions: map[string]bool{"restart_heartdesk": true}, UserDeny: []string{"example_restart"}}, false},
		{authz.MergeActionsInput{TenantActions: map[string]bool{"restart_heartdesk": true, "example_restart": false}}, false},
	} {
		policy := authz.MergeActions(tc.in)
		for _, key := range []string{"restart_heartdesk", "example_restart"} {
			if got := auth.ActionAllowed(policy, "tenant_user", key); got != tc.want {
				t.Fatalf("policy %s got %v want%v", key, got, tc.want)
			}
		}
	}
	cfg := &config.AppConfig{}
	cfg.Cards.DefaultMode = "full"
	h := NewHandler(template.New(""), routing.Current(), config.SystemInfoData{}, cfg)
	var restarts int
	restartSelf = func(string) error { restarts++; return nil }
	for _, role := range []string{"vendor_staff", "tenant_user"} {
		if err := auth.DefaultStore().AddUser(role, role, role, "synthetic-password"); err != nil {
			t.Fatal(err)
		}
		for _, allowed := range []bool{false, true} {
			u, _ := auth.DefaultStore().GetUser(role)
			u.AccessScreens = []string{"monitor"}
			s, err := auth.DefaultSessionManager().Create(u, "192.0.2.1", "synthetic-client", cfg.Cards, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			s.ActionPermissions["example_restart"] = allowed
			for _, key := range []string{"restart_heartdesk", "example_restart"} {
				req := httptest.NewRequest("POST", "http://example.com/monitor/?api="+key, nil)
				req.RemoteAddr = "192.0.2.1:1"
				req.Header.Set("User-Agent", "synthetic-client")
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
				req.Header.Set("X-CSRF-Token", s.CSRFToken)
				req.AddCookie(&http.Cookie{Name: "heartdesk_session_v2", Value: s.ID})
				req.AddCookie(&http.Cookie{Name: "heartdesk_csrf", Value: s.CSRFToken})
				w := httptest.NewRecorder()
				middleware.RequireScreen(auth.ScreenMonitor)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.dispatchAction(w, r, key) })).ServeHTTP(w, req)
				want := 403
				if allowed {
					want = 200
				}
				if w.Code != want {
					t.Fatalf("role%s allowed%v key%s got%d: %s", role, allowed, key, w.Code, w.Body.String())
				}
			}
			if got := auth.ActionAllowed(s.ActionPermissions, role, "restart_heartdesk"); got != allowed {
				t.Fatal("shared button action key differs from API policy")
			}
		}
	}
	if restarts != 4 {
		t.Fatalf("restart escaped policy gate: %d", restarts)
	}
	for _, allowed := range []bool{false, true} {
		text := "false"
		if allowed {
			text = "true"
		}
		if err := os.WriteFile(filepath.Join(root, "config", "actions_tenants.toml"), []byte("[tenants.alpha.agents.alpha-vps-example.actions]\nexample_restart = "+text+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		authz.ResetActionsCache()
		req := httptest.NewRequest("GET", "http://example.com/monitor/?agent=alpha-vps-example", nil)
		s := auth.Session{Role: "vendor_staff", TenantID: "alpha", ActionPermissions: map[string]bool{"example_restart": true}}
		for _, key := range []string{"restart_heartdesk", "example_restart"} {
			if got := isMonitorActionAllowed(req, s, key); got != allowed {
				t.Fatal("agent override did not use canonical policy key")
			}
		}
	}
}
