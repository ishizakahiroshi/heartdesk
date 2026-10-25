package app_test

import (
	"context"
	"github.com/ishizakahiroshi/heartdesk/app"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRuntimeEmbeddingRegressions(t *testing.T) {
	for _, name := range []string{"prefix", "prefix-collision", "users-toml", "users-json", "users-explicit", "extract-collision", "aliases"} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestRuntimeEmbeddingRegressionChild$")
			cmd.Env = append(os.Environ(), "HEARTDESK_TEST_EMBED_REGRESSION="+name)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
		})
	}
}
func TestRuntimeEmbeddingRegressionChild(t *testing.T) {
	name := os.Getenv("HEARTDESK_TEST_EMBED_REGRESSION")
	if name == "" {
		t.Skip("child")
	}
	opts := testOptions(t)
	switch name {
	case "aliases":
		opts.ActionPermissionAliases = map[string]string{"a": "b", "b": "a"}
		if _, err := app.New(opts); err == nil {
			t.Fatal("cyclic permission aliases accepted")
		}
		aliases := map[string]string{"restart_heartdesk": "example_restart"}
		opts.ActionPermissionAliases = aliases
		rt, err := app.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		defer rt.Close()
		aliases["restart_heartdesk"] = "different_permission"
		if app.ActionAllowed(map[string]bool{"example_restart": false}, "vendor_staff", "restart_heartdesk") {
			t.Fatal("caller changed permission alias")
		}
		if !app.ActionAllowed(map[string]bool{"example_restart": true}, "tenant_user", "restart_heartdesk") {
			t.Fatal("explicit legacy grant lost")
		}
	case "prefix-collision":
		opts.Environment = map[string]string{"HEARTDESK_ROUTING_MODE": "path", "HEARTDESK_TENANT_SLUG": "example"}
		opts.Routes = []app.Route{{Pattern: "/example/monitor/private", Authenticate: func(http.ResponseWriter, *http.Request) bool { return true }, Handler: http.NotFoundHandler()}}
		if _, err := app.New(opts); err == nil {
			t.Fatal("standard subtree accepted as fallback")
		}
	case "prefix":
		opts.Environment = map[string]string{"HEARTDESK_ROUTING_MODE": "path", "HEARTDESK_TENANT_SLUG": "example"}
		opts.Routes = []app.Route{{Pattern: "/example/nc-file", Authenticate: func(http.ResponseWriter, *http.Request) bool { return true }, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("example")) })}}
		rt, err := app.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		defer rt.Close()
		if err := rt.Prepare(context.Background()); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		rt.Handler().ServeHTTP(w, httptest.NewRequest("GET", "http://example.com/example/nc-file", nil))
		if w.Code != 200 || w.Body.String() != "example" {
			t.Fatal(w.Code, w.Body.String())
		}
	case "users-toml", "users-json", "users-explicit":
		target := filepath.Join(opts.BaseDir, "custom-users.toml")
		t.Setenv("HEARTDESK_USERS_TOML", "")
		t.Setenv("HEARTDESK_USERS_JSON", "")
		if name == "users-toml" {
			t.Setenv("HEARTDESK_USERS_TOML", target)
		} else if name == "users-json" {
			t.Setenv("HEARTDESK_USERS_JSON", target)
		} else {
			t.Setenv("HEARTDESK_USERS_TOML", filepath.Join(opts.BaseDir, "process-users.toml"))
			opts.Environment = map[string]string{"HEARTDESK_USERS_JSON": target}
		}
		rt, err := app.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		defer rt.Close()
		if err := app.DefaultStore().AddUser("example", "Example", "vendor_staff", "synthetic-password"); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(target); err != nil {
			t.Fatal("explicit user store ignored", err)
		}
	case "extract-collision":
		opts.SchedulerOnly = true
		opts.ExtractJobID = "example_extract"
		opts.Jobs = []app.Job{{ID: "example_extract", Handler: func(context.Context, *app.SchedulerConfig) error { return nil }}}
		if rt, err := app.New(opts); err == nil {
			rt.Close()
			t.Fatal("extra job replaced renamed built-in")
		}
	}
}
