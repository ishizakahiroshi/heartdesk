package app_test

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/app"
)

func TestRuntimeAuthIdentity(t *testing.T) {
	for _, scenario := range []string{"default", "custom", "invalid"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeAuthIdentityChild$")
			cmd.Env = append(os.Environ(), "HEARTDESK_TEST_AUTH_IDENTITY="+scenario)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
		})
	}
}

func TestRuntimeAuthIdentityChild(t *testing.T) {
	scenario := os.Getenv("HEARTDESK_TEST_AUTH_IDENTITY")
	if scenario == "" {
		t.Skip("child process")
	}
	opts := testOptions(t)
	opts.ConfigDir = filepath.Join(opts.BaseDir, "config")
	if err := os.MkdirAll(opts.ConfigDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(opts.ConfigDir, "tenants.toml"), []byte("[[tenants]]\ntenant_id='alpha'\nbase_host='example.com'\nrouting_mode='path'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if scenario == "invalid" {
		for _, value := range []*app.AuthIdentityConfig{{NextcloudSessionEntryPath: "//example.com/login"}, {NextcloudSessionEntryPath: "/entry?next=other"}, {NextcloudSessionEntryPath: "/entry\r\nHeader"}, {LoginChallengeCookieName: "name;other"}} {
			opts.AuthIdentity = value
			if _, err := app.New(opts); err == nil {
				t.Fatal("unsafe identity accepted")
			}
		}
		opts.AuthIdentity = nil
	}
	title, subtitle, entry := "heartdesk", "server dashboard", "/nextcloud/heartdesk-login"
	if scenario == "custom" {
		title, subtitle, entry = "Example Login", "Example Dashboard", "/nextcloud/example-login"
		opts.AuthIdentity = &app.AuthIdentityConfig{LoginTitle: title, LoginSubtitle: subtitle, NextcloudSessionEntryPath: entry, LoginChallengeCookieName: "example_challenge", TOTPIssuer: "Example", NextcloudNotRegisteredMessage: "Example account is not registered."}
		opts.Routes = []app.Route{{Pattern: "/identity/private", Screen: "monitor", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("private")) })}}
	}
	runtime, err := app.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if opts.AuthIdentity != nil {
		opts.AuthIdentity.LoginTitle = "caller mutation"
		opts.AuthIdentity.NextcloudSessionEntryPath = "/changed"
	}
	if err := runtime.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	runtime.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://example.com/login?next=%2Fmonitor%2F%3Fview%3Dexample", nil))
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "<title>"+title+"</title>") || !strings.Contains(body, subtitle) || !strings.Contains(body, `href="`+entry+`?next=%2Fmonitor%2F%3Fview%3Dexample"`) {
		t.Fatalf("login identity mismatch: status%d title=%t subtitle=%t entry=%t", w.Code, strings.Contains(body, "<title>"+title+"</title>"), strings.Contains(body, subtitle), strings.Contains(body, entry+"?next="))
	}
	if scenario == "custom" {
		if err := app.DefaultStore().AddUser("example", "Example", "tenant_user", "synthetic-password"); err != nil {
			t.Fatal(err)
		}
		if err := app.DefaultStore().UpdateAccessScreens("example", []string{"monitor"}); err != nil {
			t.Fatal(err)
		}
		user, _ := app.DefaultStore().GetUser("example")
		session, err := app.DefaultSessionManager().Create(user, "192.0.2.1", "synthetic-client", runtime.Config().Cards, "alpha")
		if err != nil {
			t.Fatal(err)
		}
		request := func(method, path string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(method, "http://example.com"+path, nil)
			r.RemoteAddr = "192.0.2.1:1234"
			r.Header.Set("User-Agent", "synthetic-client")
			r.Header.Set("X-Requested-With", "XMLHttpRequest")
			r.Header.Set("X-CSRF-Token", session.CSRFToken)
			r.AddCookie(&http.Cookie{Name: "example_session", Value: session.ID})
			r.AddCookie(&http.Cookie{Name: "example_csrf", Value: session.CSRFToken})
			out := httptest.NewRecorder()
			runtime.Handler().ServeHTTP(out, r)
			return out
		}
		generated := request(http.MethodPost, "/monitor/?api=totp_generate")
		var response struct {
			URI string `json:"uri"`
		}
		if generated.Code != 200 || json.Unmarshal(generated.Body.Bytes(), &response) != nil {
			t.Fatal("TOTP JSON setup failed")
		}
		uri, err := url.Parse(response.URI)
		if err != nil || uri.Query().Get("issuer") != "Example" {
			t.Fatal("JSON TOTP setup lost configured issuer")
		}
		settings := request(http.MethodGet, runtime.Routes().Settings2FAPath)
		if settings.Code != 200 || !strings.Contains(html.UnescapeString(settings.Body.String()), "issuer=Example") {
			t.Fatal("settings TOTP setup lost configured issuer")
		}
		if before := request(http.MethodGet, "/identity/private"); before.Code != 200 {
			t.Fatal("synthetic session was not usable before logout")
		}
		logout := request(http.MethodPost, runtime.Routes().LogoutPath)
		if logout.Code != http.StatusFound {
			t.Fatal("configured-cookie logout failed")
		}
		if replay := request(http.MethodGet, "/identity/private"); replay.Code != http.StatusUnauthorized {
			t.Fatalf("logged-out token replay got%d want401", replay.Code)
		}
	}
}
