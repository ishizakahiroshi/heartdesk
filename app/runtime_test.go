package app_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ishizakahiroshi/heartdesk/app"
	"github.com/ishizakahiroshi/heartpost/agentsig"
)

// Every scenario has its own process because the public contract deliberately
// permits one runtime per process, including after Close or initialization error.
func TestRuntimeIsolatedScenarios(t *testing.T) {
	for _, scenario := range []string{"lifecycle", "failure", "preflight", "scheduler", "nil-license", "report", "revocation", "gates", "template-collision", "route-collision", "prepare-failure"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeScenario$", "-test.v")
			cmd.Env = append(os.Environ(), "HEARTDESK_TEST_SCENARIO="+scenario)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
		})
	}
}

func testOptions(t *testing.T) app.Options {
	root := t.TempDir()
	cfg := &app.Config{}
	cfg.Server.ListenAddr = "127.0.0.1:0"
	cfg.Cards.DefaultMode = "full"
	return app.Options{BaseDir: root, Config: cfg, TenantID: "alpha", DefaultTenantID: "alpha", SkipStartupMaintenance: true, SessionCookieName: "example_session", CSRFCookieName: "example_csrf", VerifyLicense: func(*app.Config) error { return nil }}
}

func TestRuntimeScenario(t *testing.T) {
	scenario := os.Getenv("HEARTDESK_TEST_SCENARIO")
	if scenario == "" {
		t.Skip("child scenario")
	}
	opts := testOptions(t)
	switch scenario {
	case "prepare-failure":
		opts.Config.Database.DSN = filepath.Join(opts.BaseDir, "nonexistent", "database.db")
		rt, err := app.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		if err := rt.Prepare(context.Background()); err == nil {
			t.Fatal("invalid DB configuration accepted")
		}
		if err := rt.Prepare(context.Background()); err == nil {
			t.Fatal("failed preparation retried silently")
		}
		w := httptest.NewRecorder()
		rt.Handler().ServeHTTP(w, httptest.NewRequest("GET", "http://example.com/healthz", nil))
		if w.Code != 503 {
			t.Fatal("failed runtime became ready")
		}
		if err := rt.Close(); err != nil {
			t.Fatal(err)
		}
	case "revocation":
		strict := true
		opts.Config.AgentReport.StrictLicense = &strict
		opts.Config.AgentKeys = map[string]string{"alpha-vps-example": "synthetic-hmac"}
		opts.Config.AgentAllowedIPs = map[string][]string{"alpha-vps-example": {"192.0.2.1"}}
		priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
		opts.Config.VendorLicense.SigningKeys = map[string]app.SigningKeyEntry{"synthetic": {PublicKeyB64: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))}}
		now := time.Now()
		claims, _ := json.Marshal(map[string]interface{}{"iss": "heartdesk-vendor", "aud": "heartdesk-monitor", "sub": "alpha-vps-example", "tid": "alpha", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nbf": now.Add(-time.Minute).Unix(), "jti": "synthetic-revoked", "scope": "agent.report", "type": "session"})
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT","kid":"synthetic"}`))
		message := header + "." + base64.RawURLEncoding.EncodeToString(claims)
		token := message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(message)))
		revoked, _ := json.Marshal(map[string]interface{}{"synthetic-revoked": map[string]string{"agent_id": "alpha-vps-example", "revoked_at": now.Format(time.RFC3339), "expires_at": now.Add(time.Hour).Format(time.RFC3339)}})
		licenseDir := filepath.Join(opts.BaseDir, "data", "license")
		if err := os.MkdirAll(licenseDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(licenseDir, "revoked_jti.json"), revoked, 0600); err != nil {
			t.Fatal(err)
		}
		rt, err := app.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		defer rt.Close()
		body := `{"agent_id":"alpha-vps-example","collectors":{}}`
		for _, prepared := range []bool{false, true} {
			if prepared {
				if err := rt.Prepare(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			req := httptest.NewRequest("POST", "http://example.com/api/agent/report", strings.NewReader(body))
			req.RemoteAddr = "192.0.2.1:1234"
			req.Header.Set("X-Agent-Id", "alpha-vps-example")
			ts := strconv.FormatInt(now.Unix(), 10)
			req.Header.Set("X-Agent-Timestamp", ts)
			req.Header.Set("X-Agent-Signature", agentsig.Compute("synthetic-hmac", ts, []byte(body)))
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			rt.Handler().ServeHTTP(w, req)
			want := 503
			if prepared {
				want = 401
			}
			if w.Code != want {
				t.Fatalf("prepared=%v got %d want%d: %s", prepared, w.Code, want, w.Body.String())
			}
		}
	case "nil-license":
		opts.VerifyLicense = nil
		if _, err := app.New(opts); err == nil {
			t.Fatal("nil verifier bypassed standard license gate")
		}
	case "template-collision":
		opts.TemplateFS = fstest.MapFS{"extension.html": {Data: []byte(`{{define "monitor.html"}}replacement{{end}}`)}}
		if _, err := app.New(opts); err == nil {
			t.Fatal("template definition collision accepted")
		}
	case "route-collision":
		opts.Routes = []app.Route{{Pattern: "/api/", Screen: "monitor", Handler: http.NotFoundHandler()}}
		if _, err := app.New(opts); err == nil {
			t.Fatal("standard route replaced")
		}
	case "report":
		relaxed := false
		opts.DataDir = filepath.Join(opts.BaseDir, "state")
		opts.Config.AgentReport.StrictLicense = &relaxed
		opts.Config.AgentKeys = map[string]string{"alpha-vps-example": "synthetic-hmac-material"}
		opts.Config.AgentAllowedIPs = map[string][]string{"alpha-vps-example": {"192.0.2.1"}}
		var saved atomic.Int32
		opts.OnReportSaved = func(ctx *app.RequestContext, report app.AgentReport) {
			paths, err := filepath.Glob(filepath.Join(opts.DataDir, "json", "agent_reports", "report_*.jsonl"))
			if err != nil || len(paths) != 1 {
				t.Error("hook ran before durable report", err)
			}
			if len(paths) == 1 {
				body, err := os.ReadFile(paths[0])
				if err != nil || !strings.Contains(string(body), report.AgentID) {
					t.Error("report not saved before hook", err)
				}
			}
			if ctx.Config.TenantID != "alpha" || ctx.AgentID != report.AgentID {
				t.Error("wrong report context")
			}
			saved.Add(1)
		}
		rt, err := app.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		defer rt.Close()
		if err := rt.Prepare(context.Background()); err != nil {
			t.Fatal(err)
		}
		body := `{"agent_id":"alpha-vps-example","agent_type":"vps","collectors":{}}`
		for _, valid := range []bool{false, true} {
			r := httptest.NewRequest("POST", "http://example.com/api/agent/report", strings.NewReader(body))
			r.RemoteAddr = "192.0.2.1:1234"
			r.Header.Set("X-Agent-Id", "alpha-vps-example")
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			r.Header.Set("X-Agent-Timestamp", ts)
			sig := agentsig.Compute("synthetic-hmac-material", ts, []byte(body))
			if !valid {
				sig = "invalid"
			}
			r.Header.Set("X-Agent-Signature", sig)
			w := httptest.NewRecorder()
			rt.Handler().ServeHTTP(w, r)
			want := 401
			if valid {
				want = 200
			}
			if w.Code != want {
				t.Fatalf("report valid=%v: %d %s", valid, w.Code, w.Body.String())
			}
		}
		if saved.Load() != 1 {
			t.Fatal("observer ran for rejected report", saved.Load())
		}
	case "gates":
		var hits atomic.Int32
		data := func(*app.RequestContext) (interface{}, error) { hits.Add(1); return "example card", nil }
		opts.Config.Components = map[string]bool{"example_disabled": false}
		opts.Config.Agents = map[string]app.AgentConfig{"alpha-vps-example": {AgentType: "vps", Capabilities: []string{"snapshot.resources"}}}
		opts.TemplateFS = fstest.MapFS{"extension.html": {Data: []byte(`{{define "card-sec-example"}}{{.}}{{end}}{{define "card-sec-disabled"}}{{.}}{{end}}`)}}
		opts.Extensions.Cards = []app.Card{
			{Meta: app.CardMeta{ID: "sec-example", Key: "EXAMPLE", API: "example_card"}, ClientOnly: true, Capabilities: []string{"example.feature"}, Data: data, AllActions: []string{"example_create"}},
			{Meta: app.CardMeta{ID: "sec-disabled", Key: "DISABLED", API: "disabled_card"}, Component: "example_disabled", Data: data},
		}
		opts.Extensions.Exports = []app.Endpoint{{Name: "example_export", CardID: "sec-example", AllActions: []string{"example_create"}, Handler: func(w http.ResponseWriter, r *http.Request, c *app.RequestContext) {
			hits.Add(1)
			w.Write([]byte("export accepted"))
		}}}
		rt, err := app.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		defer rt.Close()
		if err := rt.Prepare(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := app.DefaultStore().AddUser("example", "Example", "vendor_staff", "synthetic-password"); err != nil {
			t.Fatal(err)
		}
		u, _ := app.DefaultStore().GetUser("example")
		u.AccessScreens = []string{"monitor"}
		cards := rt.Config().Cards
		full, err := app.DefaultSessionManager().Create(u, "192.0.2.1", "synthetic-client", cards, "alpha")
		if err != nil {
			t.Fatal(err)
		}
		cards.Defaults = map[string]string{"sec-example": "hidden"}
		hidden, _ := app.DefaultSessionManager().Create(u, "192.0.2.1", "synthetic-client", cards, "alpha")
		u.AccessScreens = nil
		noScreen, _ := app.DefaultSessionManager().Create(u, "192.0.2.1", "synthetic-client", rt.Config().Cards, "alpha")
		for _, tc := range []struct {
			path   string
			sess   app.Session
			status int
		}{
			{"/monitor/card?card=example_card", full, 200},
			{"/monitor/card?card=example_card", hidden, 403},
			{"/monitor/card?card=example_card", noScreen, 403},
			{"/monitor/card?card=example_card&agent=alpha-vps-example", full, 403},
			{"/monitor/card?card=disabled_card", full, 404},
			{"/monitor/?export=example_export", hidden, 403},
			{"/monitor/?export=example_export", full, 200},
		} {
			r := httptest.NewRequest("GET", "http://example.com"+tc.path, nil)
			r.RemoteAddr = "192.0.2.1:1"
			r.Header.Set("User-Agent", "synthetic-client")
			r.AddCookie(&http.Cookie{Name: "example_session", Value: tc.sess.ID})
			w := httptest.NewRecorder()
			rt.Handler().ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Errorf("%s got%d want%d: %s", tc.path, w.Code, tc.status, w.Body.String())
			}
		}
		if hits.Load() != 2 {
			t.Fatal("denied card/export invoked callback", hits.Load())
		}
	case "failure":
		opts.VerifyLicense = func(*app.Config) error { return errors.New("synthetic rejection") }
		if _, err := app.New(opts); err == nil {
			t.Fatal("license rejection lost")
		}
		if _, err := app.New(testOptions(t)); !errors.Is(err, app.ErrRuntimeInitialized) {
			t.Fatalf("retry after partial initialization: %v", err)
		}
	case "preflight":
		opts.StaticFS = fstest.MapFS{"img/favicon.svg": {Data: []byte("collision")}}
		if _, err := app.New(opts); err == nil {
			t.Fatal("standard asset replaced")
		}
		opts.StaticFS = nil
		opts.Extensions.APIs = []app.Endpoint{{Name: "services", CardID: "sec-services", Handler: func(http.ResponseWriter, *http.Request, *app.RequestContext) {}}}
		if _, err := app.New(opts); err == nil {
			t.Fatal("standard API replaced")
		}
		opts.Extensions = app.Extensions{}
		rt, err := app.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		defer rt.Close()
	case "scheduler":
		opts.SchedulerOnly = true
		opts.ExtractJobID = "example_extract"
		var called atomic.Int32
		disabled := map[string]bool{}
		for _, j := range app.Jobs() {
			disabled[j.ID] = true
		}
		disabled["example_extract"] = true
		opts.SchedulerConfig = &app.SchedulerConfig{BaseDir: opts.BaseDir, StateFile: filepath.Join(opts.BaseDir, "scheduler.json"), DisabledJobs: disabled}
		opts.Jobs = []app.Job{{ID: "example_job", Category: "daemon", Interval: time.Hour, RunOnStartup: true, Handler: func(ctx context.Context, cfg *app.SchedulerConfig) error { called.Add(1); return nil }}}
		rt, err := app.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- rt.RunScheduler(ctx) }()
		deadline := time.Now().Add(5 * time.Second)
		for called.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if called.Load() != 1 {
			t.Fatal("custom job did not run")
		}
		if err := rt.RunScheduler(ctx); err == nil {
			t.Fatal("duplicate scheduler accepted")
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := rt.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(opts.BaseDir, "data", "vendor", "vendor.db")); !os.IsNotExist(err) {
			t.Fatal("scheduler-only preparation opened monitor database")
		}
		found := false
		for _, j := range app.Jobs() {
			found = found || j.ID == "example_extract"
			if j.ID == "heartdesk_extract" {
				t.Fatal("old extract ID leaked")
			}
		}
		if !found {
			t.Fatal("extract ID absent")
		}
	case "lifecycle":
		reserved, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := reserved.Addr().String()
		if err := reserved.Close(); err != nil {
			t.Fatal(err)
		}
		opts.Config.Server.ListenAddr = addr
		var invoked atomic.Int32
		hook := func(w http.ResponseWriter, r *http.Request, c *app.RequestContext) {
			invoked.Add(1)
			if c.Config.TenantID != "alpha" {
				t.Error("wrong shared configuration")
			}
			w.Write([]byte("extension accepted"))
		}
		opts.Environment = map[string]string{"HEARTDESK_ICON": "example.svg"}
		opts.Config.Database.DSN = filepath.Join(opts.BaseDir, "shared.db")
		opts.StaticFS = fstest.MapFS{"extensions/example.js": {Data: []byte("example")}}
		opts.Extensions.Actions = []app.Endpoint{{Name: "example_preview", CardID: "sec-services", ReadOnly: true, AllActions: []string{"example_create"}, Handler: hook}}
		opts.Extensions.APIs = []app.Endpoint{{Name: "example_api", CardID: "sec-services", AllActions: []string{"example_create"}, Handler: hook}}
		opts.Routes = []app.Route{{Pattern: "/example/private", Methods: []string{"GET"}, Authenticate: func(w http.ResponseWriter, r *http.Request) bool {
			if r.Header.Get("Authorization") != "Bearer synthetic" {
				http.Error(w, "denied", 401)
				return false
			}
			return true
		}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("private accepted")) })}}
		rt, err := app.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(opts.Config.Database.DSN); !os.IsNotExist(err) {
			t.Fatal("New opened database")
		}
		if _, err := os.Stat(filepath.Join(opts.BaseDir, "data", "vendor", "vendor.db")); !os.IsNotExist(err) {
			t.Fatal("New opened report database")
		}
		unready := httptest.NewRecorder()
		rt.Handler().ServeHTTP(unready, httptest.NewRequest("POST", "http://example.com/api/agent/report", nil))
		if unready.Code != 503 {
			t.Fatal("unprepared report accepted", unready.Code)
		}
		if err := rt.Prepare(context.Background()); err != nil {
			t.Fatal(err)
		}
		opts.Config.Server.Name = "caller mutation"
		opts.Environment["HEARTDESK_ICON"] = "changed.svg"
		opts.Routes[0].Methods[0] = "POST"
		if rt.Config().Server.Name != "" || rt.Routes().IconFile != "example.svg" {
			t.Fatal("caller configuration was retained")
		}
		request := func(method, path string, sess *app.Session, csrf bool) *httptest.ResponseRecorder {
			r := httptest.NewRequest(method, "http://example.com"+path, nil)
			r.RemoteAddr = "192.0.2.1:1234"
			r.Header.Set("User-Agent", "synthetic-client")
			r.Header.Set("X-Requested-With", "XMLHttpRequest")
			if sess != nil {
				r.AddCookie(&http.Cookie{Name: "example_session", Value: sess.ID})
				if csrf {
					r.AddCookie(&http.Cookie{Name: "example_csrf", Value: sess.CSRFToken})
					r.Header.Set("X-CSRF-Token", sess.CSRFToken)
				}
			}
			w := httptest.NewRecorder()
			rt.Handler().ServeHTTP(w, r)
			return w
		}
		for _, role := range []string{"vendor_staff", "tenant_user"} {
			if err := app.DefaultStore().AddUser(role, role, role, "synthetic-password"); err != nil {
				t.Fatal(err)
			}
			if err := app.DefaultStore().UpdateAccessScreens(role, []string{"monitor"}); err != nil {
				t.Fatal(err)
			}
		}
		makeSession := func(role string) app.Session {
			u, ok := app.DefaultStore().GetUser(role)
			if !ok {
				t.Fatal("missing fixture user")
			}
			s, e := app.DefaultSessionManager().Create(u, "192.0.2.1", "synthetic-client", rt.Config().Cards, "alpha")
			if e != nil {
				t.Fatal(e)
			}
			return s
		}
		vendor, user := makeSession("vendor_staff"), makeSession("tenant_user")
		for _, tc := range []struct {
			method, path string
			sess         *app.Session
			csrf         bool
			status       int
		}{
			{"GET", "/monitor/?api=example_api", nil, false, 401},
			{"GET", "/monitor/?api=example_api", &user, false, 403},
			{"GET", "/monitor/?api=example_api", &vendor, false, 200},
			{"PUT", "/monitor/?api=example_api", &vendor, true, 405},
			{"POST", "/monitor/?api=example_preview", &vendor, false, 403},
			{"POST", "/monitor/?api=example_preview", &user, true, 403},
			{"POST", "/monitor/?api=example_preview", &vendor, true, 200},
			{"GET", "/monitor/?api=example_api&agent=beta-vps-example", &user, false, 403},
			{"GET", "/static/extensions/example.js", nil, false, 200},
			{"GET", "/static/extensions/", nil, false, 404},
			{"GET", "/example/private", nil, false, 401},
			{"POST", "/example/private", nil, false, 405},
		} {
			w := request(tc.method, tc.path, tc.sess, tc.csrf)
			if w.Code != tc.status {
				t.Errorf("%s %s got %d want %d: %s", tc.method, tc.path, w.Code, tc.status, w.Body.String())
			}
		}
		if invoked.Load() != 2 {
			t.Fatalf("denied callback executed: %d", invoked.Load())
		}
		r := httptest.NewRequest("GET", "http://example.com/example/private", nil)
		r.Header.Set("Authorization", "Bearer synthetic")
		w := httptest.NewRecorder()
		rt.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- rt.Run(ctx) }()
		deadline := time.Now().Add(5 * time.Second)
		ready := false
		for time.Now().Before(deadline) {
			conn, e := net.DialTimeout("tcp", addr, 50*time.Millisecond)
			if e == nil {
				conn.Close()
				ready = true
				break
			}
			select {
			case err := <-done:
				t.Fatalf("monitor stopped before listening: %v", err)
			default:
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !ready {
			cancel()
			t.Fatal("monitor did not start listening")
		}
		if err := rt.Run(ctx); err == nil {
			t.Fatal("duplicate monitor accepted")
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := rt.Close(); err != nil {
			t.Fatal(err)
		}
		if err := rt.Close(); err != nil {
			t.Fatal(err)
		}
		if w := request("GET", "/healthz", nil, false); w.Code != 503 {
			t.Fatal("closed handler accepted request")
		}
		if err := rt.Run(context.Background()); err == nil {
			t.Fatal("closed runtime restarted")
		}
		if _, err := app.New(testOptions(t)); !errors.Is(err, app.ErrRuntimeInitialized) {
			t.Fatal("second runtime accepted", err)
		}
	default:
		t.Fatal("unknown scenario")
	}
}
