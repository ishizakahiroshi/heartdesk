package app_test

import (
	"encoding/json"
	"html"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/app"
	"github.com/ishizakahiroshi/heartdesk/core/monitor"
	heartdesk "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/authz"
	"github.com/ishizakahiroshi/heartdesk/web"
	"io/fs"
)

func TestEmbeddingIdentities(t *testing.T) {
	for _, scenario := range []string{"default", "custom", "invalid"} {
		t.Run(scenario, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestEmbeddingIdentityChild$")
			cmd.Env = append(os.Environ(), "HEARTDESK_TEST_EMBED_IDENTITY="+scenario)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
		})
	}
}

func TestEmbeddingIdentityChild(t *testing.T) {
	scenario := os.Getenv("HEARTDESK_TEST_EMBED_IDENTITY")
	if scenario == "" {
		t.Skip("child process")
	}
	opts := testOptions(t)
	if scenario == "invalid" {
		for _, bad := range []*app.MonitorIdentityConfig{{LoginHistorySourceKey: "phpmyadmin"}, {AuditAppTrustedJSONKey: "total_recent"}, {LoginHistorySourceKey: "__proto__"}, {LoginHistoryArchiveFilename: "../escape"}, {LoginHistoryArchiveFilename: "readme.txt"}} {
			opts.MonitorIdentity = bad
			if _, err := app.New(opts); err == nil {
				t.Fatalf("invalid monitor identity accepted: %+v", bad)
			}
		}
		opts.MonitorIdentity = nil
		for _, bad := range []*app.OperationalIdentityConfig{{SchedulerLockPrefix: "../escape"}, {AptUpdateLockPath: "relative.lock"}, {ScriptMetadataPrefix: "EXAMPLE;other"}, {AlertScriptName: "../runner"}, {TrustedAuditDBUser: "example'"}} {
			opts.OperationalIdentity = bad
			if _, err := app.New(opts); err == nil {
				t.Fatal("invalid operational identity accepted")
			}
		}
		opts.OperationalIdentity = nil
	}
	expected := app.MonitorIdentityConfig{AppName: "heartdesk", Subtitle: "server dashboard", StorageNamespace: "heartdesk", ThemeStorageKey: "heartdesk_theme", LoginLogAppName: "heartdesk_monitor", AdminLoginLogAppName: "heartdesk_admin", LoginHistorySourceKey: "heartdesk", LoginHistoryExportBasename: "login_history", LoginHistoryArchiveFilename: "login_history.txt", LoginHistoryArchiveLabel: "heartdesk ログイン履歴", AuditAppTrustedJSONKey: "excluded_app_trusted"}
	expectedOp := app.OperationalIdentityConfig{SchedulerLockPrefix: "heartdesk", AptUpdateLockPath: "/var/lock/heartdesk-apt-update.lock", ScriptMetadataPrefix: "HEARTDESK", AlertScriptName: "heartdesk-alerts", TrustedAuditDBUser: "heartdesk_app"}
	if scenario == "custom" {
		expected = app.MonitorIdentityConfig{AppName: "Example </script><img src=x>", Subtitle: "Example & Ops", StorageNamespace: "example", ThemeStorageKey: "old_example_theme", LoginLogAppName: "example_monitor", AdminLoginLogAppName: "example_admin", LoginHistorySourceKey: "example", LoginHistoryExportBasename: "example_history", LoginHistoryArchiveFilename: "example_history.txt", LoginHistoryArchiveLabel: "Example history", AuditAppTrustedJSONKey: "excluded_example_trusted"}
		expectedOp = app.OperationalIdentityConfig{SchedulerLockPrefix: "example", AptUpdateLockPath: filepath.Join(opts.BaseDir, "example-apt.lock"), ScriptMetadataPrefix: "EXAMPLE", AlertScriptName: "example-alerts", TrustedAuditDBUser: "example_app"}
		monitorInput, operationalInput := expected, expectedOp
		opts.MonitorIdentity, opts.OperationalIdentity = &monitorInput, &operationalInput
		opts.VendorName = "Example Vendor"
		opts.CardAliases = map[string]string{"example-old-card": "sec-login-history"}
	}
	runtime, err := app.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if opts.MonitorIdentity != nil {
		opts.MonitorIdentity.AppName = "caller mutation"
		opts.MonitorIdentity.ThemeStorageKey = "changed"
		opts.OperationalIdentity.SchedulerLockPrefix = "changed"
		opts.CardAliases["example-old-card"] = "sec-services"
	}
	actual, operational := monitor.CurrentMonitorIdentity(), heartdesk.OperationalIdentity()
	if actual != expected || operational != expectedOp {
		t.Fatalf("identity defaults/copy mismatch: monitor=%+v operational=%+v", actual, operational)
	}
	if scenario == "custom" && runtime.Context(nil).SystemInfo.VendorName != "Example Vendor" {
		t.Fatal("explicit vendor footer identity lost")
	}
	jsonBytes, err := json.Marshal(monitor.NginxLoginHistoriesResponse{})
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(jsonBytes, &wire); err != nil || len(wire) != 2 || wire[expected.LoginHistorySourceKey] == nil || wire["phpmyadmin"] == nil {
		t.Fatal("login history wire identity lost")
	}
	jsonBytes, err = json.Marshal(monitor.AuditAnomalySummary{WindowMin: 5, TotalRecent: 9, ExcludedAppTrusted: 3})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(jsonBytes, &wire); err != nil || string(wire[expected.AuditAppTrustedJSONKey]) != "3" || string(wire["total_recent"]) != "9" {
		t.Fatal("audit wire key/value lost")
	}
	page := monitor.PageData{Identity: actual, CardAliases: authz.ConfiguredCardAliases(), AppName: actual.AppName, PageTitle: actual.AppName, StaticBase: "/static", AppBase: "/monitor", Cards: map[string]template.HTML{}}
	rendered, err := runtime.Context(nil).Render("monitor", page)
	if err != nil {
		t.Fatal(err)
	}
	body := string(rendered)
	if !strings.Contains(body, "<title>"+html.EscapeString(actual.AppName)+"</title>") || strings.Contains(body, "</script><img src=x>") {
		t.Fatal("monitor template failed text/script escaping")
	}
	scripts := regexp.MustCompile(`(?s)<script>\s*(.*?)</script>`).FindStringSubmatch(body)
	if len(scripts) != 2 {
		t.Fatal("identity JavaScript block missing")
	}
	shared, err := fs.ReadFile(web.Static(), "js/shared.js")
	if err != nil {
		t.Fatal(err)
	}
	functions := ""
	for _, name := range []string{"configuredCardId", "loadCollapsedSet", "initThemeToggle"} {
		function := regexp.MustCompile(`(?s)function ` + name + `\([^)]*\) \{.*?\n\}`).Find(shared)
		if len(function) == 0 {
			t.Fatalf("missing preferences helper %s", name)
		}
		functions += string(function) + "\n"
	}
	if node, err := exec.LookPath("node"); err == nil {
		payload, _ := json.Marshal(map[string]any{"script": scripts[1], "functions": functions, "identity": expected, "custom": scenario == "custom"})
		program := `const fs=require('fs'),vm=require('vm'),assert=require('assert');const p=JSON.parse(fs.readFileSync(0,'utf8'));const c={};vm.runInNewContext(p.script,c);assert.strictEqual(c.HD_COLLAPSE_KEY,p.identity.StorageNamespace+'.monitor.collapsed.v1');assert.strictEqual(c.HD_SIDENAV_ORDER_KEY,p.identity.StorageNamespace+'.monitor.sidenav.order.v1');assert.strictEqual(c.HD_IDENTITY.AppName,p.identity.AppName);assert.strictEqual(c.HD_IDENTITY.ThemeStorageKey,p.identity.ThemeStorageKey);c.COLLAPSE_KEY=c.HD_COLLAPSE_KEY;let click,writes=0;const body={value:'',setAttribute(k,v){this.value=v},getAttribute(){return this.value}};c.document={body,getElementById(){return {addEventListener(k,f){click=f}}}};c.window={matchMedia(){return {matches:false}}};c.localStorage={getItem(k){if(k===c.HD_COLLAPSE_KEY)return ' ["example-old-card"] ';assert.strictEqual(k,p.identity.ThemeStorageKey);return 'light'},setItem(k,v){assert.strictEqual(k,p.identity.ThemeStorageKey);assert.strictEqual(v,'dark');writes++}};vm.runInNewContext(p.functions+';initThemeToggle();',c);click();assert.strictEqual(writes,1);const set=c.loadCollapsedSet();assert.strictEqual(set[p.custom?'sec-login-history':'example-old-card'],true);`
		cmd := exec.Command(node, "-e", program)
		cmd.Stdin = strings.NewReader(string(payload))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("rendered identity/preferences JavaScript failed: %v\n%s", err, out)
		}
	} else {
		t.Log("Node unavailable: JavaScript execution skipped; Go API/JSON/template assertions still ran")
	}
}
