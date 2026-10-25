package monitor

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	heartdesk "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/web"
)

func TestOverviewCurrentInventory(t *testing.T) {
	t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
	agentLastSeenMu.Lock()
	origSeen, origCols := agentLastSeen, agentLatestCollectors
	agentLastSeen = map[string]*AgentLastSeen{}
	for _, id := range []string{"alpha-vps-live", "alpha-vps-retired", "beta-vps-live", "beta-vps-disabled"} {
		agentLastSeen[id] = &AgentLastSeen{AgentID: id, AgentLabel: "same label", AgentType: "vps", ReceivedAt: time.Now().Format(time.RFC3339)}
	}
	agentLatestCollectors = map[string]map[string]json.RawMessage{}
	agentLastSeenMu.Unlock()
	t.Cleanup(func() {
		agentLastSeenMu.Lock()
		agentLastSeen, agentLatestCollectors = origSeen, origCols
		agentLastSeenMu.Unlock()
	})
	own := map[string]config.AgentConfig{
		"alpha-vps-live":    {AgentID: "alpha-vps-live"},
		"alpha-vps-missing": {AgentID: "alpha-vps-missing"},
	}
	aggregate := map[string]string{"beta-vps-live": "synthetic-key", "beta-vps-disabled": ""}
	for _, tc := range []struct {
		name         string
		cfg          *config.AppConfig
		role, tenant string
		want         string
	}{
		{"local", &config.AppConfig{Agents: own}, "vendor_staff", "alpha", "alpha-vps-live,alpha-vps-missing"},
		{"aggregate", &config.AppConfig{AggregatorAgentKeys: aggregate}, "vendor_staff", "alpha", "beta-vps-live"},
		{"union", &config.AppConfig{Agents: own, AggregatorAgentKeys: aggregate}, "vendor_staff", "alpha", "alpha-vps-live,alpha-vps-missing,beta-vps-live"},
		{"tenant", &config.AppConfig{Agents: own, AggregatorAgentKeys: aggregate}, "tenant_admin", "alpha", "alpha-vps-live,alpha-vps-missing"},
		{"no tenant", &config.AppConfig{Agents: own}, "tenant_admin", "", ""},
		{"disabled aggregate", &config.AppConfig{AggregatorAgentKeys: map[string]string{"beta-vps-disabled": ""}}, "vendor_staff", "", ""},
		{"legacy", &config.AppConfig{}, "vendor_staff", "", "alpha-vps-live,alpha-vps-retired,beta-vps-disabled,beta-vps-live"},
		{"nil legacy", nil, "tenant_user", "beta", "beta-vps-disabled,beta-vps-live"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := getAgentOverviewForConfig(tc.cfg, tc.role, tc.tenant)
			var ids []string
			for _, row := range rows {
				ids = append(ids, row.AgentID)
				if row.AgentID == "alpha-vps-missing" && (!row.IsAlert || row.ReceivedAt != "") {
					t.Fatal("unreported registration must remain an alert")
				}
				if row.AgentID == "alpha-vps-live" && row.IsAlert {
					t.Fatal("fresh report must remain healthy")
				}
			}
			if got := strings.Join(ids, ","); got != tc.want {
				t.Fatalf("inventory = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestOverviewHandlerUsesEffectiveConfig(t *testing.T) {
	// Environment and authentication defaults are process-wide; isolate this fixture.
	if os.Getenv("HEARTDESK_TEST_OVERVIEW_CONTEXT") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestOverviewHandlerUsesEffectiveConfig$", "-test.timeout=60s")
		cmd.Env = append(os.Environ(), "HEARTDESK_TEST_OVERVIEW_CONTEXT=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return
	}
	root := t.TempDir()
	heartdesk.ConfigureEnvironment(map[string]string{"HEARTDESK_BASE_DIR": root, "HEARTDESK_CONFIG_DIR": root, "HEARTDESK_USERS_TOML": filepath.Join(root, "users.toml")})
	config.SetRuntimeLoader(func(string) (*config.AppConfig, error) {
		return &config.AppConfig{Agents: map[string]config.AgentConfig{"beta-vps-default": {AgentID: "beta-vps-default"}}}, nil
	})
	if err := auth.DefaultStore().AddUser("fixture", "fixture", "vendor_staff", "synthetic-password"); err != nil {
		t.Fatal(err)
	}
	u, _ := auth.DefaultStore().GetUser("fixture")
	cfg := &config.AppConfig{Agents: map[string]config.AgentConfig{"alpha-vps-runtime": {AgentID: "alpha-vps-runtime"}}}
	s, err := auth.DefaultSessionManager().Create(u, "192.0.2.1", "synthetic-client", cfg.Cards, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://example.com/monitor/?api=agent_overview", nil)
	h := &Handler{appCfg: cfg}
	if got := h.agentOverviewForRequest(r); len(got) != 0 {
		t.Fatal("unauthenticated overview returned rows")
	}
	r.AddCookie(&http.Cookie{Name: "heartdesk_session_v2", Value: s.ID})
	rows := h.agentOverviewForRequest(r)
	if len(rows) != 1 || rows[0].AgentID != "alpha-vps-runtime" {
		t.Fatalf("handler used default inventory: %#v", rows)
	}
}

func TestOverviewTemplatesDistinguishUnreportedFromFresh(t *testing.T) {
	funcs := template.FuncMap{}
	for _, name := range []string{"fval", "fpct", "barClass", "pctClass", "pctBarClass", "pctClassStr", "pctWidth", "pctWidthStr", "pctBarClassStr", "cardLabel"} {
		funcs[name] = func(...interface{}) string { return "" }
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(web.Templates(), "*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, received := range []string{"", time.Now().Format(time.RFC3339)} {
		item := AgentOverviewItem{AgentID: "alpha-vps-fixture", ReceivedAt: received, IsAlert: received == ""}
		for _, tc := range []struct {
			name string
			data interface{}
		}{
			{"layout", PageData{ServerTree: []AgentOverviewItem{item}}},
			{"card-sec-agent-status", []AgentLastSeen{{AgentID: item.AgentID, ReceivedAt: received, IsAlert: item.IsAlert}}},
			{"agents-overview", struct {
				Items                []AgentOverviewItem
				MonitorBase, AppName string
			}{Items: []AgentOverviewItem{item}}},
		} {
			var buf bytes.Buffer
			if err := tmpl.ExecuteTemplate(&buf, tc.name, tc.data); err != nil {
				t.Fatal(err)
			}
			got := buf.String()
			if received == "" && (!strings.Contains(got, "未報告") || strings.Contains(got, "0分前") || strings.Contains(got, "0 分前")) {
				t.Fatalf("%s claims unreported agent was fresh", tc.name)
			}
			if received != "" && !(strings.Contains(got, "0分前") || strings.Contains(got, "0 分前")) {
				t.Fatalf("%s omits genuine fresh age", tc.name)
			}
		}
	}
}
