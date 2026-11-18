package monitor

import (
	"fmt"
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
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
)

func TestStorageForecastUsesLocalAgentReports(t *testing.T) {
	if os.Getenv("HEARTDESK_TEST_LOCAL_FORECAST") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestStorageForecastUsesLocalAgentReports$", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), "HEARTDESK_TEST_LOCAL_FORECAST=1")
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
	})
	dir := filepath.Join(root, "data", "json", "agent_reports")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	record := func(ts time.Time) string {
		return fmt.Sprintf(`{"reported_at":%q,"collectors":{"system":{"disk":[{"mount_point":"/","usage_percent":25}]}}}`+"\n", ts.Format(time.RFC3339))
	}
	if err := os.WriteFile(filepath.Join(dir, "report_alpha-vps-local_202611.jsonl"), []byte(record(time.Now().Add(-time.Minute))+record(time.Now())), 0600); err != nil {
		t.Fatal(err)
	}
	if err := auth.DefaultStore().AddUser("reader", "Synthetic reader", "tenant_user", "synthetic-password"); err != nil {
		t.Fatal(err)
	}
	u, ok := auth.DefaultStore().GetUser("reader")
	if !ok {
		t.Fatal("missing user")
	}
	u.AccessScreens = []string{"monitor"}
	s, err := auth.DefaultSessionManager().Create(u, "192.0.2.1", "synthetic-client", config.CardsConfig{DefaultMode: "full"}, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	defer auth.DefaultSessionManager().Delete(s.ID)
	cfg := &config.AppConfig{Agents: map[string]config.AgentConfig{"alpha-vps-local": {AgentID: "alpha-vps-local", IsPrimary: true}}}
	tmpl := template.Must(template.New("test").Parse(`{{define "card-sec-storage-forecast"}}{{if .HasData}}ready {{.Samples}}{{else}}empty{{end}}{{end}}`))
	h := NewHandler(tmpl, routing.Current(), config.SystemInfoData{}, cfg)
	meta, ok := navmeta.MonitorCardByAPIKey("storage_forecast")
	if !ok {
		t.Fatal("forecast card missing")
	}
	cards := buildServerDetailCards(h, []navmeta.MonitorCardMeta{meta}, nil, "", "alpha-vps-local")
	if got := string(cards[meta.ID]); got != "ready 2" {
		t.Fatalf("initial card = %q", got)
	}
	r := httptest.NewRequest(http.MethodGet, "http://example.com/card?card=storage_forecast&agent=alpha-vps-local", nil)
	r.RemoteAddr = "192.0.2.1:1"
	r.Header.Set("User-Agent", "synthetic-client")
	r.AddCookie(&http.Cookie{Name: "heartdesk_session_v2", Value: s.ID})
	w := httptest.NewRecorder()
	h.APICard(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "ready 2") {
		t.Fatalf("refreshed card: status=%d body=%q", w.Code, w.Body.String())
	}
}
