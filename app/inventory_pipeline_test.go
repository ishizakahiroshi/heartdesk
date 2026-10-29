package app_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/app"
	"github.com/ishizakahiroshi/heartdesk/internal/alerts"
	"github.com/ishizakahiroshi/heartpost/agentsig"
)

type pipelineNotifier struct {
	url    string
	client *http.Client
}

func (*pipelineNotifier) Prepare(*app.Config) {}
func (n *pipelineNotifier) Notify(_ string, message string) app.DeliveryResult {
	resp, err := n.client.Post(n.url, "text/plain", strings.NewReader(message))
	if err != nil {
		return app.DeliveryResult{Attempted: true}
	}
	defer resp.Body.Close()
	return app.DeliveryResult{Attempted: true, Delivered: resp.StatusCode == 200}
}

func TestInventoryProducerToDurableConsumer(t *testing.T) {
	fixture := os.Getenv("HEARTDESK_INVENTORY_WIRE_FIXTURE")
	if fixture == "" {
		t.Skip("requires freshly exported synthetic heartpost wire fixture")
	}
	if os.Getenv("HEARTDESK_PIPELINE_CHILD") != "1" {
		root := t.TempDir()
		for _, phase := range []string{"ingest", "restart"} {
			cmd := exec.Command(os.Args[0], "-test.run=^TestInventoryProducerToDurableConsumer$", "-test.timeout=90s")
			cmd.Env = append(os.Environ(), "HEARTDESK_PIPELINE_CHILD=1", "HEARTDESK_PIPELINE_ROOT="+root, "HEARTDESK_PIPELINE_PHASE="+phase)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("phase=%s %v\n%s", phase, err, out)
			}
		}
		return
	}
	phase := os.Getenv("HEARTDESK_PIPELINE_PHASE")
	root := os.Getenv("HEARTDESK_PIPELINE_ROOT")
	opts := testOptions(t)
	opts.BaseDir = root
	strict := false
	opts.Config.AgentReport.StrictLicense = &strict
	opts.Config.AgentKeys = map[string]string{"alpha-vps-example": "synthetic-pipeline-key"}
	opts.Config.AgentAllowedIPs = map[string][]string{"alpha-vps-example": {"192.0.2.1"}}
	opts.Config.Agents = map[string]app.AgentConfig{"alpha-vps-example": {AgentType: "vps"}}
	var calls atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if phase == "ingest" && calls.Add(1) == 1 {
			w.WriteHeader(503)
		} else {
			if phase != "ingest" {
				calls.Add(1)
			}
			w.WriteHeader(200)
		}
	}))
	defer receiver.Close()
	opts.Notifiers = []app.Notifier{&pipelineNotifier{url: receiver.URL, client: receiver.Client()}}
	rt, err := app.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if err := rt.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	rulesDir := filepath.Join(root, "data", "json")
	if err := os.MkdirAll(rulesDir, 0700); err != nil {
		t.Fatal(err)
	}
	rulesFile := filepath.Join(rulesDir, "alert_rules.json")
	if err := os.WriteFile(rulesFile, []byte(`{"rules":{"inventory_changed":{"enabled":true}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if phase == "ingest" {
		raw, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatal(err)
		}
		var bodies []json.RawMessage
		if json.Unmarshal(raw, &bodies) != nil || len(bodies) != 2 {
			t.Fatal("invalid producer fixture")
		}
		for _, body := range bodies {
			r := httptest.NewRequest("POST", "http://example.com/api/agent/report", strings.NewReader(string(body)))
			r.RemoteAddr = "192.0.2.1:1"
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			r.Header.Set("X-Agent-Id", "alpha-vps-example")
			r.Header.Set("X-Agent-Timestamp", ts)
			r.Header.Set("X-Agent-Signature", agentsig.Compute("synthetic-pipeline-key", ts, body))
			w := httptest.NewRecorder()
			rt.Handler().ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("producer report rejected: %d", w.Code)
			}
		}
	}
	if phase == "ingest" {
		if fired, err := alerts.Run(rt.Config()); err != nil || len(fired) != 0 {
			t.Fatal("503 should remain pending", err)
		}
	}
	fired, err := alerts.Run(rt.Config())
	if err != nil {
		t.Fatal(err)
	}
	if phase == "ingest" && (len(fired) != 1 || calls.Load() != 2) {
		t.Fatalf("expected one retry delivery, got events=%d calls=%d", len(fired), calls.Load())
	}
	if phase == "restart" && (len(fired) != 0 || calls.Load() != 0) {
		t.Fatal("process restart delivered duplicate")
	}
	if err := app.DefaultStore().AddUser("pipeline-reader", "Synthetic reader", "tenant_user", "synthetic-password"); err != nil && phase != "restart" {
		t.Fatal(err)
	}
	u, exists := app.DefaultStore().GetUser("pipeline-reader")
	if !exists {
		t.Fatal("reader missing")
	}
	u.AccessScreens = []string{"monitor"}
	session, err := app.DefaultSessionManager().Create(u, "192.0.2.1", "synthetic-client", rt.Config().Cards, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://example.com/monitor/?api=inventory&agent=alpha-vps-example", nil)
	r.RemoteAddr = "192.0.2.1:1"
	r.Header.Set("User-Agent", "synthetic-client")
	r.AddCookie(&http.Cookie{Name: "example_session", Value: session.ID})
	w := httptest.NewRecorder()
	rt.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("inventory API: %d", w.Code)
	}
	var view struct {
		Changes  []struct{ Before, After string }
		Sections []struct {
			Key   string
			Items map[string]string
		}
	}
	if json.Unmarshal(w.Body.Bytes(), &view) != nil || len(view.Changes) != 1 || view.Changes[0].Before != "1.0" || view.Changes[0].After != "2.0" {
		t.Fatal("producer difference did not survive storage/API/restart")
	}
	for _, section := range view.Sections {
		if section.Key == "packages" && section.Items["sample:amd64"] != "2.0" {
			t.Fatal("wrong package observation")
		}
	}
}
