package monitor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
)

func TestGetAgentOverviewForSession_TenantFilter(t *testing.T) {
	// BaseDir() は未設定だと log.Fatal でプロセスごと落ちる（パッケージ内の後続テストも道連れになる）。
	t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())

	agentLastSeenMu.Lock()
	origSeen := agentLastSeen
	origCols := agentLatestCollectors
	now := time.Now().Format(time.RFC3339)
	agentLastSeen = map[string]*AgentLastSeen{
		"alpha-vps-host1": {
			AgentID: "alpha-vps-host1", AgentLabel: "a", AgentType: "vps", ReceivedAt: now,
		},
		"beta-vps-host1": {
			AgentID: "beta-vps-host1", AgentLabel: "b", AgentType: "vps", ReceivedAt: now,
		},
	}
	agentLatestCollectors = map[string]map[string]json.RawMessage{}
	agentLastSeenMu.Unlock()
	t.Cleanup(func() {
		agentLastSeenMu.Lock()
		agentLastSeen = origSeen
		agentLatestCollectors = origCols
		agentLastSeenMu.Unlock()
	})

	tenant := GetAgentOverviewForSession("tenant_admin", "alpha")
	if len(tenant) != 1 || tenant[0].AgentID != "alpha-vps-host1" {
		t.Fatalf("tenant filter: got %#v", tenant)
	}

	vendor := GetAgentOverviewForSession("vendor_staff", "alpha")
	if len(vendor) < 2 {
		t.Fatalf("vendor should see all, got %d", len(vendor))
	}
}

func TestLoadCollectorRawPrefersMerged(t *testing.T) {
	agentLastSeenMu.Lock()
	origCols := agentLatestCollectors
	agentLatestCollectors = map[string]map[string]json.RawMessage{
		"alpha-vps-host1": {
			"system": json.RawMessage(`{"cpu":{"usage_percent":12}}`),
		},
	}
	agentLastSeenMu.Unlock()
	t.Cleanup(func() {
		agentLastSeenMu.Lock()
		agentLatestCollectors = origCols
		agentLastSeenMu.Unlock()
	})

	raw := loadCollectorRaw("alpha-vps-host1", "system")
	if raw == nil || !strings.Contains(string(raw), "usage_percent") {
		t.Fatalf("expected merged collector, got %s", string(raw))
	}
}

func TestResolveCardIDForAPI_NoSyntheticFailOpen(t *testing.T) {
	if _, ok := resolveCardIDForAPI("totally_unknown_api_xyz"); ok {
		t.Fatal("unknown api must not be mapped")
	}
	id, ok := resolveCardIDForAPI("user_mgmt_catalog")
	if !ok || id != navmeta.CardSecUserMgmt {
		t.Fatalf("user_mgmt_catalog map: id=%q ok=%v", id, ok)
	}
	id, ok = resolveCardIDForAPI("r2_metrics")
	if !ok || id != navmeta.CardSecR2 {
		t.Fatalf("r2_metrics map: id=%q ok=%v", id, ok)
	}
	_, ok = resolveCardIDForAPI("agent_overview")
	if !ok {
		t.Fatal("agent_overview should be explicitly mapped")
	}
}

func TestExportCardIDByKey_All(t *testing.T) {
	if id, ok := exportCardIDByKey[exportKeyAll]; !ok || id != "" {
		t.Fatalf("export all should be vendor-only empty card, got %q ok=%v", id, ok)
	}
}

func TestGetAgentStatusForConfig_UnreportedAndBadTime(t *testing.T) {
	agentLastSeenMu.Lock()
	orig := agentLastSeen
	agentLastSeen = map[string]*AgentLastSeen{
		"alpha-vps-host1": {
			AgentID: "alpha-vps-host1", AgentLabel: "a", AgentType: "vps", ReceivedAt: "not-a-time",
		},
	}
	agentLastSeenMu.Unlock()
	t.Cleanup(func() {
		agentLastSeenMu.Lock()
		agentLastSeen = orig
		agentLastSeenMu.Unlock()
	})

	cfg := &config.AppConfig{
		Agents: map[string]config.AgentConfig{
			"alpha-vps-host1": {AgentID: "alpha-vps-host1", AgentType: "vps"},
			"alpha-vps-other": {AgentID: "alpha-vps-other", AgentType: "vps", AgentLabel: "never"},
		},
	}
	rows := GetAgentStatusForConfig(cfg)
	if len(rows) != 2 {
		t.Fatalf("want 2 rows (seen+unreported), got %d %#v", len(rows), rows)
	}
	var bad, unreported *AgentLastSeen
	for i := range rows {
		switch rows[i].AgentID {
		case "alpha-vps-host1":
			bad = &rows[i]
		case "alpha-vps-other":
			unreported = &rows[i]
		}
	}
	if bad == nil || !bad.IsAlert {
		t.Fatalf("bad ReceivedAt should alert: %#v", bad)
	}
	if unreported == nil || !unreported.IsAlert {
		t.Fatalf("unreported should alert: %#v", unreported)
	}
}

func TestCsvSafeFormulaPrefix(t *testing.T) {
	if got := csvSafe("=cmd|'/c calc'!A0"); !strings.HasPrefix(got, "'") {
		t.Fatalf("csvSafe formula: %q", got)
	}
}

func TestLoadLatestAgentRecord_RejectsInvalidAgentID(t *testing.T) {
	if rec := loadLatestAgentRecord("../../etc/passwd"); rec != nil {
		t.Fatal("invalid agent must not load")
	}
	if rec := loadLatestAgentRecord("foo/../../../x"); rec != nil {
		t.Fatal("path-like agent must not load")
	}
}
