package monitor

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// 設定の agent_type と報告の agent_type が食い違うとき、設定が勝つこと
// （無報告アラートの閾値・表示する種類）を確かめる。
func TestAgentStatusConfigTypeWinsOverReportedType(t *testing.T) {
	received := time.Now().Add(-3 * time.Minute).Format(time.RFC3339)

	cfg := &config.AppConfig{
		Agents: map[string]config.AgentConfig{
			"alpha-a": {AgentID: "alpha-a", AgentType: "rental"}, // 報告は vps
			"alpha-b": {AgentID: "alpha-b", AgentType: "vps"},    // 報告は rental
			"alpha-c": {AgentID: "alpha-c", AgentType: "rental"}, // 報告に種類なし
			"alpha-d": {AgentID: "alpha-d", AgentType: ""},       // 設定に種類なし・報告は " Rental "
			"alpha-e": {AgentID: "alpha-e", AgentType: "vps"},    // 報告は未知の値
		},
	}
	cfg.AgentHealth.RentalAlertMin = 2 // rental は 2 分で警告
	cfg.AgentHealth.VPSAlertMin = 10   // vps は 10 分で警告

	cases := []struct {
		id        string
		reported  string
		wantType  string
		wantAlert bool
	}{
		{"alpha-a", "vps", "rental", true},
		{"alpha-b", "rental", "vps", false},
		{"alpha-c", "", "rental", true},
		{"alpha-d", " Rental ", "rental", true},
		{"alpha-e", "bogus", "vps", false},
	}

	agentLastSeenMu.Lock()
	original := agentLastSeen
	agentLastSeen = map[string]*AgentLastSeen{}
	for _, c := range cases {
		agentLastSeen[c.id] = &AgentLastSeen{AgentID: c.id, AgentType: c.reported, ReceivedAt: received}
	}
	agentLastSeenMu.Unlock()
	t.Cleanup(func() {
		agentLastSeenMu.Lock()
		agentLastSeen = original
		agentLastSeenMu.Unlock()
	})

	byID := map[string]AgentLastSeen{}
	for _, row := range GetAgentStatusForConfig(cfg) {
		byID[row.AgentID] = row
	}
	for _, c := range cases {
		row, ok := byID[c.id]
		if !ok {
			t.Fatalf("%s: row missing", c.id)
		}
		if row.AgentType != c.wantType {
			t.Errorf("%s: agent_type = %q, want %q (reported %q)", c.id, row.AgentType, c.wantType, c.reported)
		}
		if row.IsAlert != c.wantAlert {
			t.Errorf("%s: is_alert = %v, want %v (reported %q)", c.id, row.IsAlert, c.wantAlert, c.reported)
		}
	}
}

// 種類を持たない報告で、受信済みの種類を消さないこと。
func TestUpdateAgentLastSeenKeepsTypeWhenReportHasNone(t *testing.T) {
	agentLastSeenMu.Lock()
	original := agentLastSeen
	originalCollectors := agentLatestCollectors
	agentLastSeen = map[string]*AgentLastSeen{}
	agentLatestCollectors = map[string]map[string]json.RawMessage{}
	agentLastSeenMu.Unlock()
	t.Cleanup(func() {
		agentLastSeenMu.Lock()
		agentLastSeen = original
		agentLatestCollectors = originalCollectors
		agentLastSeenMu.Unlock()
	})

	now := time.Now().Format(time.RFC3339)
	updateAgentLastSeenFields("alpha-a", "label", "rental", now, nil)
	updateAgentLastSeenFields("alpha-a", "label", "", now, nil)
	if got := GetAgentLastSeenByID("alpha-a").AgentType; got != "rental" {
		t.Fatalf("agent_type after typeless report = %q, want %q", got, "rental")
	}
	updateAgentLastSeenFields("alpha-a", "label", "vps", now, nil)
	if got := GetAgentLastSeenByID("alpha-a").AgentType; got != "vps" {
		t.Fatalf("agent_type after report with vps = %q, want %q", got, "vps")
	}
}
