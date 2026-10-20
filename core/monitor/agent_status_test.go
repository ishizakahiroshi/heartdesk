package monitor

import (
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

func TestGetAgentStatusForConfigFiltersUnmanagedAgents(t *testing.T) {
	agentLastSeenMu.Lock()
	original := agentLastSeen
	now := time.Now().Format(time.RFC3339)
	agentLastSeen = map[string]*AgentLastSeen{
		"alpha-vps-host1": {
			AgentID:    "alpha-vps-host1",
			AgentLabel: "host-1.example.com",
			AgentType:  "vps",
			ReceivedAt: now,
		},
		"beta-rental-host2": {
			AgentID:    "beta-rental-host2",
			AgentLabel: "host-2.example.com",
			AgentType:  "rental",
			ReceivedAt: now,
		},
	}
	agentLastSeenMu.Unlock()
	t.Cleanup(func() {
		agentLastSeenMu.Lock()
		agentLastSeen = original
		agentLastSeenMu.Unlock()
	})

	cfg := &config.AppConfig{
		Agents: map[string]config.AgentConfig{
			"alpha-vps-host1": {
				AgentID:    "alpha-vps-host1",
				AgentType:  "vps",
				AgentLabel: "host-1.example.com (VPS)",
			},
		},
	}

	rows := GetAgentStatusForConfig(cfg)
	if len(rows) != 1 {
		t.Fatalf("expected one managed agent, got %d: %#v", len(rows), rows)
	}
	if rows[0].AgentID != "alpha-vps-host1" {
		t.Fatalf("unexpected agent returned: %s", rows[0].AgentID)
	}
	if rows[0].AgentLabel != "host-1.example.com (VPS)" {
		t.Fatalf("expected config label to be applied, got %q", rows[0].AgentLabel)
	}
}
