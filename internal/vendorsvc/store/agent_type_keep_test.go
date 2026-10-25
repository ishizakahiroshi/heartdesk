package store_test

import (
	"context"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc/store"
)

// Older reports may omit the agent type. Such a report must preserve the
// recorded type, while a later explicit type must still replace it.
func TestUpsertAgentKeepsTypeWhenReportHasNone(t *testing.T) {
	ctx := context.Background()
	s := openTestDB(t)
	if err := s.Tenant.CreateTenant(ctx, store.Tenant{ID: "alpha", Name: "Synthetic", Type: "monitor_owned"}); err != nil {
		t.Fatal(err)
	}
	agent := store.Agent{TenantID: "alpha", AgentID: "alpha-host-1", AgentLabel: "host-1"}
	for _, step := range []struct{ report, want string }{
		{"rental", "rental"}, {"", "rental"}, {"vps", "vps"}, {"", "vps"},
	} {
		agent.AgentType = step.report
		if err := s.Agent.UpsertAgent(ctx, "alpha", agent); err != nil {
			t.Fatal(err)
		}
		got, err := s.Agent.GetAgentByID(ctx, "alpha", agent.AgentID)
		if err != nil || got == nil {
			t.Fatalf("stored agent unavailable: %v", err)
		}
		if got.AgentType != step.want {
			t.Fatalf("report type=%q stored type=%q, want%q", step.report, got.AgentType, step.want)
		}
	}
}
