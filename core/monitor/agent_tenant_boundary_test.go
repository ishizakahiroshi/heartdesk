package monitor

import (
	"testing"
)

// TestCheckAgentTenantBoundary は ?agent=<agent_id> の
// tenant 越境防止を確認する。
//
// 集約 Monitor では agentID 先頭の tenant prefix とセッションテナントが
// 一致しない限り読み書きを拒否する（vendor_staff は bypass）。
func TestCheckAgentTenantBoundary(t *testing.T) {
	tests := []struct {
		name         string
		role         string
		sessTenantID string
		agentID      string
		want         bool
	}{
		{
			name:         "empty agent is local monitor: allow",
			role:         "tenant_admin",
			sessTenantID: "alpha",
			agentID:      "",
			want:         true,
		},
		{
			name:         "tenant_admin same tenant: allow",
			role:         "tenant_admin",
			sessTenantID: "alpha",
			agentID:      "alpha-vps-host1",
			want:         true,
		},
		{
			name:         "tenant_user same tenant: allow",
			role:         "tenant_user",
			sessTenantID: "alpha",
			agentID:      "alpha-vps-host2",
			want:         true,
		},
		{
			name:         "tenant_admin cross tenant (alpha -> beta): deny",
			role:         "tenant_admin",
			sessTenantID: "alpha",
			agentID:      "beta-vps-host1",
			want:         false,
		},
		{
			name:         "tenant_admin cross tenant (beta -> gamma): deny",
			role:         "tenant_admin",
			sessTenantID: "beta",
			agentID:      "gamma-vps-host1",
			want:         false,
		},
		{
			name:         "vendor_staff cross tenant: allow (bypass)",
			role:         "vendor_staff",
			sessTenantID: "beta",
			agentID:      "alpha-vps-host1",
			want:         true,
		},
		{
			name:         "vendor_staff with empty tenant: allow (bypass)",
			role:         "vendor_staff",
			sessTenantID: "",
			agentID:      "beta-vps-host1",
			want:         true,
		},
		{
			name:         "tenant_admin with empty sess tenant: deny (fail-closed)",
			role:         "tenant_admin",
			sessTenantID: "",
			agentID:      "alpha-vps-host1",
			want:         false,
		},
		{
			name:         "invalid agentID format: deny",
			role:         "tenant_admin",
			sessTenantID: "alpha",
			agentID:      "../../etc/passwd",
			want:         false,
		},
		{
			name:         "glob-meta agentID: deny",
			role:         "tenant_admin",
			sessTenantID: "alpha",
			agentID:      "*",
			want:         false,
		},
		{
			name:         "unknown role same tenant: deny (vendor_staff bypass only)",
			role:         "ghost_role",
			sessTenantID: "alpha",
			agentID:      "alpha-vps-host1",
			// role が空文字に正規化されるが sessTenantID/agentTenant 一致で許可。
			// 越境ではないため拒否する理由がない。
			want: true,
		},
		{
			name:         "unknown role cross tenant: deny",
			role:         "ghost_role",
			sessTenantID: "alpha",
			agentID:      "beta-vps-host1",
			want:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkAgentTenantBoundary(tt.role, tt.sessTenantID, tt.agentID)
			if got != tt.want {
				t.Fatalf("checkAgentTenantBoundary(role=%q, sessTenant=%q, agent=%q) = %v, want %v",
					tt.role, tt.sessTenantID, tt.agentID, got, tt.want)
			}
		})
	}
}
