package monitor

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc/store"
)

func TestAgentRetentionKeepsCutoffMonth(t *testing.T) {
	zone := time.FixedZone("fixture", 9*60*60)
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, zone)
	want := time.Date(2026, 7, 1, 0, 0, 0, 0, zone)
	if got := agentRetentionBoundary(now, 3); !got.Equal(want) {
		t.Fatalf("boundary=%s want=%s", got, want)
	}
}

func TestReportDoesNotReactivateArchivedTenant(t *testing.T) {
	db, err := vendorsvc.OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tenants := store.NewTenantStore(db)
	ctx := context.Background()
	if err := tenants.CreateTenant(ctx, store.Tenant{ID: "alpha", Name: "fixture", Type: "monitor_owned"}); err != nil {
		t.Fatal(err)
	}
	if err := tenants.SoftDeleteTenant(ctx, "alpha", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := ensureAgentReportTenant(ctx, tenants, "alpha"); err == nil {
		t.Fatal("archived tenant accepted a new report")
	}
}
