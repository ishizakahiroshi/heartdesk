package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc/store"
)

// seedReport は一時 vendor DB を作り、tenant と 5 年前の raw report を 1 件投入してパスを返す。
func seedReport(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vendor.db")
	db, err := vendorsvc.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()
	if err := store.NewTenantStore(db).CreateTenant(ctx, store.Tenant{ID: "alpha", Name: "T1", Type: "monitor_owned"}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	old := time.Now().AddDate(-5, 0, 0)
	if err := store.NewReportStore(db).InsertRawReport(ctx, "alpha", store.RawReport{
		AgentID:        "alpha-vps-x",
		ReceivedAt:     old,
		ReportedAt:     old,
		CollectorsJSON: "{}",
	}); err != nil {
		t.Fatalf("InsertRawReport: %v", err)
	}
	return dbPath
}

func countReports(t *testing.T, dbPath string) int {
	t.Helper()
	ctx := context.Background()
	db, err := vendorsvc.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB(count): %v", err)
	}
	defer db.Close()
	rows, err := store.NewReportStore(db).ListRawReports(ctx, "alpha", "alpha-vps-x",
		time.Now().AddDate(-10, 0, 0), time.Now().Add(time.Hour), 100)
	if err != nil {
		t.Fatalf("ListRawReports: %v", err)
	}
	return len(rows)
}

// TestPurgeOldReports_ZeroRetentionDoesNotDeleteAll は、保持日数 0（RetentionYears 未設定相当）で
// before==now となり全行削除される回帰（データ全消失バグ）を防ぐ。
func TestPurgeOldReports_ZeroRetentionDoesNotDeleteAll(t *testing.T) {
	dbPath := seedReport(t)

	// 全 retention 0。purge は no-op であるべき。
	cfg := &config.SchedulerConfig{VendorDBPath: dbPath}
	if err := PurgeOldReports(context.Background(), cfg); err != nil {
		t.Fatalf("PurgeOldReports: %v", err)
	}

	if got := countReports(t, dbPath); got != 1 {
		t.Fatalf("zero-retention purge: rows = %d, want 1（データを削除してはならない）", got)
	}
}

// TestPurgeOldReports_PositiveRetentionDeletesOld は、保持日数 > 0 のとき古い行が正しく削除される
// （ガード追加で通常の purge が壊れていない）ことを確認する。
func TestPurgeOldReports_PositiveRetentionDeletesOld(t *testing.T) {
	dbPath := seedReport(t)

	cfg := &config.SchedulerConfig{
		VendorDBPath:            dbPath,
		VendorRawReportDays:     1,
		VendorHourlySummaryDays: 1,
		VendorDailySummaryDays:  1,
		VendorAuditLogDays:      1,
	}
	if err := PurgeOldReports(context.Background(), cfg); err != nil {
		t.Fatalf("PurgeOldReports: %v", err)
	}

	if got := countReports(t, dbPath); got != 0 {
		t.Fatalf("positive-retention purge: rows = %d, want 0（5年前の行は削除されるべき）", got)
	}
}
