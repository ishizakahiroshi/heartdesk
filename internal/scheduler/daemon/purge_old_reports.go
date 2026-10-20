package daemon

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc/store"
)

// PurgeOldReports は [vendor.retention] の設定に基づいて古いレポート・監査ログを削除する。
// cfg.VendorDBPath が空の場合は何もしない（Monitor 単体環境では Vendor DB なし）。
func PurgeOldReports(ctx context.Context, cfg *config.SchedulerConfig) error {
	if cfg == nil || cfg.VendorDBPath == "" {
		return nil
	}

	db, err := vendorsvc.OpenDB(cfg.VendorDBPath)
	if err != nil {
		return fmt.Errorf("purge_old_reports: open db: %w", err)
	}
	defer db.Close()

	rs := store.NewReportStore(db)
	as := store.NewAuditStore(db)
	ts := store.NewTenantStore(db)

	now := time.Now()
	rawBefore := now.AddDate(0, 0, -cfg.VendorRawReportDays)
	hourlyBefore := now.AddDate(0, 0, -cfg.VendorHourlySummaryDays)
	dailyBefore := now.AddDate(0, 0, -cfg.VendorDailySummaryDays)
	auditBefore := now.AddDate(0, 0, -cfg.VendorAuditLogDays)

	tenants, err := ts.ListAllTenants(ctx)
	if err != nil {
		return fmt.Errorf("purge_old_reports: list tenants: %w", err)
	}

	// 保持日数が 0 以下のテーブルは purge しない。
	// VendorRawReportDays 等は AuditAggregated.RetentionYears*365 から導出され、
	// RetentionYears は TOML 未指定時に Go ゼロ値 0 になる。その場合 before==now となり
	// 「now 以前の全行」を削除してしまう（全データ消失）。保持日数 0 は「未設定＝purge しない」と
	// 解釈し、兄弟処理 auditdb.Cleanup（years<=0 は no-op）と挙動を揃える。
	rawEnabled := cfg.VendorRawReportDays > 0
	hourlyEnabled := cfg.VendorHourlySummaryDays > 0
	dailyEnabled := cfg.VendorDailySummaryDays > 0
	auditEnabled := cfg.VendorAuditLogDays > 0
	if !rawEnabled && !hourlyEnabled && !dailyEnabled && !auditEnabled {
		log.Printf("[purge_old_reports] 保持日数が全て 0 以下のため purge をスキップ（retention 未設定の可能性）")
		return nil
	}

	var totalRaw, totalHourly, totalDaily, totalAudit int64

	for _, t := range tenants {
		if err := ctx.Err(); err != nil {
			return err
		}
		// soft delete 済みテナントもデータ保持期間中は purge 対象にする
		// （hard delete は purge_archived_tenants が担う）
		tenantID := t.ID

		if rawEnabled {
			n, err := rs.PurgeRawReportsOlderThan(ctx, tenantID, rawBefore)
			if err != nil {
				log.Printf("[purge_old_reports] WARN: tenant=%s PurgeRawReportsOlderThan: %v", tenantID, err)
			}
			totalRaw += n
		}

		if hourlyEnabled {
			n, err := rs.PurgeHourlyOlderThan(ctx, tenantID, hourlyBefore)
			if err != nil {
				log.Printf("[purge_old_reports] WARN: tenant=%s PurgeHourlyOlderThan: %v", tenantID, err)
			}
			totalHourly += n
		}

		if dailyEnabled {
			n, err := rs.PurgeDailyOlderThan(ctx, tenantID, dailyBefore)
			if err != nil {
				log.Printf("[purge_old_reports] WARN: tenant=%s PurgeDailyOlderThan: %v", tenantID, err)
			}
			totalDaily += n
		}

		if auditEnabled {
			n, err := as.PurgeOlderThan(ctx, tenantID, auditBefore)
			if err != nil {
				log.Printf("[purge_old_reports] WARN: tenant=%s PurgeOlderThan(audit): %v", tenantID, err)
			}
			totalAudit += n
		}
	}

	log.Printf("[purge_old_reports] 完了: raw=%d hourly=%d daily=%d audit=%d (tenants=%d)",
		totalRaw, totalHourly, totalDaily, totalAudit, len(tenants))
	return nil
}

// DryRunPurgeResult は --dry-run 時の削除対象件数集計。
type DryRunPurgeResult struct {
	RawCount    int64
	HourlyCount int64
	DailyCount  int64
	AuditCount  int64
	TenantCount int
}

// DryRunPurgeOldReports は --dry-run 時に削除対象件数を集計して返す（削除しない）。
func DryRunPurgeOldReports(ctx context.Context, cfg *config.SchedulerConfig) (*DryRunPurgeResult, error) {
	if cfg.VendorDBPath == "" {
		return nil, fmt.Errorf("vendor db_path が設定されていません")
	}

	db, err := vendorsvc.OpenDB(cfg.VendorDBPath)
	if err != nil {
		return nil, fmt.Errorf("dry-run purge_old_reports: open db: %w", err)
	}
	defer db.Close()

	ts := store.NewTenantStore(db)
	now := time.Now()
	rawBefore := now.AddDate(0, 0, -cfg.VendorRawReportDays)
	hourlyBefore := now.AddDate(0, 0, -cfg.VendorHourlySummaryDays)
	dailyBefore := now.AddDate(0, 0, -cfg.VendorDailySummaryDays)
	auditBefore := now.AddDate(0, 0, -cfg.VendorAuditLogDays)

	tenants, err := ts.ListAllTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("dry-run: list tenants: %w", err)
	}

	res := &DryRunPurgeResult{TenantCount: len(tenants)}

	// 実削除（PurgeOldReports）と同じく保持日数 0 以下のテーブルは集計対象外にする。
	rawEnabled := cfg.VendorRawReportDays > 0
	hourlyEnabled := cfg.VendorHourlySummaryDays > 0
	dailyEnabled := cfg.VendorDailySummaryDays > 0
	auditEnabled := cfg.VendorAuditLogDays > 0

	for _, t := range tenants {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tenantID := t.ID

		// dry-run はエラーを握りつぶさない（DB 破損時に「0 件」と誤報告しないため）。
		if rawEnabled {
			n, err := countOlderThan(ctx, db, "agent_reports_raw", "received_at", tenantID, rawBefore)
			if err != nil {
				return nil, fmt.Errorf("dry-run count raw tenant=%s: %w", tenantID, err)
			}
			res.RawCount += n
		}

		if hourlyEnabled {
			n, err := countOlderThan(ctx, db, "agent_reports_hourly", "hour_start", tenantID, hourlyBefore)
			if err != nil {
				return nil, fmt.Errorf("dry-run count hourly tenant=%s: %w", tenantID, err)
			}
			res.HourlyCount += n
		}

		if dailyEnabled {
			n, err := countOlderThan(ctx, db, "agent_reports_daily", "day", tenantID, dailyBefore)
			if err != nil {
				return nil, fmt.Errorf("dry-run count daily tenant=%s: %w", tenantID, err)
			}
			res.DailyCount += n
		}

		if auditEnabled {
			n, err := countOlderThan(ctx, db, "audit_log", "occurred_at", tenantID, auditBefore)
			if err != nil {
				return nil, fmt.Errorf("dry-run count audit tenant=%s: %w", tenantID, err)
			}
			res.AuditCount += n
		}
	}
	return res, nil
}

// purgeAllowedTargets は countOlderThan で許可するテーブル名 → 時刻カラム名のホワイトリスト。
// SQLite は識別子のプレースホルダ化ができないため、fmt.Sprintf で組む前に許可リスト検証する。
var purgeAllowedTargets = map[string]string{
	"agent_reports_raw":    "received_at",
	"agent_reports_hourly": "hour_start",
	"agent_reports_daily":  "day",
	"audit_log":            "occurred_at",
}

// countOlderThan は指定テーブル・テナントの削除対象件数を COUNT で取得する。
func countOlderThan(ctx context.Context, db *sql.DB, table, timeCol, tenantID string, before time.Time) (int64, error) {
	if want, ok := purgeAllowedTargets[table]; !ok || want != timeCol {
		return 0, fmt.Errorf("countOlderThan: disallowed table/column: %q/%q", table, timeCol)
	}
	// agent_reports_daily.day は日付のみ（"2006-01-02"）で格納され、実削除 PurgeDailyOlderThan も
	// 日付のみで比較する。dry-run も同形式に揃えないと、SQLite の文字列辞書比較で
	// "2026-06-14" < "2026-06-14T00:00:00Z"（接頭辞関係で常に真）となり境界当日を過大カウントする。
	beforeStr := before.UTC().Format("2006-01-02T15:04:05Z")
	if timeCol == "day" {
		beforeStr = before.UTC().Format("2006-01-02")
	}
	q := fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE tenant_id = ? AND %s < ?`, table, timeCol)
	var n int64
	if err := db.QueryRowContext(ctx, q, tenantID, beforeStr).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}
