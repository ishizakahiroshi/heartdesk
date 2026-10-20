package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type sqliteReportStore struct{ db *sql.DB }

// NewReportStore は ReportStore の SQLite 実装を返す。
func NewReportStore(db *sql.DB) ReportStore {
	return &sqliteReportStore{db: db}
}

func (s *sqliteReportStore) InsertRawReport(ctx context.Context, tenantID string, r RawReport) error {
	const q = `INSERT INTO agent_reports_raw (tenant_id, agent_id, received_at, reported_at, collectors_json)
		VALUES (?, ?, ?, ?, ?)`
	recv := r.ReceivedAt.UTC().Format("2006-01-02T15:04:05Z")
	rep := r.ReportedAt.UTC().Format("2006-01-02T15:04:05Z")
	if _, err := s.db.ExecContext(ctx, q, tenantID, r.AgentID, recv, rep, r.CollectorsJSON); err != nil {
		return fmt.Errorf("store.InsertRawReport: %w", err)
	}
	return nil
}

func (s *sqliteReportStore) ListRawReports(ctx context.Context, tenantID, agentID string, from, to time.Time, limit int) ([]RawReport, error) {
	const q = `SELECT id, tenant_id, agent_id, received_at, reported_at, collectors_json
		FROM agent_reports_raw
		WHERE tenant_id = ? AND agent_id = ? AND received_at >= ? AND received_at <= ?
		ORDER BY received_at DESC LIMIT ?`
	fromStr := from.UTC().Format("2006-01-02T15:04:05Z")
	toStr := to.UTC().Format("2006-01-02T15:04:05Z")
	rows, err := s.db.QueryContext(ctx, q, tenantID, agentID, fromStr, toStr, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListRawReports: %w", err)
	}
	defer rows.Close()
	return scanRawReports(rows)
}

func (s *sqliteReportStore) PurgeRawReportsOlderThan(ctx context.Context, tenantID string, before time.Time) (int64, error) {
	const q = `DELETE FROM agent_reports_raw WHERE tenant_id = ? AND received_at < ?`
	beforeStr := before.UTC().Format("2006-01-02T15:04:05Z")
	res, err := s.db.ExecContext(ctx, q, tenantID, beforeStr)
	if err != nil {
		return 0, fmt.Errorf("store.PurgeRawReportsOlderThan: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (s *sqliteReportStore) UpsertHourlySummary(ctx context.Context, tenantID string, sum HourlySummary) error {
	const q = `INSERT INTO agent_reports_hourly
		(tenant_id, agent_id, hour_start, cpu_avg, cpu_max, mem_avg, mem_max, disk_pct_max, ban_active_max, sample_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id, agent_id, hour_start) DO UPDATE SET
			cpu_avg        = excluded.cpu_avg,
			cpu_max        = excluded.cpu_max,
			mem_avg        = excluded.mem_avg,
			mem_max        = excluded.mem_max,
			disk_pct_max   = excluded.disk_pct_max,
			ban_active_max = excluded.ban_active_max,
			sample_count   = excluded.sample_count`
	hourStr := sum.HourStart.UTC().Format("2006-01-02T15:04:05Z")
	_, err := s.db.ExecContext(ctx, q, tenantID, sum.AgentID, hourStr,
		sum.CPUAvg, sum.CPUMax, sum.MemAvg, sum.MemMax, sum.DiskPctMax, sum.BanActiveMax, sum.SampleCount)
	if err != nil {
		return fmt.Errorf("store.UpsertHourlySummary: %w", err)
	}
	return nil
}

func (s *sqliteReportStore) UpsertDailySummary(ctx context.Context, tenantID string, sum DailySummary) error {
	const q = `INSERT INTO agent_reports_daily
		(tenant_id, agent_id, day, cpu_avg, cpu_max, mem_avg, mem_max, disk_pct_max, ban_active_max, sample_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id, agent_id, day) DO UPDATE SET
			cpu_avg        = excluded.cpu_avg,
			cpu_max        = excluded.cpu_max,
			mem_avg        = excluded.mem_avg,
			mem_max        = excluded.mem_max,
			disk_pct_max   = excluded.disk_pct_max,
			ban_active_max = excluded.ban_active_max,
			sample_count   = excluded.sample_count`
	_, err := s.db.ExecContext(ctx, q, tenantID, sum.AgentID, sum.Day,
		sum.CPUAvg, sum.CPUMax, sum.MemAvg, sum.MemMax, sum.DiskPctMax, sum.BanActiveMax, sum.SampleCount)
	if err != nil {
		return fmt.Errorf("store.UpsertDailySummary: %w", err)
	}
	return nil
}

func (s *sqliteReportStore) PurgeHourlyOlderThan(ctx context.Context, tenantID string, before time.Time) (int64, error) {
	const q = `DELETE FROM agent_reports_hourly WHERE tenant_id = ? AND hour_start < ?`
	beforeStr := before.UTC().Format("2006-01-02T15:04:05Z")
	res, err := s.db.ExecContext(ctx, q, tenantID, beforeStr)
	if err != nil {
		return 0, fmt.Errorf("store.PurgeHourlyOlderThan: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (s *sqliteReportStore) PurgeDailyOlderThan(ctx context.Context, tenantID string, before time.Time) (int64, error) {
	const q = `DELETE FROM agent_reports_daily WHERE tenant_id = ? AND day < ?`
	beforeStr := before.UTC().Format("2006-01-02")
	res, err := s.db.ExecContext(ctx, q, tenantID, beforeStr)
	if err != nil {
		return 0, fmt.Errorf("store.PurgeDailyOlderThan: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (s *sqliteReportStore) ListLatestReportsAcrossTenants(ctx context.Context, limit int) ([]RawReport, error) {
	const q = `SELECT id, tenant_id, agent_id, received_at, reported_at, collectors_json
		FROM agent_reports_raw ORDER BY received_at DESC LIMIT ?`
	rows, err := s.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListLatestReportsAcrossTenants: %w", err)
	}
	defer rows.Close()
	return scanRawReports(rows)
}

// --- scan helper ---

func scanRawReports(rows *sql.Rows) ([]RawReport, error) {
	var out []RawReport
	for rows.Next() {
		var r RawReport
		var recv, rep sql.NullString
		if err := rows.Scan(&r.ID, &r.TenantID, &r.AgentID, &recv, &rep, &r.CollectorsJSON); err != nil {
			return nil, fmt.Errorf("store.scanRawReports: %w", err)
		}
		if recv.Valid {
			r.ReceivedAt = parseStoreTime(recv.String)
		}
		if rep.Valid {
			r.ReportedAt = parseStoreTime(rep.String)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.scanRawReports rows: %w", err)
	}
	return out, nil
}
