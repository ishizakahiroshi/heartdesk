package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type sqliteAuditStore struct{ db *sql.DB }

// NewAuditStore は AuditStore の SQLite 実装を返す。
func NewAuditStore(db *sql.DB) AuditStore {
	return &sqliteAuditStore{db: db}
}

func (s *sqliteAuditStore) AppendAudit(ctx context.Context, tenantID string, e AuditEntry) error {
	const q = `INSERT INTO audit_log (tenant_id, user_id, event_type, ip_address, occurred_at, details_json)
		VALUES (?, ?, ?, ?, ?, ?)`
	var tid *string
	if tenantID != "" {
		tid = &tenantID
	}
	// 発生時刻は e.OccurredAt を優先し、未設定（zero）のときのみ現在時刻にフォールバックする。
	// 集約系（agent 報告の取り込み）で本来の発生時刻が失われないようにする。
	occurred := e.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now()
	}
	occurredStr := occurred.UTC().Format("2006-01-02T15:04:05Z")
	if _, err := s.db.ExecContext(ctx, q, tid, e.UserID, e.EventType, e.IPAddress, occurredStr, e.DetailsJSON); err != nil {
		return fmt.Errorf("store.AppendAudit: %w", err)
	}
	return nil
}

func (s *sqliteAuditStore) ListAudit(ctx context.Context, tenantID string, from, to time.Time, limit int) ([]AuditEntry, error) {
	const q = `SELECT id, tenant_id, user_id, event_type, ip_address, occurred_at, details_json
		FROM audit_log
		WHERE tenant_id = ? AND occurred_at >= ? AND occurred_at <= ?
		ORDER BY occurred_at DESC LIMIT ?`
	fromStr := from.UTC().Format("2006-01-02T15:04:05Z")
	toStr := to.UTC().Format("2006-01-02T15:04:05Z")
	rows, err := s.db.QueryContext(ctx, q, tenantID, fromStr, toStr, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListAudit: %w", err)
	}
	defer rows.Close()
	return scanAuditEntries(rows)
}

func (s *sqliteAuditStore) PurgeOlderThan(ctx context.Context, tenantID string, before time.Time) (int64, error) {
	const q = `DELETE FROM audit_log WHERE tenant_id = ? AND occurred_at < ?`
	beforeStr := before.UTC().Format("2006-01-02T15:04:05Z")
	res, err := s.db.ExecContext(ctx, q, tenantID, beforeStr)
	if err != nil {
		return 0, fmt.Errorf("store.PurgeOlderThan: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (s *sqliteAuditStore) ListAuditAcrossTenants(ctx context.Context, from, to time.Time, limit int) ([]AuditEntry, error) {
	const q = `SELECT id, tenant_id, user_id, event_type, ip_address, occurred_at, details_json
		FROM audit_log
		WHERE occurred_at >= ? AND occurred_at <= ?
		ORDER BY occurred_at DESC LIMIT ?`
	fromStr := from.UTC().Format("2006-01-02T15:04:05Z")
	toStr := to.UTC().Format("2006-01-02T15:04:05Z")
	rows, err := s.db.QueryContext(ctx, q, fromStr, toStr, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListAuditAcrossTenants: %w", err)
	}
	defer rows.Close()
	return scanAuditEntries(rows)
}

// --- scan helper ---

func scanAuditEntries(rows *sql.Rows) ([]AuditEntry, error) {
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var tid, ip, details, occurred sql.NullString
		var uid sql.NullInt64
		if err := rows.Scan(&e.ID, &tid, &uid, &e.EventType, &ip, &occurred, &details); err != nil {
			return nil, fmt.Errorf("store.scanAuditEntries: %w", err)
		}
		if tid.Valid {
			e.TenantID = &tid.String
		}
		if uid.Valid {
			e.UserID = &uid.Int64
		}
		if ip.Valid {
			e.IPAddress = &ip.String
		}
		if details.Valid {
			e.DetailsJSON = &details.String
		}
		if occurred.Valid {
			e.OccurredAt = parseStoreTime(occurred.String)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.scanAuditEntries rows: %w", err)
	}
	return out, nil
}
