package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type sqliteSessionStore struct{ db *sql.DB }

// NewSessionStore は SessionStore の SQLite 実装を返す。
func NewSessionStore(db *sql.DB) SessionStore {
	return &sqliteSessionStore{db: db}
}

func (s *sqliteSessionStore) CreateSession(ctx context.Context, sess Session) error {
	const q = `INSERT INTO sessions (id, user_id, current_tenant_id, csrf_token, expires_at, created_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	expiresAt := sess.ExpiresAt.UTC().Format(storeTimeLayout)
	now := nowStoreTime()
	if _, err := s.db.ExecContext(ctx, q,
		sess.ID, sess.UserID, sess.CurrentTenantID, sess.CSRFToken, expiresAt, now, now,
	); err != nil {
		return fmt.Errorf("store.CreateSession: %w", err)
	}
	return nil
}

func (s *sqliteSessionStore) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	const q = `SELECT id, user_id, current_tenant_id, csrf_token, expires_at, created_at, last_seen_at
		FROM sessions WHERE id = ?`
	row := s.db.QueryRowContext(ctx, q, sessionID)
	return scanSession(row)
}

func (s *sqliteSessionStore) UpdateCurrentTenant(ctx context.Context, sessionID, tenantID string) error {
	const q = `UPDATE sessions SET current_tenant_id = ?, last_seen_at = ? WHERE id = ?`
	if _, err := s.db.ExecContext(ctx, q, tenantID, nowStoreTime(), sessionID); err != nil {
		return fmt.Errorf("store.UpdateCurrentTenant: %w", err)
	}
	return nil
}

func (s *sqliteSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	const q = `DELETE FROM sessions WHERE id = ?`
	if _, err := s.db.ExecContext(ctx, q, sessionID); err != nil {
		return fmt.Errorf("store.DeleteSession: %w", err)
	}
	return nil
}

func (s *sqliteSessionStore) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	const q = `DELETE FROM sessions WHERE expires_at < ?`
	nowStr := now.UTC().Format(storeTimeLayout)
	res, err := s.db.ExecContext(ctx, q, nowStr)
	if err != nil {
		return 0, fmt.Errorf("store.DeleteExpiredSessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// --- scan helper ---

func scanSession(row *sql.Row) (*Session, error) {
	var sess Session
	var currentTenantID sql.NullString
	var expiresAt, createdAt, lastSeenAt sql.NullString
	err := row.Scan(
		&sess.ID, &sess.UserID, &currentTenantID, &sess.CSRFToken,
		&expiresAt, &createdAt, &lastSeenAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store.scanSession: %w", err)
	}
	if currentTenantID.Valid {
		sess.CurrentTenantID = &currentTenantID.String
	}
	if expiresAt.Valid {
		sess.ExpiresAt = parseStoreTime(expiresAt.String)
	}
	if createdAt.Valid {
		sess.CreatedAt = parseStoreTime(createdAt.String)
	}
	if lastSeenAt.Valid {
		sess.LastSeenAt = parseStoreTime(lastSeenAt.String)
	}
	return &sess, nil
}
