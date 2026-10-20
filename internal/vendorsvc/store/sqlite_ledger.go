package store

import (
	"context"
	"database/sql"
	"fmt"
)

type sqliteLedgerStore struct{ db *sql.DB }

// NewLedgerStore は LedgerStore の SQLite 実装を返す。
func NewLedgerStore(db *sql.DB) LedgerStore {
	return &sqliteLedgerStore{db: db}
}

func (s *sqliteLedgerStore) AppendLedger(ctx context.Context, tenantID string, e LedgerEntry) error {
	// license_ledger.tenant_id は tenants(id) への FK を持ち、foreign_keys(ON) 下では
	// 親 tenants 行が無いと INSERT 自体が制約違反になる。新規プロビジョニング（発行→インストール→
	// 初回レポート）では発行時点で tenants 行がまだ無いのが正常順序のため、親行を
	// INSERT OR IGNORE で担保してから台帳行を挿入する（既定 type は ensureAgentReportTenant と同じ
	// monitor_owned）。tenantID 空（運営横断）は親担保しない。tx で原子的に行う。
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.AppendLedger begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := nowStoreTime()
	if tenantID != "" {
		const ensureTenant = `INSERT OR IGNORE INTO tenants (id, name, type, created_at, updated_at)
			VALUES (?, ?, 'monitor_owned', ?, ?)`
		if _, err := tx.ExecContext(ctx, ensureTenant, tenantID, tenantID, now, now); err != nil {
			return fmt.Errorf("store.AppendLedger ensure tenant: %w", err)
		}
	}

	const q = `INSERT INTO license_ledger
		(tenant_id, agent_id, action, kid, jti, key_prefix, actor, reason, vendor_secret_hash, issued_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if _, err := tx.ExecContext(ctx, q,
		tenantID, e.AgentID, e.Action,
		e.KID, e.JTI, e.KeyPrefix,
		e.Actor, e.Reason, e.VendorSecretHash, now,
	); err != nil {
		return fmt.Errorf("store.AppendLedger: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.AppendLedger commit: %w", err)
	}
	return nil
}

func (s *sqliteLedgerStore) ListLedger(ctx context.Context, tenantID string) ([]LedgerEntry, error) {
	const q = `SELECT id, tenant_id, agent_id, action, kid, jti, key_prefix, actor, reason, vendor_secret_hash, issued_at
		FROM license_ledger WHERE tenant_id = ? ORDER BY issued_at DESC`
	rows, err := s.db.QueryContext(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store.ListLedger: %w", err)
	}
	defer rows.Close()
	return scanLedgerEntries(rows)
}

func (s *sqliteLedgerStore) GetByJTI(ctx context.Context, tenantID, jti string) (*LedgerEntry, error) {
	const q = `SELECT id, tenant_id, agent_id, action, kid, jti, key_prefix, actor, reason, vendor_secret_hash, issued_at
		FROM license_ledger WHERE tenant_id = ? AND jti = ? LIMIT 1`
	row := s.db.QueryRowContext(ctx, q, tenantID, jti)
	return scanLedgerEntry(row)
}

func (s *sqliteLedgerStore) ListLedgerAcrossTenants(ctx context.Context) ([]LedgerEntry, error) {
	const q = `SELECT id, tenant_id, agent_id, action, kid, jti, key_prefix, actor, reason, vendor_secret_hash, issued_at
		FROM license_ledger ORDER BY issued_at DESC`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("store.ListLedgerAcrossTenants: %w", err)
	}
	defer rows.Close()
	return scanLedgerEntries(rows)
}

func (s *sqliteLedgerStore) RevokedJTIs(ctx context.Context) (map[string]bool, error) {
	const q = `SELECT jti FROM license_ledger WHERE action = 'revoke' AND jti IS NOT NULL`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("store.RevokedJTIs: %w", err)
	}
	defer rows.Close()
	out := make(map[string]bool)
	for rows.Next() {
		var jti string
		if err := rows.Scan(&jti); err != nil {
			return nil, fmt.Errorf("store.RevokedJTIs scan: %w", err)
		}
		out[jti] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.RevokedJTIs rows: %w", err)
	}
	return out, nil
}

// --- scan helpers ---

func scanLedgerEntry(row *sql.Row) (*LedgerEntry, error) {
	var e LedgerEntry
	var kid, jti, keyPrefix, actor, reason, vendorHash, issuedAt sql.NullString
	err := row.Scan(&e.ID, &e.TenantID, &e.AgentID, &e.Action,
		&kid, &jti, &keyPrefix, &actor, &reason, &vendorHash, &issuedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store.scanLedgerEntry: %w", err)
	}
	if kid.Valid {
		e.KID = &kid.String
	}
	if jti.Valid {
		e.JTI = &jti.String
	}
	if keyPrefix.Valid {
		e.KeyPrefix = &keyPrefix.String
	}
	if actor.Valid {
		e.Actor = &actor.String
	}
	if reason.Valid {
		e.Reason = &reason.String
	}
	if vendorHash.Valid {
		e.VendorSecretHash = &vendorHash.String
	}
	if issuedAt.Valid {
		e.IssuedAt = parseStoreTime(issuedAt.String)
		e.Timestamp = e.IssuedAt // 既存 vendorconsole.LedgerEntry 互換
	}
	return &e, nil
}

func scanLedgerEntries(rows *sql.Rows) ([]LedgerEntry, error) {
	var out []LedgerEntry
	for rows.Next() {
		var e LedgerEntry
		var kid, jti, keyPrefix, actor, reason, vendorHash, issuedAt sql.NullString
		if err := rows.Scan(&e.ID, &e.TenantID, &e.AgentID, &e.Action,
			&kid, &jti, &keyPrefix, &actor, &reason, &vendorHash, &issuedAt); err != nil {
			return nil, fmt.Errorf("store.scanLedgerEntries: %w", err)
		}
		if kid.Valid {
			e.KID = &kid.String
		}
		if jti.Valid {
			e.JTI = &jti.String
		}
		if keyPrefix.Valid {
			e.KeyPrefix = &keyPrefix.String
		}
		if actor.Valid {
			e.Actor = &actor.String
		}
		if reason.Valid {
			e.Reason = &reason.String
		}
		if vendorHash.Valid {
			e.VendorSecretHash = &vendorHash.String
		}
		if issuedAt.Valid {
			e.IssuedAt = parseStoreTime(issuedAt.String)
			e.Timestamp = e.IssuedAt // 既存 vendorconsole.LedgerEntry 互換
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.scanLedgerEntries rows: %w", err)
	}
	return out, nil
}
