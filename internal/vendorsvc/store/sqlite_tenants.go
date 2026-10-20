package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type sqliteTenantStore struct{ db *sql.DB }

// NewTenantStore は TenantStore の SQLite 実装を返す。
func NewTenantStore(db *sql.DB) TenantStore {
	return &sqliteTenantStore{db: db}
}

func (s *sqliteTenantStore) CreateTenant(ctx context.Context, t Tenant) error {
	const q = `INSERT INTO tenants (id, name, type, vendor_relay_enabled, deleted_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	relayInt := 0
	if t.VendorRelayEnabled {
		relayInt = 1
	}
	var deletedAt *string
	if t.DeletedAt != nil {
		s := t.DeletedAt.UTC().Format(storeTimeLayout)
		deletedAt = &s
	}
	now := nowStoreTime()
	if _, err := s.db.ExecContext(ctx, q, t.ID, t.Name, t.Type, relayInt, deletedAt, now, now); err != nil {
		return fmt.Errorf("store.CreateTenant: %w", err)
	}
	return nil
}

func (s *sqliteTenantStore) GetTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	const q = `SELECT id, name, type, vendor_relay_enabled, deleted_at, created_at, updated_at
		FROM tenants WHERE id = ?`
	row := s.db.QueryRowContext(ctx, q, tenantID)
	return scanTenant(row)
}

func (s *sqliteTenantStore) UpdateTenant(ctx context.Context, tenantID string, patch TenantPatch) error {
	// 動的 SET 句（nil フィールドは更新しない）
	sets := []string{"updated_at = ?"}
	args := []any{nowStoreTime()}

	if patch.Name != nil {
		sets = append(sets, "name = ?")
		args = append(args, *patch.Name)
	}
	if patch.Type != nil {
		sets = append(sets, "type = ?")
		args = append(args, *patch.Type)
	}
	if patch.VendorRelayEnabled != nil {
		v := 0
		if *patch.VendorRelayEnabled {
			v = 1
		}
		sets = append(sets, "vendor_relay_enabled = ?")
		args = append(args, v)
	}
	args = append(args, tenantID)

	q := "UPDATE tenants SET "
	for i, set := range sets {
		if i > 0 {
			q += ", "
		}
		q += set
	}
	q += " WHERE id = ?"

	if _, err := s.db.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("store.UpdateTenant: %w", err)
	}
	return nil
}

func (s *sqliteTenantStore) SoftDeleteTenant(ctx context.Context, tenantID string, at time.Time) error {
	const q = `UPDATE tenants SET deleted_at = ?, updated_at = ? WHERE id = ?`
	deletedAt := at.UTC().Format(storeTimeLayout)
	if _, err := s.db.ExecContext(ctx, q, deletedAt, nowStoreTime(), tenantID); err != nil {
		return fmt.Errorf("store.SoftDeleteTenant: %w", err)
	}
	return nil
}

func (s *sqliteTenantStore) HardDeleteTenant(ctx context.Context, tenantID string) error {
	const q = `DELETE FROM tenants WHERE id = ?`
	if _, err := s.db.ExecContext(ctx, q, tenantID); err != nil {
		return fmt.Errorf("store.HardDeleteTenant: %w", err)
	}
	return nil
}

func (s *sqliteTenantStore) ListAllTenants(ctx context.Context) ([]Tenant, error) {
	const q = `SELECT id, name, type, vendor_relay_enabled, deleted_at, created_at, updated_at
		FROM tenants ORDER BY id`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("store.ListAllTenants: %w", err)
	}
	defer rows.Close()
	return scanTenants(rows)
}

func (s *sqliteTenantStore) ListArchivedTenants(ctx context.Context, before time.Time) ([]Tenant, error) {
	const q = `SELECT id, name, type, vendor_relay_enabled, deleted_at, created_at, updated_at
		FROM tenants WHERE deleted_at IS NOT NULL AND deleted_at < ? ORDER BY deleted_at`
	beforeStr := before.UTC().Format(storeTimeLayout)
	rows, err := s.db.QueryContext(ctx, q, beforeStr)
	if err != nil {
		return nil, fmt.Errorf("store.ListArchivedTenants: %w", err)
	}
	defer rows.Close()
	return scanTenants(rows)
}

// --- scan helpers ---

func scanTenant(row *sql.Row) (*Tenant, error) {
	var t Tenant
	var relay int
	var deletedAt, createdAt, updatedAt sql.NullString
	err := row.Scan(&t.ID, &t.Name, &t.Type, &relay, &deletedAt, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store.scanTenant: %w", err)
	}
	t.VendorRelayEnabled = relay != 0
	if deletedAt.Valid {
		tt := parseStoreTime(deletedAt.String)
		t.DeletedAt = &tt
	}
	if createdAt.Valid {
		t.CreatedAt = parseStoreTime(createdAt.String)
	}
	if updatedAt.Valid {
		t.UpdatedAt = parseStoreTime(updatedAt.String)
	}
	return &t, nil
}

func scanTenants(rows *sql.Rows) ([]Tenant, error) {
	var out []Tenant
	for rows.Next() {
		var t Tenant
		var relay int
		var deletedAt, createdAt, updatedAt sql.NullString
		if err := rows.Scan(&t.ID, &t.Name, &t.Type, &relay, &deletedAt, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("store.scanTenants: %w", err)
		}
		t.VendorRelayEnabled = relay != 0
		if deletedAt.Valid {
			tt := parseStoreTime(deletedAt.String)
			t.DeletedAt = &tt
		}
		if createdAt.Valid {
			t.CreatedAt = parseStoreTime(createdAt.String)
		}
		if updatedAt.Valid {
			t.UpdatedAt = parseStoreTime(updatedAt.String)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.scanTenants rows: %w", err)
	}
	return out, nil
}
