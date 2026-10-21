package store

import (
	"context"
	"database/sql"
	"fmt"
)

type sqliteUserStore struct{ db *sql.DB }

// NewUserStore は UserStore の SQLite 実装を返す。
func NewUserStore(db *sql.DB) UserStore {
	return &sqliteUserStore{db: db}
}

func (s *sqliteUserStore) CreateUser(ctx context.Context, tenantID string, u User) error {
	// トランザクション：users + user_tenants に同時 INSERT
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.CreateUser: begin tx: %w", err)
	}

	const insertUser = `INSERT INTO users (email, password_hash, totp_secret, is_super, created_at)
		VALUES (?, ?, ?, ?, ?)`
	superInt := 0
	if u.IsSuper {
		superInt = 1
	}
	res, err := tx.ExecContext(ctx, insertUser, u.Email, u.PasswordHash, u.TOTPSecret, superInt, nowStoreTime())
	if err != nil {
		tx.Rollback() //nolint:errcheck
		return fmt.Errorf("store.CreateUser: insert user: %w", err)
	}

	userID, err := res.LastInsertId()
	if err != nil {
		tx.Rollback() //nolint:errcheck
		return fmt.Errorf("store.CreateUser: last insert id: %w", err)
	}

	// tenantID が指定されている場合は user_tenants にも INSERT
	if tenantID != "" {
		const insertTenant = `INSERT INTO user_tenants (user_id, tenant_id) VALUES (?, ?)`
		if _, err := tx.ExecContext(ctx, insertTenant, userID, tenantID); err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("store.CreateUser: insert user_tenants: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.CreateUser: commit: %w", err)
	}
	return nil
}

func (s *sqliteUserStore) GetUserByEmail(ctx context.Context, tenantID, email string) (*User, error) {
	const q = `SELECT u.id, u.email, u.password_hash, u.totp_secret, u.is_super, u.created_at, u.last_login_at
		FROM users u
		INNER JOIN user_tenants ut ON ut.user_id = u.id
		WHERE ut.tenant_id = ? AND u.email = ?`
	row := s.db.QueryRowContext(ctx, q, tenantID, email)
	return scanUser(row)
}

// UpdateUserPassword はテナント境界内でユーザーのパスワードを更新する。
// tenantID が空文字の場合はエラーを返す（tenantID 第1引数必須）。
// CLI 横断操作で使う場合は UpdateUserPasswordAcrossTenants を呼ぶこと。
func (s *sqliteUserStore) UpdateUserPassword(ctx context.Context, tenantID string, userID int64, passwordHash string) error {
	if tenantID == "" {
		return fmt.Errorf("store.UpdateUserPassword: tenantID must not be empty (use UpdateUserPasswordAcrossTenants for cross-tenant operations)")
	}
	const q = `UPDATE users SET password_hash = ?
		WHERE id = ? AND id IN (SELECT user_id FROM user_tenants WHERE tenant_id = ?)`
	if _, err := s.db.ExecContext(ctx, q, passwordHash, userID, tenantID); err != nil {
		return fmt.Errorf("store.UpdateUserPassword: %w", err)
	}
	return nil
}

// UpdateUserPasswordAcrossTenants は user_tenants 照合なしでパスワードを更新する。
// CLI の運営横断操作（user passwd 等）専用。Web ハンドラ経路から呼んではならない。
// 既存の *AcrossTenants 命名規約（GetUserByEmailAcrossTenants 等）に揃えてある。
func (s *sqliteUserStore) UpdateUserPasswordAcrossTenants(ctx context.Context, userID int64, passwordHash string) error {
	const q = `UPDATE users SET password_hash = ? WHERE id = ?`
	if _, err := s.db.ExecContext(ctx, q, passwordHash, userID); err != nil {
		return fmt.Errorf("store.UpdateUserPasswordAcrossTenants: %w", err)
	}
	return nil
}

func (s *sqliteUserStore) DeleteUser(ctx context.Context, tenantID string, userID int64) error {
	// user_tenants のみ削除（ユーザー自体は他テナントに所属する可能性あり）
	const q = `DELETE FROM user_tenants WHERE tenant_id = ? AND user_id = ?`
	if _, err := s.db.ExecContext(ctx, q, tenantID, userID); err != nil {
		return fmt.Errorf("store.DeleteUser: %w", err)
	}
	return nil
}

func (s *sqliteUserStore) GetUserByEmailAcrossTenants(ctx context.Context, email string) (*User, error) {
	const q = `SELECT id, email, password_hash, totp_secret, is_super, created_at, last_login_at
		FROM users WHERE email = ?`
	row := s.db.QueryRowContext(ctx, q, email)
	return scanUser(row)
}

func (s *sqliteUserStore) ListUserTenants(ctx context.Context, userID int64) ([]string, error) {
	const q = `SELECT tenant_id FROM user_tenants WHERE user_id = ? ORDER BY tenant_id`
	rows, err := s.db.QueryContext(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("store.ListUserTenants: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tid string
		if err := rows.Scan(&tid); err != nil {
			return nil, fmt.Errorf("store.ListUserTenants scan: %w", err)
		}
		out = append(out, tid)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListUserTenants rows: %w", err)
	}
	return out, nil
}

func (s *sqliteUserStore) AttachUserToTenant(ctx context.Context, userID int64, tenantID string) error {
	const q = `INSERT OR IGNORE INTO user_tenants (user_id, tenant_id) VALUES (?, ?)`
	if _, err := s.db.ExecContext(ctx, q, userID, tenantID); err != nil {
		return fmt.Errorf("store.AttachUserToTenant: %w", err)
	}
	return nil
}

func (s *sqliteUserStore) DetachUserFromTenant(ctx context.Context, userID int64, tenantID string) error {
	const q = `DELETE FROM user_tenants WHERE user_id = ? AND tenant_id = ?`
	if _, err := s.db.ExecContext(ctx, q, userID, tenantID); err != nil {
		return fmt.Errorf("store.DetachUserFromTenant: %w", err)
	}
	return nil
}

// ListAllUsers は全ユーザーを取得する（CLI user list 用、運営横断操作）。
func (s *sqliteUserStore) ListAllUsers(ctx context.Context) ([]User, error) {
	const q = `SELECT id, email, password_hash, totp_secret, is_super, created_at, last_login_at
		FROM users ORDER BY email`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("store.ListAllUsers: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var superInt int
		var totpSecret sql.NullString
		var createdAt, lastLoginAt sql.NullString
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &totpSecret, &superInt, &createdAt, &lastLoginAt); err != nil {
			return nil, fmt.Errorf("store.ListAllUsers scan: %w", err)
		}
		u.IsSuper = superInt != 0
		if totpSecret.Valid {
			u.TOTPSecret = &totpSecret.String
		}
		if createdAt.Valid {
			u.CreatedAt = parseStoreTime(createdAt.String)
		}
		if lastLoginAt.Valid {
			t := parseStoreTime(lastLoginAt.String)
			u.LastLoginAt = &t
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListAllUsers rows: %w", err)
	}
	return out, nil
}

// HardDeleteUser は users テーブルからユーザーを完全削除する（ON DELETE CASCADE で user_tenants / sessions も削除）。
// CLI user delete 専用。通常の DeleteUser は user_tenants のみを削除する。
func (s *sqliteUserStore) HardDeleteUser(ctx context.Context, userID int64) error {
	const q = `DELETE FROM users WHERE id = ?`
	if _, err := s.db.ExecContext(ctx, q, userID); err != nil {
		return fmt.Errorf("store.HardDeleteUser: %w", err)
	}
	return nil
}

// --- scan helper ---

func scanUser(row *sql.Row) (*User, error) {
	var u User
	var superInt int
	var totpSecret sql.NullString
	var createdAt, lastLoginAt sql.NullString
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &totpSecret, &superInt, &createdAt, &lastLoginAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store.scanUser: %w", err)
	}
	u.IsSuper = superInt != 0
	if totpSecret.Valid {
		u.TOTPSecret = &totpSecret.String
	}
	if createdAt.Valid {
		u.CreatedAt = parseStoreTime(createdAt.String)
	}
	if lastLoginAt.Valid {
		t := parseStoreTime(lastLoginAt.String)
		u.LastLoginAt = &t
	}
	return &u, nil
}
