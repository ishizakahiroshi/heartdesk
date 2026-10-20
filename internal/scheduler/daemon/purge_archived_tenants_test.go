package daemon

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc/store"
)

// seedArchivedTenant は purge_archived_tenants の修正検証用に、
// archive 済みテナント + 所属ユーザー + session を 1 組準備する。
//
// 返り値: dbPath / 所属ユーザーID / 他テナント所属ユーザーID / is_super ユーザーID / sessionID
func seedArchivedTenant(t *testing.T) (dbPath string, soleUserID int64, multiTenantUserID int64, superUserID int64, sessionID string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "vendor.db")
	db, err := vendorsvc.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()

	ts := store.NewTenantStore(db)
	// archive 済みテナント t-purge（deleted_at = 90 日前）
	if err := ts.CreateTenant(ctx, store.Tenant{ID: "t-purge", Name: "Purge", Type: "monitor_owned"}); err != nil {
		t.Fatalf("CreateTenant t-purge: %v", err)
	}
	if err := ts.SoftDeleteTenant(ctx, "t-purge", time.Now().AddDate(0, 0, -90)); err != nil {
		t.Fatalf("SoftDeleteTenant: %v", err)
	}
	// 残存するテナント t-keep
	if err := ts.CreateTenant(ctx, store.Tenant{ID: "t-keep", Name: "Keep", Type: "monitor_owned"}); err != nil {
		t.Fatalf("CreateTenant t-keep: %v", err)
	}

	us := store.NewUserStore(db)

	// (a) 単独所属ユーザー（t-purge のみ）= purge で users 行も削除されるべき
	if err := us.CreateUser(ctx, "t-purge", store.User{
		Email: "sole@example.com", PasswordHash: "x",
	}); err != nil {
		t.Fatalf("CreateUser sole: %v", err)
	}
	soleUserID = mustGetUserID(t, db, "sole@example.com")

	// (b) 多テナント所属ユーザー（t-purge + t-keep）= users 行は残るべき
	if err := us.CreateUser(ctx, "t-purge", store.User{
		Email: "multi@example.com", PasswordHash: "x",
	}); err != nil {
		t.Fatalf("CreateUser multi: %v", err)
	}
	multiTenantUserID = mustGetUserID(t, db, "multi@example.com")
	if err := us.AttachUserToTenant(ctx, multiTenantUserID, "t-keep"); err != nil {
		t.Fatalf("AttachUserToTenant t-keep: %v", err)
	}

	// (c) is_super=true で t-purge のみ所属 = users 行は残るべき（運営フラグ明示）
	if err := us.CreateUser(ctx, "t-purge", store.User{
		Email: "super@example.com", PasswordHash: "x", IsSuper: true,
	}); err != nil {
		t.Fatalf("CreateUser super: %v", err)
	}
	superUserID = mustGetUserID(t, db, "super@example.com")

	// session（current_tenant_id = "t-purge"）が残っている = purge で消されるべき
	sessionID = "sess-stale-1"
	ss := store.NewSessionStore(db)
	if err := ss.CreateSession(ctx, store.Session{
		ID:        sessionID,
		UserID:    soleUserID, // 削除対象ユーザーの session
		CSRFToken: "csrf",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	// current_tenant_id を t-purge にセット
	if err := ss.UpdateCurrentTenant(ctx, sessionID, "t-purge"); err != nil {
		t.Fatalf("UpdateCurrentTenant: %v", err)
	}

	// 別 session: t-keep を current_tenant_id に持つ = 残るべき
	if err := ss.CreateSession(ctx, store.Session{
		ID:        "sess-keep-1",
		UserID:    multiTenantUserID,
		CSRFToken: "csrf",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("CreateSession keep: %v", err)
	}
	if err := ss.UpdateCurrentTenant(ctx, "sess-keep-1", "t-keep"); err != nil {
		t.Fatalf("UpdateCurrentTenant keep: %v", err)
	}

	return dbPath, soleUserID, multiTenantUserID, superUserID, sessionID
}

func mustGetUserID(t *testing.T, db *sql.DB, email string) int64 {
	t.Helper()
	var id int64
	if err := db.QueryRow(`SELECT id FROM users WHERE email = ?`, email).Scan(&id); err != nil {
		t.Fatalf("mustGetUserID(%s): %v", email, err)
	}
	return id
}

func userExists(t *testing.T, db *sql.DB, userID int64) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE id = ?`, userID).Scan(&n); err != nil {
		t.Fatalf("userExists query: %v", err)
	}
	return n > 0
}

func sessionExists(t *testing.T, db *sql.DB, sessionID string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id = ?`, sessionID).Scan(&n); err != nil {
		t.Fatalf("sessionExists query: %v", err)
	}
	return n > 0
}

// TestPurgeArchivedTenants_InvalidatesStaleSessions は、purge 対象テナントを
// current_tenant_id に持つ session が purge トランザクションで削除される（C-027 修正の再現）ことを確認する。
func TestPurgeArchivedTenants_InvalidatesStaleSessions(t *testing.T) {
	dbPath, _, _, _, staleSession := seedArchivedTenant(t)

	cfg := &config.SchedulerConfig{VendorDBPath: dbPath}
	if err := PurgeArchivedTenants(context.Background(), cfg); err != nil {
		t.Fatalf("PurgeArchivedTenants: %v", err)
	}

	db, err := vendorsvc.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB(verify): %v", err)
	}
	defer db.Close()

	if sessionExists(t, db, staleSession) {
		t.Fatalf("stale session %q が purge 後も残存している（C-027 回帰）", staleSession)
	}
	if !sessionExists(t, db, "sess-keep-1") {
		t.Fatalf("無関係な session(sess-keep-1) が誤って削除された")
	}
}

// TestPurgeArchivedTenants_RemovesOrphanedUsers は、purge 対象テナントにしか所属していない
// 一般ユーザーは users 行ごと削除され、他テナント所属ユーザー / is_super=true のユーザーは
// 残ること（C-038 修正による暗黙の権限昇格防止）を確認する。
func TestPurgeArchivedTenants_RemovesOrphanedUsers(t *testing.T) {
	dbPath, soleUserID, multiUserID, superUserID, _ := seedArchivedTenant(t)

	cfg := &config.SchedulerConfig{VendorDBPath: dbPath}
	if err := PurgeArchivedTenants(context.Background(), cfg); err != nil {
		t.Fatalf("PurgeArchivedTenants: %v", err)
	}

	db, err := vendorsvc.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB(verify): %v", err)
	}
	defer db.Close()

	if userExists(t, db, soleUserID) {
		t.Fatalf("孤児ユーザー(uid=%d) が purge 後も残存している（C-038 回帰：暗黙の運営権限昇格）", soleUserID)
	}
	if !userExists(t, db, multiUserID) {
		t.Fatalf("他テナント所属ユーザー(uid=%d) が誤って削除された", multiUserID)
	}
	if !userExists(t, db, superUserID) {
		t.Fatalf("is_super=true のユーザー(uid=%d) が誤って削除された", superUserID)
	}

	// tenants 行自体も消えていることを念のため確認
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tenants WHERE id = ?`, "t-purge").Scan(&n); err != nil {
		t.Fatalf("tenants count: %v", err)
	}
	if n != 0 {
		t.Fatalf("t-purge tenant 行が残存している: count=%d", n)
	}
}
