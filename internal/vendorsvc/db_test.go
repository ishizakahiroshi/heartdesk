package vendorsvc_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc"
)

// TestOpenDB は OpenDB の基本動作と冪等性を検証する。
func TestOpenDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vendor.db")

	// 1. 初回 OpenDB
	db, err := vendorsvc.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	// 2. WAL モード確認
	var journalMode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Errorf("journal_mode = %q, want %q", journalMode, "wal")
	}

	// 3. schema_version テーブルに version=1 が存在すること
	var version int
	if err := db.QueryRow("SELECT MAX(version) FROM schema_version").Scan(&version); err != nil {
		t.Fatalf("SELECT schema_version: %v", err)
	}
	if version != 1 {
		t.Errorf("schema_version MAX = %d, want 1", version)
	}

	// 4. DB ファイルが実際に存在すること
	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("db file not found: %v", err)
	}
	db.Close()

	// 5. 2回目の OpenDB でもエラーにならず、version が増えないこと（冪等性）
	db2, err := vendorsvc.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB (2nd) failed: %v", err)
	}
	defer db2.Close()

	var version2 int
	if err := db2.QueryRow("SELECT MAX(version) FROM schema_version").Scan(&version2); err != nil {
		t.Fatalf("SELECT schema_version (2nd): %v", err)
	}
	if version2 != 1 {
		t.Errorf("schema_version MAX (2nd) = %d, want 1 (should not increase on re-run)", version2)
	}
}

// TestOpenDB_CreateDir は存在しない親ディレクトリが自動作成されることを確認する。
func TestOpenDB_CreateDir(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "nested", "deep", "vendor.db")

	db, err := vendorsvc.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB with nested dir failed: %v", err)
	}
	db.Close()

	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("db file not created at nested path: %v", err)
	}
}

// TestOpenDB_ForeignKeys は PRAGMA foreign_keys が ON になっていることを確認する。
func TestOpenDB_ForeignKeys(t *testing.T) {
	dir := t.TempDir()
	db, err := vendorsvc.OpenDB(filepath.Join(dir, "vendor.db"))
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	var fkEnabled int
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&fkEnabled); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if fkEnabled != 1 {
		t.Errorf("foreign_keys = %d, want 1", fkEnabled)
	}
}

// openTestDB はテスト用の一時 DB を作成するヘルパ。
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := vendorsvc.OpenDB(filepath.Join(dir, "vendor.db"))
	if err != nil {
		t.Fatalf("openTestDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
