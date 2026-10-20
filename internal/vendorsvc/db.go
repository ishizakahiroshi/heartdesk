package vendorsvc

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc/store"

	_ "modernc.org/sqlite"
)

// OpenDB は SQLite DB を開き WAL モード・PRAGMA 設定・マイグレーションを実施して返す。
// dbPath はファイルパス（例: "/var/lib/heartdesk/data/vendor/vendor.db"）。
// 呼び出し元は返った *sql.DB を Close する責任を持つ。
func OpenDB(dbPath string) (*sql.DB, error) {
	// 親ディレクトリを作成（権限 0750 = heartdesk:heartdesk）
	if err := os.MkdirAll(filepath.Dir(dbPath), 0750); err != nil {
		return nil, fmt.Errorf("vendorsvc.OpenDB: mkdir %s: %w", filepath.Dir(dbPath), err)
	}

	// PRAGMA は DSN の _pragma= で指定する。db.Exec("PRAGMA ...") はプール内の 1 接続にしか
	// 適用されず、後から張られる接続では foreign_keys などが無効化される懸念があるため、
	// per-connection PRAGMA を含めて全て DSN 経由で全接続に適用する。
	// journal_mode=WAL は DB レベルで永続だが、冪等なので含めて問題ない。
	dsn := dbPath + "?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(ON)" +
		"&_pragma=temp_store(MEMORY)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("vendorsvc.OpenDB: sql.Open: %w", err)
	}

	// WAL モードでは同時 read 可能なため MaxOpenConns=1 は不要。
	// write は serialized されるため 8 程度で十分。
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(2)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("vendorsvc.OpenDB: ping: %w", err)
	}

	// マイグレーション実施
	if err := store.MigrateUp(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("vendorsvc.OpenDB: migrate: %w", err)
	}

	return db, nil
}
