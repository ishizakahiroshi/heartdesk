package store

import (
	"database/sql"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc/store/migrations"
)

// migrationNameRe はマイグレーションファイル名の命名規則（3桁連番 + アンダースコア）。
var migrationNameRe = regexp.MustCompile(`^\d{3}_`)

// MigrateUp は schema_version テーブルを使い、未適用の SQL マイグレーションを順次実行する。
// 冪等であり、何度呼んでも安全。1ファイル = 1トランザクション。
func MigrateUp(db *sql.DB) error {
	// schema_version テーブルを作成（存在しない場合のみ）
	const createVersion = `CREATE TABLE IF NOT EXISTS schema_version (
		version    INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT (datetime('now'))
	);`
	if _, err := db.Exec(createVersion); err != nil {
		return fmt.Errorf("store.MigrateUp: create schema_version: %w", err)
	}

	// 現在の最大バージョンを取得
	var currentVersion int
	row := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`)
	if err := row.Scan(&currentVersion); err != nil {
		return fmt.Errorf("store.MigrateUp: get current version: %w", err)
	}

	// embed.FS から *.sql ファイルを列挙
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("store.MigrateUp: readdir migrations: %w", err)
	}

	// ファイル名昇順でソート（001_, 002_, ...）
	var sqlFiles []fs.DirEntry
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			sqlFiles = append(sqlFiles, e)
		}
	}
	sort.Slice(sqlFiles, func(i, j int) bool {
		return sqlFiles[i].Name() < sqlFiles[j].Name()
	})

	for _, entry := range sqlFiles {
		name := entry.Name()
		// 命名規則（3桁連番 + "_"）を強制する。違反は明示エラーにして気づけるようにする。
		if !migrationNameRe.MatchString(name) {
			return fmt.Errorf("store.MigrateUp: migration file %q violates naming convention (expected ^\\d{3}_)", name)
		}
		// ファイル名先頭3桁をバージョンとして解釈（例: "001_initial.sql" → 1）
		fileVersion, err := strconv.Atoi(name[:3])
		if err != nil {
			return fmt.Errorf("store.MigrateUp: parse version from %q: %w", name, err)
		}

		// 適用済みはスキップ
		if fileVersion <= currentVersion {
			continue
		}

		// SQL ファイルを読み込む
		content, err := migrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("store.MigrateUp: read %q: %w", name, err)
		}

		// トランザクション内で実行
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("store.MigrateUp: begin tx for %q: %w", name, err)
		}

		if _, err := tx.Exec(string(content)); err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("store.MigrateUp: exec %q: %w", name, err)
		}

		if _, err := tx.Exec(`INSERT INTO schema_version (version) VALUES (?)`, fileVersion); err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("store.MigrateUp: insert version %d: %w", fileVersion, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store.MigrateUp: commit %q: %w", name, err)
		}
	}

	return nil
}
