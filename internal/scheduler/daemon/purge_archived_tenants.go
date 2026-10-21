package daemon

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc/store"
)

// PurgeArchivedTenants は soft delete から 30 日経過したテナントとその関連データを物理削除する。
// cfg.VendorDBPath が空の場合は何もしない（Monitor 単体環境では Vendor DB なし）。
func PurgeArchivedTenants(ctx context.Context, cfg *config.SchedulerConfig) error {
	if cfg == nil || cfg.VendorDBPath == "" {
		return nil
	}

	db, err := vendorsvc.OpenDB(cfg.VendorDBPath)
	if err != nil {
		return fmt.Errorf("purge_archived_tenants: open db: %w", err)
	}
	defer db.Close()

	ts := store.NewTenantStore(db)

	// 30 日前のしきい値
	threshold := time.Now().AddDate(0, 0, -30)

	archived, err := ts.ListArchivedTenants(ctx, threshold)
	if err != nil {
		return fmt.Errorf("purge_archived_tenants: list archived: %w", err)
	}

	if len(archived) == 0 {
		log.Printf("[purge_archived_tenants] 削除対象テナントなし (threshold=%s)", threshold.Format("2006-01-02"))
		return nil
	}

	for _, t := range archived {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := purgeOneTenant(ctx, db, t.ID); err != nil {
			log.Printf("[purge_archived_tenants] WARN: tenant_id=%s purge失敗: %v", t.ID, err)
			// 1件失敗しても続行し、次の反復でリトライされる
			continue
		}
		log.Printf("[purge_archived_tenants] 物理削除完了: tenant_id=%s deleted_at=%v", t.ID, t.DeletedAt)
	}
	return nil
}

// CountArchivedTenants は 30 日経過アーカイブ済みテナント件数を返す（--dry-run 用）。
func CountArchivedTenants(ctx context.Context, db *sql.DB) (int, error) {
	ts := store.NewTenantStore(db)
	threshold := time.Now().AddDate(0, 0, -30)
	archived, err := ts.ListArchivedTenants(ctx, threshold)
	if err != nil {
		return 0, err
	}
	return len(archived), nil
}

// purgeOneTenant はテナントの関連データ + テナント行を 1 トランザクションで物理削除する。
// 削除順: sessions(current_tenant_id) → 所属ユーザー収集 → agent_reports_raw → hourly → daily →
// audit_log → agents → license_ledger → user_tenants → orphan users → tenants
// （外部キー制約: tenants.id 参照テーブルを先に削除）。
// 途中で失敗した場合は Rollback し、部分削除を残さない（次回反復でリトライ）。
//
// 当該テナントを `current_tenant_id` に持つ session を先頭で無効化し、
// purge 後にステイル session で `current_tenant_id` が消滅済みテナントを指したまま残るのを防ぐ。
// user_tenants 削除前に当該テナントへ所属するユーザーを記録し、削除後に
// `user_tenants` 0 件かつ `is_super = 0` のユーザーを users から削除する。
// schema コメント上 `user_tenants` 0 件 = 運営扱いとなるため、テナント物理削除に伴って
// 暗黙に運営権限へ昇格してしまう経路を塞ぐ。
func purgeOneTenant(ctx context.Context, db *sql.DB, tenantID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	// Commit 成功後の Rollback は no-op。失敗時はここで巻き戻す。
	defer func() { _ = tx.Rollback() }()

	// (1) ステイル session の無効化。
	// sessions.current_tenant_id は TEXT のみ・FK 無しのため、テナント削除で自動消去されない。
	// このテナントを「現在テナント」として保持している session を即時無効化する。
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM sessions WHERE current_tenant_id = ?`, tenantID); err != nil {
		return fmt.Errorf("DELETE sessions: %w", err)
	}

	// (2) 当該テナントに所属するユーザー ID を収集。
	// user_tenants 削除後の「孤児ユーザー（0 件所属）」検出に使う。
	affectedUserIDs, err := collectTenantUserIDs(ctx, tx, tenantID)
	if err != nil {
		return fmt.Errorf("collect user_tenants user_ids: %w", err)
	}

	stmts := []struct {
		label string
		query string
	}{
		{"agent_reports_raw", `DELETE FROM agent_reports_raw WHERE tenant_id = ?`},
		{"agent_reports_hourly", `DELETE FROM agent_reports_hourly WHERE tenant_id = ?`},
		{"agent_reports_daily", `DELETE FROM agent_reports_daily WHERE tenant_id = ?`},
		{"audit_log", `DELETE FROM audit_log WHERE tenant_id = ?`},
		{"agents", `DELETE FROM agents WHERE tenant_id = ?`},
		{"license_ledger", `DELETE FROM license_ledger WHERE tenant_id = ?`},
		{"user_tenants", `DELETE FROM user_tenants WHERE tenant_id = ?`},
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s.query, tenantID); err != nil {
			return fmt.Errorf("DELETE %s: %w", s.label, err)
		}
	}

	// (3) 孤児ユーザーの削除。
	// user_tenants 0 件かつ is_super = 0 のユーザー = 「このテナント以外にどこにも所属していない一般ユーザー」。
	// schema コメント上 user_tenants 0 件 = 運営扱いとなるため、削除せず残すと暗黙の権限昇格になる。
	// users への CASCADE で残りの sessions / user_tenants も連鎖削除される。
	for _, uid := range affectedUserIDs {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM users
			   WHERE id = ?
			     AND is_super = 0
			     AND NOT EXISTS (SELECT 1 FROM user_tenants WHERE user_id = ?)`,
			uid, uid); err != nil {
			return fmt.Errorf("DELETE orphan user %d: %w", uid, err)
		}
	}

	// (4) tenants 本体の削除。
	if _, err := tx.ExecContext(ctx, `DELETE FROM tenants WHERE id = ?`, tenantID); err != nil {
		return fmt.Errorf("DELETE tenants: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// collectTenantUserIDs は user_tenants から当該テナントに所属するユーザー ID 一覧を返す。
// tx 内で呼び、後段の user_tenants 削除直前のスナップショットとして使う。
func collectTenantUserIDs(ctx context.Context, tx *sql.Tx, tenantID string) ([]int64, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT user_id FROM user_tenants WHERE tenant_id = ?`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}
