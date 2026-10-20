package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// legacyJSONLedgerEntry は旧 core/vendor_console JSON 台帳
// （vendor_license_ledger.json）の 1 レコードを表す移行専用構造体。
// store パッケージは vendorconsole に依存しないため、ここで形だけ再定義する。
type legacyJSONLedgerEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	TenantID  string    `json:"tenant_id"`
	AgentID   string    `json:"agent_id"`
	KID       string    `json:"kid,omitempty"`
	KeyPrefix string    `json:"key_prefix,omitempty"`
	Actor     string    `json:"actor"`
	Reason    string    `json:"reason,omitempty"`
}

// MigrateLedgerFromJSONFile は旧 JSON 台帳を license_ledger テーブルへ一度だけ取り込む。
// license_ledger に既に行がある場合・JSON ファイルが存在しない場合は no-op（冪等）。
// 元の JSON ファイルはバックアップとしてそのまま残す（削除しない）。
// 取り込み件数を返す。
func MigrateLedgerFromJSONFile(ctx context.Context, db *sql.DB, jsonPath string) (int, error) {
	var existing int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM license_ledger`).Scan(&existing); err != nil {
		return 0, fmt.Errorf("store.MigrateLedger count: %w", err)
	}
	if existing > 0 {
		return 0, nil // 既に移行済み or 運用開始済み
	}

	raw, err := os.ReadFile(jsonPath)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store.MigrateLedger read: %w", err)
	}

	var legacy []legacyJSONLedgerEntry
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &legacy); err != nil {
			return 0, fmt.Errorf("store.MigrateLedger parse: %w", err)
		}
	}
	if len(legacy) == 0 {
		return 0, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.MigrateLedger begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// license_ledger.tenant_id は tenants(id) への FK を持ち、foreign_keys(ON) 下では
	// 親 tenants 行が無いと INSERT 自体が制約違反になる。AppendLedger と同じ流儀で、
	// legacy エントリに登場する tenant_id をまず INSERT OR IGNORE で担保してから台帳行を挿入する。
	// 既定 type は AppendLedger / ensureAgentReportTenant と同じ monitor_owned。
	// tenantID 空（運営横断ログ）は親担保しない。
	const ensureTenant = `INSERT OR IGNORE INTO tenants (id, name, type, created_at, updated_at)
		VALUES (?, ?, 'monitor_owned', datetime('now'), datetime('now'))`
	seenTenants := make(map[string]struct{}, len(legacy))
	for _, e := range legacy {
		if e.TenantID == "" {
			continue
		}
		if _, ok := seenTenants[e.TenantID]; ok {
			continue
		}
		seenTenants[e.TenantID] = struct{}{}
		if _, err := tx.ExecContext(ctx, ensureTenant, e.TenantID, e.TenantID); err != nil {
			return 0, fmt.Errorf("store.MigrateLedger ensure tenant: %w", err)
		}
	}

	// issued_at を元のタイムスタンプで保存する（AppendLedger は datetime('now') 固定のため使わない）。
	// jti は旧 JSON 台帳に存在しないため NULL リテラル。reason は失効エントリで使うため保持する。
	const q = `INSERT INTO license_ledger
		(tenant_id, agent_id, action, kid, jti, key_prefix, actor, reason, issued_at)
		VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?)`
	// 旧台帳は新しい順に並んでいるため、古い順に挿入して id を時系列昇順にする。
	n := 0
	for i := len(legacy) - 1; i >= 0; i-- {
		e := legacy[i]
		issuedAt := e.Timestamp.UTC().Format(storeTimeLayout)
		if _, err := tx.ExecContext(ctx, q,
			e.TenantID, e.AgentID, e.Action,
			nullableString(e.KID), nullableString(e.KeyPrefix),
			nullableString(e.Actor), nullableString(e.Reason), issuedAt,
		); err != nil {
			return 0, fmt.Errorf("store.MigrateLedger insert: %w", err)
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.MigrateLedger commit: %w", err)
	}
	return n, nil
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
