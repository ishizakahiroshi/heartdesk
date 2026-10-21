// Package auditdb は Vendor Console 用の監査ログ集約 SQLite を管理する。
//
// 仕様:
//   - DB ファイル: config.toml [audit_aggregated].db_path（既定 /var/lib/heartdesk/data/audit_aggregated.db）
//   - スキーマ: audit_log_aggregated（agent_id / tenant_id / ts / event_type / user / ip_address / result / details / received_at）
//   - 利用元:
//   - heartdesk Monitor (heartdesk バイナリ): /api/agent/report で collector_id="audit_log" 受信時に Insert
//   - heartdesk Scheduler (heartdesk-scheduler バイナリ): audit_aggregated_cleanup ジョブで retention_years 超過分を削除
//
// CGO 不要の modernc.org/sqlite を使うので Windows ローカルクロスビルドでも問題なし。
package auditdb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/audit"
)

// Config は audit_aggregated SQLite の動作設定。
// config.toml [audit_aggregated] を構造体化したもの。
type Config struct {
	Enabled        bool
	DBPath         string
	RetentionYears int
}

const schema = `
CREATE TABLE IF NOT EXISTS audit_log_aggregated (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id     TEXT NOT NULL,
    tenant_id    TEXT NOT NULL,
    ts           TEXT NOT NULL,
    event_type   TEXT,
    user         TEXT,
    ip_address   TEXT,
    result       TEXT,
    details      TEXT,
    received_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_agg_agent_ts  ON audit_log_aggregated(agent_id, ts);
CREATE INDEX IF NOT EXISTS idx_audit_agg_tenant_ts ON audit_log_aggregated(tenant_id, ts);
CREATE INDEX IF NOT EXISTS idx_audit_agg_user_ts   ON audit_log_aggregated(user, ts);
CREATE INDEX IF NOT EXISTS idx_audit_agg_event_ts  ON audit_log_aggregated(event_type, ts);
`

var (
	mu      sync.RWMutex
	current *sql.DB
	cfg     Config
)

// Init は audit_aggregated SQLite を開き、スキーマを適用する。
// enabled=false の場合は no-op（集約役以外の Monitor 等から呼ばれる）。
// 二重呼び出しは安全（既存ハンドルを閉じてから開き直す）。
func Init(c Config) error {
	if !c.Enabled {
		log.Printf("auditdb: disabled")
		return nil
	}
	dbPath := strings.TrimSpace(c.DBPath)
	if dbPath == "" {
		dbPath = heartdesk.Path("data/audit_aggregated.db")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o750); err != nil {
		return fmt.Errorf("auditdb: mkdir: %w", err)
	}
	dsn := "file:" + dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("auditdb: open: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return fmt.Errorf("auditdb: ping: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return fmt.Errorf("auditdb: schema: %w", err)
	}

	mu.Lock()
	if current != nil {
		_ = current.Close()
	}
	current = db
	cfg = c
	mu.Unlock()

	log.Printf("auditdb: ready db_path=%s retention_years=%d", dbPath, c.RetentionYears)
	return nil
}

// Enabled は受信パイプラインから INSERT 可能かを返す。
func Enabled() bool {
	mu.RLock()
	defer mu.RUnlock()
	return current != nil && cfg.Enabled
}

// Close はテスト終了時等で DB を閉じる。
func Close() {
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		_ = current.Close()
		current = nil
	}
}

// InsertEvents は agent から受け取った監査イベントを audit_log_aggregated へ INSERT する。
// tenant_id は agent_id の `<tenant>-<type>-<name>` 形式から先頭セグメントを取り出す。
// 1 トランザクション内で全件 commit する（部分成功は許容しない）。
func InsertEvents(agentID string, events []audit.Event) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	mu.RLock()
	db := current
	enabled := cfg.Enabled
	mu.RUnlock()
	if db == nil || !enabled {
		return 0, fmt.Errorf("auditdb: not initialized")
	}

	tenantID := tenantIDFromAgentID(agentID)

	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	const stmt = `INSERT INTO audit_log_aggregated
        (agent_id, tenant_id, ts, event_type, user, ip_address, result, details, received_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	prep, err := tx.Prepare(stmt)
	if err != nil {
		return 0, fmt.Errorf("prepare: %w", err)
	}
	defer prep.Close()

	receivedAt := time.Now().In(heartdesk.JST()).Format(time.RFC3339)
	inserted := 0
	for _, ev := range events {
		ts := strings.TrimSpace(ev.Time)
		eventType := strings.TrimSpace(ev.Event)
		if ts == "" || eventType == "" {
			continue
		}
		details, _ := json.Marshal(ev)
		if _, err := prep.Exec(
			agentID,
			tenantID,
			ts,
			eventType,
			strings.TrimSpace(ev.User),
			strings.TrimSpace(ev.IP),
			strings.TrimSpace(ev.Result),
			string(details),
			receivedAt,
		); err != nil {
			return inserted, fmt.Errorf("insert: %w", err)
		}
		inserted++
	}
	if err := tx.Commit(); err != nil {
		return inserted, fmt.Errorf("commit: %w", err)
	}
	tx = nil
	return inserted, nil
}

// Cleanup は retention_years より古い行を削除する。戻り値は削除件数。
// retention_years が 0 以下なら no-op。
func Cleanup() (int64, error) {
	mu.RLock()
	db := current
	years := cfg.RetentionYears
	enabled := cfg.Enabled
	mu.RUnlock()
	if db == nil || !enabled {
		return 0, nil
	}
	if years <= 0 {
		return 0, nil
	}
	cutoff := time.Now().AddDate(-years, 0, 0).In(heartdesk.JST()).Format(time.RFC3339)
	// ts は agent ごとに異なる TZ オフセット（...Z / ...+09:00）で格納されるため、
	// 文字列辞書比較では同一 instant でも順序が狂う（境界付近の誤削除/誤残存）。
	// SQLite の datetime() は ISO8601 のオフセットを解釈して UTC に正規化するため、
	// 両辺を datetime() で包んで instant 比較に揃える（保存形式は変更しない）。
	res, err := db.Exec(`DELETE FROM audit_log_aggregated WHERE datetime(ts) < datetime(?)`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("auditdb cleanup: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func tenantIDFromAgentID(agentID string) string {
	idx := strings.Index(agentID, "-")
	if idx <= 0 {
		return ""
	}
	return agentID[:idx]
}

// QueryParams は Query のフィルタ条件。ゼロ値は「条件なし」扱い。
type QueryParams struct {
	Tenant string // tenant_id の完全一致
	Agent  string // agent_id の完全一致
	User   string // user の部分一致（LIKE %user%）
	Event  string // event_type の完全一致
	From   string // ts >= from (RFC3339)
	To     string // ts <= to (RFC3339)
	Limit  int    // デフォルト 100、最大 1000
	Offset int    // ページングオフセット
}

// LogRecord は audit_log_aggregated の 1 行。
type LogRecord struct {
	ID         int64  `json:"id"`
	AgentID    string `json:"agent_id"`
	TenantID   string `json:"tenant_id"`
	Ts         string `json:"ts"`
	EventType  string `json:"event_type"`
	User       string `json:"user"`
	IPAddress  string `json:"ip_address"`
	Result     string `json:"result"`
	Details    string `json:"details"`
	ReceivedAt string `json:"received_at"`
}

// QueryResult は Query の結果。
type QueryResult struct {
	Total  int64       `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
	Logs   []LogRecord `json:"logs"`
}

// Query は audit_log_aggregated をフィルタ + ページングで検索する。
func Query(p QueryParams) (QueryResult, error) {
	mu.RLock()
	db := current
	enabled := cfg.Enabled
	mu.RUnlock()
	if db == nil || !enabled {
		return QueryResult{Logs: []LogRecord{}}, fmt.Errorf("auditdb: not initialized")
	}
	if p.Limit <= 0 || p.Limit > 1000 {
		p.Limit = 100
	}
	if p.Offset < 0 {
		p.Offset = 0
	}

	var where []string
	var args []interface{}
	if p.Tenant != "" {
		where = append(where, "tenant_id = ?")
		args = append(args, p.Tenant)
	}
	if p.Agent != "" {
		where = append(where, "agent_id = ?")
		args = append(args, p.Agent)
	}
	if p.User != "" {
		where = append(where, "user LIKE ?")
		args = append(args, "%"+p.User+"%")
	}
	if p.Event != "" {
		where = append(where, "event_type = ?")
		args = append(args, p.Event)
	}
	// ts は agent ごとに TZ オフセット表記が異なりうるため、範囲比較は datetime() で
	// instant 正規化して文字列辞書比較の誤判定を避ける（Cleanup と同方針）。
	if p.From != "" {
		where = append(where, "datetime(ts) >= datetime(?)")
		args = append(args, p.From)
	}
	if p.To != "" {
		where = append(where, "datetime(ts) <= datetime(?)")
		args = append(args, p.To)
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = " WHERE " + strings.Join(where, " AND ")
	}

	var total int64
	if err := db.QueryRow("SELECT COUNT(*) FROM audit_log_aggregated"+whereClause, args...).Scan(&total); err != nil {
		return QueryResult{Logs: []LogRecord{}}, fmt.Errorf("auditdb query count: %w", err)
	}

	selectArgs := append(append([]interface{}(nil), args...), p.Limit, p.Offset)
	rows, err := db.Query(
		"SELECT id, agent_id, tenant_id, ts, event_type, user, ip_address, result, details, received_at"+
			" FROM audit_log_aggregated"+whereClause+" ORDER BY ts DESC LIMIT ? OFFSET ?",
		selectArgs...)
	if err != nil {
		return QueryResult{Logs: []LogRecord{}}, fmt.Errorf("auditdb query logs: %w", err)
	}
	defer rows.Close()

	logs := make([]LogRecord, 0)
	for rows.Next() {
		var r LogRecord
		if err := rows.Scan(&r.ID, &r.AgentID, &r.TenantID, &r.Ts, &r.EventType, &r.User, &r.IPAddress, &r.Result, &r.Details, &r.ReceivedAt); err != nil {
			return QueryResult{Logs: logs}, fmt.Errorf("auditdb scan: %w", err)
		}
		logs = append(logs, r)
	}
	if err := rows.Err(); err != nil {
		return QueryResult{Logs: logs}, fmt.Errorf("auditdb rows: %w", err)
	}
	return QueryResult{Total: total, Limit: p.Limit, Offset: p.Offset, Logs: logs}, nil
}

// ListDistinctTenants は audit_log_aggregated に存在する tenant_id の一覧を返す。
// カードフィルタのプルダウン用。DB が未初期化の場合は空スライスを返す。
func ListDistinctTenants() ([]string, error) {
	mu.RLock()
	db := current
	enabled := cfg.Enabled
	mu.RUnlock()
	if db == nil || !enabled {
		return []string{}, nil
	}
	rows, err := db.Query("SELECT DISTINCT tenant_id FROM audit_log_aggregated WHERE tenant_id != '' ORDER BY tenant_id")
	if err != nil {
		return nil, fmt.Errorf("auditdb list tenants: %w", err)
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, fmt.Errorf("auditdb scan tenant: %w", err)
		}
		tenants = append(tenants, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auditdb list tenants rows: %w", err)
	}
	if tenants == nil {
		tenants = []string{}
	}
	return tenants, nil
}
