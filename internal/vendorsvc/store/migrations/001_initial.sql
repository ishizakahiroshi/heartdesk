-- ============================================================
-- 001_initial.sql : SAB Vendor 集約 DB 初期スキーマ
-- 親plan: （sab 側の内部 plan。公開版では省略）
-- ============================================================

-- テナント
CREATE TABLE tenants (
    id                    TEXT PRIMARY KEY,                    -- "tenant-a" / "tenant-b" / ...
    name                  TEXT NOT NULL,
    type                  TEXT NOT NULL CHECK (type IN ('monitor_owned','vendor_hosted','vendor')),
    vendor_relay_enabled  INTEGER NOT NULL DEFAULT 0,          -- 0/1
    deleted_at            TEXT,                                -- NULL = active、ISO8601 = アーカイブ中（30日後 purge）
    created_at            TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_tenants_deleted_at ON tenants(deleted_at);

-- ユーザー（運営 + テナントユーザー共用、1メアド = 1ユーザー）
CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,                              -- bcrypt or argon2id（C7 で確定）
    totp_secret     TEXT,                                       -- base32、NULL 可（初回ログイン時設定）
    is_super        INTEGER NOT NULL DEFAULT 0,                 -- 1 = ライセンス管理権限あり
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at   TEXT
);

-- ユーザーとテナントの多対多（tenant_ids[] 表現）
-- 0 件 = 運営（全テナント横断）、1 件以上 = 当該テナントにのみアクセス可
CREATE TABLE user_tenants (
    user_id    INTEGER NOT NULL,
    tenant_id  TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, tenant_id),
    FOREIGN KEY (user_id)   REFERENCES users(id)   ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX idx_user_tenants_tenant ON user_tenants(tenant_id);

-- セッション（ログイン後の current_tenant_id を含む）
CREATE TABLE sessions (
    id                 TEXT PRIMARY KEY,                       -- ランダム ID
    user_id            INTEGER NOT NULL,
    current_tenant_id  TEXT,                                   -- 単一テナントユーザー or 選択後にセット、運営 NULL
    csrf_token         TEXT NOT NULL,
    expires_at         TEXT NOT NULL,
    created_at         TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at       TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_user_id    ON sessions(user_id);

-- Agent メタ情報（受信実績ベース）
CREATE TABLE agents (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id         TEXT NOT NULL,
    agent_id          TEXT NOT NULL,                            -- "<tenant>-<type>-<name>"
    agent_label       TEXT NOT NULL,
    agent_type        TEXT NOT NULL,                            -- "vps" | "rental"
    last_received_at  TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (tenant_id, agent_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX idx_agents_tenant_last_recv ON agents(tenant_id, last_received_at);

-- Agent Report 生データ（保持期間: TOML raw_report_days）
CREATE TABLE agent_reports_raw (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    received_at     TEXT NOT NULL,                              -- Vendor 側受信時刻（ISO8601）
    reported_at     TEXT NOT NULL,                              -- Agent 側送信時刻
    collectors_json TEXT NOT NULL,                              -- AgentReport.Collectors を丸ごと JSON 文字列
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX idx_reports_raw_tenant_recv ON agent_reports_raw(tenant_id, received_at);
CREATE INDEX idx_reports_raw_agent_recv  ON agent_reports_raw(agent_id, received_at);

-- 時間集計（保持期間: TOML hourly_summary_days）
CREATE TABLE agent_reports_hourly (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    hour_start    TEXT NOT NULL,                                -- "2026-05-04T14:00:00+09:00"
    cpu_avg       REAL,
    cpu_max       REAL,
    mem_avg       REAL,
    mem_max       REAL,
    disk_pct_max  REAL,
    ban_active_max INTEGER,
    sample_count  INTEGER NOT NULL DEFAULT 0,
    UNIQUE (tenant_id, agent_id, hour_start),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX idx_reports_hourly_tenant_hour ON agent_reports_hourly(tenant_id, hour_start);

-- 日次集計（保持期間: TOML daily_summary_days、デフォルト 730 日 = 2年）
CREATE TABLE agent_reports_daily (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id      TEXT NOT NULL,
    agent_id       TEXT NOT NULL,
    day            TEXT NOT NULL,                               -- "2026-05-04"
    cpu_avg        REAL,
    cpu_max        REAL,
    mem_avg        REAL,
    mem_max        REAL,
    disk_pct_max   REAL,
    ban_active_max INTEGER,
    sample_count   INTEGER NOT NULL DEFAULT 0,
    UNIQUE (tenant_id, agent_id, day),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX idx_reports_daily_tenant_day ON agent_reports_daily(tenant_id, day);

-- 監査ログ（保持期間: TOML audit_log_days）
CREATE TABLE audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id     TEXT,                                          -- NULL = 運営横断イベント（テナント作成等）
    user_id       INTEGER,
    event_type    TEXT NOT NULL,                                 -- "login_success" / "tenant_create" / "license_issue" 等
    ip_address    TEXT,
    occurred_at   TEXT NOT NULL DEFAULT (datetime('now')),
    details_json  TEXT,                                          -- 任意の追加情報
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id)   REFERENCES users(id)   ON DELETE SET NULL
);
CREATE INDEX idx_audit_tenant_time ON audit_log(tenant_id, occurred_at);
CREATE INDEX idx_audit_user_time   ON audit_log(user_id, occurred_at);
CREATE INDEX idx_audit_event_time  ON audit_log(event_type, occurred_at);

-- ライセンス台帳（既存 license_ledger.jsonl の SQLite 移行版、C13 で MC 既存データを移行）
CREATE TABLE license_ledger (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id           TEXT NOT NULL,
    agent_id            TEXT NOT NULL,
    action              TEXT NOT NULL CHECK (action IN ('issue','revoke','rotate-gen')),
    kid                 TEXT,                                    -- ed25519 鍵 ID
    jti                 TEXT,                                    -- JWT JTI（revoke 検索用）
    key_prefix          TEXT,                                    -- 既存 LedgerEntry.KeyPrefix 互換
    actor               TEXT,                                    -- 操作ユーザー email or "cli"
    reason              TEXT,                                    -- revoke 理由
    vendor_secret_hash  TEXT,                                    -- 当該操作時の vendorSecret SHA-256（鍵ローテ追跡用、将来）
    issued_at           TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX idx_ledger_tenant_time ON license_ledger(tenant_id, issued_at);
CREATE INDEX idx_ledger_jti         ON license_ledger(jti);
CREATE INDEX idx_ledger_action_time ON license_ledger(action, issued_at);
