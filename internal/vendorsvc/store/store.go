// Package store は heartdesk Vendor 集約 DB の repository interface と型定義を提供する。
// 全 store 関数の第1引数は tenantID string 必須（ζ1）。
// 運営横断クエリは *AcrossTenants サフィックスで明示分離。
// SessionStore のみ tenantID 第1引数例外（ログイン直後はテナント未確定のため）。
package store

import (
	"context"
	"time"
)

// --- ドメイン型 ---

// Tenant はテナント行を表す。
type Tenant struct {
	ID                 string
	Name               string
	Type               string // "monitor_owned" | "vendor_hosted" | "vendor"
	VendorRelayEnabled bool
	DeletedAt          *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// User はユーザー行を表す（パスワードハッシュ含む）。
type User struct {
	ID           int64
	Email        string
	PasswordHash string
	TOTPSecret   *string
	IsSuper      bool
	CreatedAt    time.Time
	LastLoginAt  *time.Time
}

// Agent は agents 行を表す。
type Agent struct {
	ID             int64
	TenantID       string
	AgentID        string
	AgentLabel     string
	AgentType      string // "vps" | "rental"
	LastReceivedAt *time.Time
	CreatedAt      time.Time
}

// RawReport は agent_reports_raw 行を表す。
type RawReport struct {
	ID             int64
	TenantID       string
	AgentID        string
	ReceivedAt     time.Time
	ReportedAt     time.Time
	CollectorsJSON string
}

// AuditEntry は audit_log 行を表す。
type AuditEntry struct {
	ID          int64
	TenantID    *string
	UserID      *int64
	EventType   string
	IPAddress   *string
	OccurredAt  time.Time
	DetailsJSON *string
}

// LedgerEntry はライセンス台帳行を表す。
// 既存 vendorconsole.LedgerEntry と互換フィールド名を維持（C13 移行時の単純コピー用）。
type LedgerEntry struct {
	ID               int64
	TenantID         string
	AgentID          string
	Action           string // "issue" | "revoke" | "rotate-gen"
	KID              *string
	JTI              *string
	KeyPrefix        *string
	Actor            *string
	Reason           *string
	VendorSecretHash *string
	IssuedAt         time.Time
	// 既存 vendorconsole.LedgerEntry 互換フィールド（C13 移行用）
	Timestamp time.Time // IssuedAt と同値
}

// Session はセッション行を表す。
type Session struct {
	ID              string
	UserID          int64
	CurrentTenantID *string
	CSRFToken       string
	ExpiresAt       time.Time
	CreatedAt       time.Time
	LastSeenAt      time.Time
}

// TenantPatch はテナント部分更新のフィールドセット。nil = 変更なし。
type TenantPatch struct {
	Name               *string
	Type               *string
	VendorRelayEnabled *bool
}

// --- repository interfaces ---

// TenantStore はテナントの CRUD を担う。
type TenantStore interface {
	CreateTenant(ctx context.Context, t Tenant) error
	GetTenant(ctx context.Context, tenantID string) (*Tenant, error)
	UpdateTenant(ctx context.Context, tenantID string, patch TenantPatch) error
	SoftDeleteTenant(ctx context.Context, tenantID string, at time.Time) error // deleted_at セット
	HardDeleteTenant(ctx context.Context, tenantID string) error               // 完全削除（30日経過後 purge ジョブから）

	// 運営横断クエリ（明示的に分離、命名で判別可能）
	ListAllTenants(ctx context.Context) ([]Tenant, error)
	ListArchivedTenants(ctx context.Context, before time.Time) ([]Tenant, error)
}

// UserStore はユーザーの管理を担う。
type UserStore interface {
	CreateUser(ctx context.Context, tenantID string, u User) error                                    // user_tenants への INSERT も含む
	GetUserByEmail(ctx context.Context, tenantID, email string) (*User, error)                        // tenantID で隔離（運営は別関数）
	UpdateUserPassword(ctx context.Context, tenantID string, userID int64, passwordHash string) error // tenantID 必須（空文字はエラー）
	DeleteUser(ctx context.Context, tenantID string, userID int64) error

	// 運営横断
	GetUserByEmailAcrossTenants(ctx context.Context, email string) (*User, error)                 // ログイン時、所属テナント不明
	UpdateUserPasswordAcrossTenants(ctx context.Context, userID int64, passwordHash string) error // CLI 専用（user_tenants 照合なし）
	ListUserTenants(ctx context.Context, userID int64) ([]string, error)
	AttachUserToTenant(ctx context.Context, userID int64, tenantID string) error
	DetachUserFromTenant(ctx context.Context, userID int64, tenantID string) error
}

// AgentStore は Agent メタ情報を担う。
type AgentStore interface {
	UpsertAgent(ctx context.Context, tenantID string, a Agent) error // last_received_at 更新含む
	GetAgents(ctx context.Context, tenantID string) ([]Agent, error)
	GetAgentByID(ctx context.Context, tenantID, agentID string) (*Agent, error)

	// 運営横断
	GetAgentsAcrossTenants(ctx context.Context) ([]Agent, error)
}

// HourlySummary は時間集計行の書き込みデータを表す。
type HourlySummary struct {
	TenantID     string
	AgentID      string
	HourStart    time.Time
	CPUAvg       *float64
	CPUMax       *float64
	MemAvg       *float64
	MemMax       *float64
	DiskPctMax   *float64
	BanActiveMax *int64
	SampleCount  int
}

// DailySummary は日次集計行の書き込みデータを表す。
type DailySummary struct {
	TenantID     string
	AgentID      string
	Day          string // "2006-01-02"
	CPUAvg       *float64
	CPUMax       *float64
	MemAvg       *float64
	MemMax       *float64
	DiskPctMax   *float64
	BanActiveMax *int64
	SampleCount  int
}

// ReportStore は Agent レポートの生データ・集計データを担う。
type ReportStore interface {
	InsertRawReport(ctx context.Context, tenantID string, r RawReport) error
	ListRawReports(ctx context.Context, tenantID, agentID string, from, to time.Time, limit int) ([]RawReport, error)
	PurgeRawReportsOlderThan(ctx context.Context, tenantID string, before time.Time) (int64, error)

	UpsertHourlySummary(ctx context.Context, tenantID string, s HourlySummary) error
	UpsertDailySummary(ctx context.Context, tenantID string, s DailySummary) error
	PurgeHourlyOlderThan(ctx context.Context, tenantID string, before time.Time) (int64, error)
	PurgeDailyOlderThan(ctx context.Context, tenantID string, before time.Time) (int64, error)

	// 運営横断（C12 全テナント横断ダッシュボード用）
	ListLatestReportsAcrossTenants(ctx context.Context, limit int) ([]RawReport, error)
}

// AuditStore は監査ログを担う。
type AuditStore interface {
	AppendAudit(ctx context.Context, tenantID string, e AuditEntry) error
	ListAudit(ctx context.Context, tenantID string, from, to time.Time, limit int) ([]AuditEntry, error)
	PurgeOlderThan(ctx context.Context, tenantID string, before time.Time) (int64, error)

	// 運営横断
	ListAuditAcrossTenants(ctx context.Context, from, to time.Time, limit int) ([]AuditEntry, error)
}

// LedgerStore はライセンス台帳を担う。
type LedgerStore interface {
	AppendLedger(ctx context.Context, tenantID string, e LedgerEntry) error
	ListLedger(ctx context.Context, tenantID string) ([]LedgerEntry, error)
	GetByJTI(ctx context.Context, tenantID, jti string) (*LedgerEntry, error)

	// 運営横断
	ListLedgerAcrossTenants(ctx context.Context) ([]LedgerEntry, error)
	RevokedJTIs(ctx context.Context) (map[string]bool, error) // Monitor 起動時の互換用、横断
}

// SessionStore はセッションを担う。
// tenantID は current_tenant_id として session 内に持つため、第1引数ではなく内部フィールドで管理する。
// これは ζ1（tenantID 第1引数必須）の唯一の例外。middleware 側で current_tenant_id を取り出し以降の store 呼び出しに渡す。
type SessionStore interface {
	CreateSession(ctx context.Context, s Session) error
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	UpdateCurrentTenant(ctx context.Context, sessionID, tenantID string) error
	DeleteSession(ctx context.Context, sessionID string) error
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error)
}

// Stores は全 repository をひとまとめにしたコンビニエンス型。
// テスト・起動コードで一括生成するために使用する。
type Stores struct {
	Tenant  TenantStore
	User    UserStore
	Agent   AgentStore
	Report  ReportStore
	Audit   AuditStore
	Ledger  LedgerStore
	Session SessionStore
}
