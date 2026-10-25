package monitor

import (
	"html/template"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// ServiceInfo は1サービスのステータス・メモリ・バージョンを保持する
type ServiceInfo struct {
	Status  string  `json:"status"`  // "active" / "inactive" / "unknown"
	Mem     float64 `json:"mem"`     // MB（RSS 合計）
	Version string  `json:"version"` // バージョン文字列
}

// CronInfo は Nextcloud Cron の状態を保持する
type CronInfo struct {
	Class string `json:"class"` // "ok" / "warning" / "danger"
	Label string `json:"label"` // "3分前" など
	Time  string `json:"time"`  // "2026-04-15(火) 09:20:01"
}

// NextcloudInfo は Nextcloud 本体の状態・バージョン・容量を保持する
type NextcloudInfo struct {
	Class    string `json:"class"`    // "ok" / "warning"
	Label    string `json:"label"`    // "通常" / "メンテ中"
	Version  string `json:"version"`  // "33.0.2"
	Capacity string `json:"capacity"` // "12.3 GB / 50.0 GB"
}

// ServicesResponse は /api/services の JSON レスポンス
type ServicesResponse struct {
	Services    map[string]ServiceInfo `json:"services"`
	Order       []string               `json:"order"` // サービス表示順
	Nextcloud   *NextcloudInfo         `json:"nextcloud,omitempty"`
	NcCron      CronInfo               `json:"nc_cron"`
	IsMaint     bool                   `json:"is_maint"` // Nextcloudメンテナンスモード中か
	Actions     []string               `json:"actions"`  // 表示するボタンのアクションキー一覧
	Unavailable bool                   `json:"unavailable,omitempty"`
}

// KernelInfo はカーネルバージョン情報を保持する
type KernelInfo struct {
	Current  string
	Latest   string
	Outdated bool
}

// CountMode はカードヘッダー右側の件数バッジ表示方式
type CountMode string

const (
	CountModeNone  CountMode = ""      // 表示しない（ゼロ値）
	CountModeTotal CountMode = "total" // 全件数のみ（"1,000件"）
	CountModeRatio CountMode = "ratio" // 絞り込み時は分子/分母（"350 / 1,000件"）
)

// NavItem はサイドバーリンク / カード1枚分の定義
type NavItem struct {
	ID          string   // セクションID（例: "sec-services"）
	Label       string   // 表示ラベル（例: "🟢 サービス稼働状況"）
	ParentGroup string   // カードの親分類（例: "監視・運用"）
	Exports     []string // DLボタンのexportキー一覧（例: ["ban"]）。空ならボタンなし
	Href        string   // サイドナビ用の遷移先。空なら #ID へスクロール

	// UIメタデータ
	CountMode    CountMode // "" / "total" / "ratio"
	DefaultLimit int       // 行数制限のデフォルト（0 = 制限なし / バッジのみ）
	SlotID       string    // 件数バッジ・expand-btn 共用スロットID（空なら自動: ID+"-count-btn"）
	NoRefresh    bool      // true のとき更新ボタンを付けない（例: 静的カード）
	HasFilter    bool      // true のとき setupCardFilter を自動起動（将来対応）
}

// NavSection はサイドナビ / カード出力の1エントリ
//   - NavGroup != "" → グループ区切り見出し
//   - TwoCol != nil  → .two-col ラッパーで横並び
//   - その他        → 通常カード1枚
type NavSection struct {
	NavGroup string    // グループ見出し文字列（例: "監視・運用"）
	NavItem            // 通常カード用（ID / Label）
	TwoCol   []NavItem // two-col 用（2要素固定）
}

// HeaderLink はテンプレートに渡すヘッダーリンク（プレースホルダ解決済み）
type HeaderLink struct {
	Order     int
	Title     string
	Href      string // 解決済みURL（Action="export_all"なら"?export=all"）
	IsAction  bool   // true = target="_blank"不要な内部アクション
	NewTab    bool   // true = 新しいタブで開く（外部リンク向け）
	IconType  string // "svg" / "url" / "emoji"
	IconSrc   string // svg or url の場合の実際のsrc
	IconEmoji string
}

// PageData は HTML テンプレートに渡すデータ
type PageData struct {
	Identity                  MonitorIdentityConfig
	CardAliases               map[string]string
	AppName                   string
	PageTitle                 string
	AppBase                   string
	MonitorBase               string
	VendorBase                string
	StaticBase                string
	AssetVersion              string // 静的アセットのキャッシュバスティング用ビルドID
	IconPath                  string
	MonitorFaviconPath        string
	LogoutPath                string
	BaseHost                  string
	CurrentUser               string
	CurrentUserName           string // 表示名（users.toml の name フィールド）
	CurrentUserInitial        string // アバター用頭文字（name 先頭1文字）
	CurrentRole               string
	CurrentTOTPEnabled        bool
	CurrentAvatarURL          string
	AgentID                   string
	AgentType                 string
	CSRFToken                 string
	SettingsPasswordPath      string
	Settings2FAPath           string
	AdminAuditLogPath         string
	AdminUnlockPath           string
	Now                       string
	IsMaint                   bool
	CurrentAgentID            string
	ServerTree                []AgentOverviewItem
	Nav                       []NavSection
	Cards                     map[string]template.HTML // セクションID → 生成済みカードHTML
	ResourceGraph             ResourceGraphData
	StorageForecast           StorageForecastData
	JSVars                    template.JS // ページ読み込み時に注入するJS変数宣言（SSH_ALLOWED_TYPES等）
	ResourceBarThresholds     template.JS // リソースバーしきい値（BAR_THRESHOLDS）
	CardOptions               template.JS // ページ読み込み時に注入するカード別オプション（HD_CARD_OPTIONS）
	CardIDs                   template.JS // ページ読み込み時に注入するカードID辞書（HD_CARD_IDS）
	CardAPIs                  template.JS // ページ読み込み時に注入するカードAPI辞書（HD_CARD_APIS）
	CardViewModes             template.JS // ユーザー別カード表示モード（HD_CARD_VIEW_MODES）
	ChildCardViewModes        template.JS // ユーザー別子カード表示モード（HD_CHILD_CARD_VIEW_MODES）
	CardMeta                  template.JS // カードごとの親分類・表示順メタデータ（HD_CARD_META）
	CardJSModules             []string    // 表示カードに対応する cards/*.js モジュール（layout.html で range 出力）
	SystemInfo                config.SystemInfoData
	HeaderLinks               []HeaderLink
	ShowOverviewRefreshButton bool
	ShowServerContext         bool
	PageContextTitle          string
	PageContextType           string
	PageContextID             string
	PageContextIP             string
}

// ServerDetailPageData はサーバー詳細画面（?view=server_detail）のテンプレートデータ
type ServerDetailPageData struct {
	Identity                  MonitorIdentityConfig
	CardAliases               map[string]string
	PageTitle                 string
	AppBase                   string
	MonitorBase               string
	VendorBase                string
	StaticBase                string
	AssetVersion              string // 静的アセットのキャッシュバスティング用ビルドID
	IconPath                  string
	MonitorFaviconPath        string
	LogoutPath                string
	SettingsPasswordPath      string
	Settings2FAPath           string
	AdminAuditLogPath         string
	AdminUnlockPath           string
	BaseHost                  string
	AppName                   string
	HeaderLinks               []HeaderLink
	CurrentUser               string
	CurrentUserName           string
	CurrentUserInitial        string
	CurrentRole               string
	CurrentTOTPEnabled        bool
	CurrentAvatarURL          string
	CSRFToken                 string
	Now                       string
	IsMaint                   bool
	CurrentAgentID            string
	ServerTree                []AgentOverviewItem
	Nav                       []NavSection
	Cards                     map[string]template.HTML
	JSVars                    template.JS
	ResourceBarThresholds     template.JS
	CardOptions               template.JS
	CardIDs                   template.JS
	CardAPIs                  template.JS
	CardViewModes             template.JS
	ChildCardViewModes        template.JS
	CardMeta                  template.JS
	CardJSModules             []string
	SystemInfo                config.SystemInfoData
	AgentID                   string
	AgentLabel                string
	AgentType                 string
	IsInfraDoc                bool
	InfraDocTitle             string
	ShowOverviewRefreshButton bool
	ShowServerContext         bool
	PageContextTitle          string
	PageContextType           string
	PageContextID             string
	PageContextIP             string
}

// ---- リソース系カード ----

// ResourcePoint は1時間または1日分のリソース平均（nil = データなし）
type ResourcePoint struct {
	CPU  *float64
	Mem  *float64
	Disk *float64
}

// ResourceGraphData は resource_graph カードのデータ
type ResourceGraphData struct {
	H24     map[string]ResourcePoint // key: "00"~"23"
	D7      map[string]ResourcePoint // key: "2026-04-08"
	H24Keys []string                 // 時刻順キー（古い→新しい, 24要素）
	D7Keys  []string                 // 日付順キー（古い→新しい, 7要素）
	Empty   bool
}

// StorageForecastData はストレージ逼迫予測カードのデータ
type StorageForecastData struct {
	HasData     bool
	Current     float64
	SlopePerDay float64
	ETA90       *float64 // nil = slope <= 0
	ETA95       *float64
	WindowDays  float64
	Samples     int
	Status      string // "ok" / "warning" / "danger"
	// 表示用フィールド（テンプレートで直接使用）
	SlopeLabel  string // "+0.34%/日" or "横ばい"
	ETA90Label  string // "約202日" or "—"
	ETA95Label  string // "約217日" or "—"
	StatusLabel string // "安定" / "注意" / "逼迫"
	StatusClass string // "result-success" / "result-warning" / "result-fail"
}

// ProcessInfo は1プロセスの情報（cpu_top / mem_top API）
type ProcessInfo struct {
	PID     string `json:"pid"`
	CPU     string `json:"cpu"`
	Mem     string `json:"mem"`
	RSS     int64  `json:"rss"` // bytes
	Command string `json:"command"`
}

// ProcessesResponse は /api/monitor/processes の JSON レスポンス
type ProcessesResponse struct {
	TopCPU      []ProcessInfo `json:"top_cpu"`
	TopMem      []ProcessInfo `json:"top_mem"`
	Total       int           `json:"total"` // 全プロセス数（1000件上限前）
	Unavailable bool          `json:"unavailable,omitempty"`
}

// R2BucketInfo はバケット別ストレージ情報
type R2BucketInfo struct {
	PayloadSize string `json:"payloadSize"`
	ObjectCount string `json:"objectCount"`
}

// R2StorageInfo はストレージ合計
type R2StorageInfo struct {
	PayloadSize string                  `json:"payloadSize"`
	ObjectCount string                  `json:"objectCount"`
	Buckets     map[string]R2BucketInfo `json:"buckets"`
}

// R2OperationsInfo は月間操作回数
type R2OperationsInfo struct {
	ClassA int    `json:"class_a"`
	ClassB int    `json:"class_b"`
	Month  string `json:"month"`
}

// R2MetricsData は /api/monitor/r2_metrics の JSON レスポンス
type R2MetricsData struct {
	Storage    *R2StorageInfo    `json:"storage"`
	Operations *R2OperationsInfo `json:"operations"`
	Error      string            `json:"error,omitempty"`
}

// NcUserSummary はユーザー合計容量
type NcUserSummary struct {
	Used      int64 `json:"used"`
	Quota     int64 `json:"quota"`
	Unlimited int   `json:"unlimited"`
	Users     int   `json:"users"`
}

// NcGroupFolder はグループフォルダ情報
type NcGroupFolder struct {
	ID         int    `json:"id"`
	MountPoint string `json:"mount_point"`
	Size       int64  `json:"size"`
	Quota      *int64 `json:"quota"` // nil = 無制限
}

// NcGroupFolderTotals はグループフォルダ合計
type NcGroupFolderTotals struct {
	Size      int64 `json:"size"`
	Quota     int64 `json:"quota"`
	Unlimited int   `json:"unlimited"`
}

// NcStorageCache はキャッシュ情報
type NcStorageCache struct {
	Hit    bool   `json:"hit"`
	TTLSec int    `json:"ttl_sec"`
	File   string `json:"file"`
}

// NcStorageData は /api/monitor/nc_storage の JSON レスポンス
type NcStorageData struct {
	Users             NcUserSummary       `json:"users"`
	Groupfolders      []NcGroupFolder     `json:"groupfolders"`
	GroupfolderTotals NcGroupFolderTotals `json:"groupfolders_totals"`
	Errors            map[string]string   `json:"errors"`
	FetchedAt         string              `json:"fetched_at"`
	Cache             NcStorageCache      `json:"cache"`
}

// DBInfo はDB別容量
type DBInfo struct {
	Name string `json:"name"`
	Size string `json:"size"`
}

// DiskLogFile はロールされたログファイル情報
type DiskLogFile struct {
	Name string `json:"name"`
	Size string `json:"size"`
	Date string `json:"date"`
}

// DiskData は /api/monitor/disk の JSON レスポンス
type DiskData struct {
	NcDataSize    string         `json:"nc_data_size"`
	NcAppSize     string         `json:"nc_app_size"`
	LogSize       string         `json:"log_size"`
	NcLogSize     string         `json:"nc_log_size"`
	NcLogFiles    []DiskLogFile  `json:"nc_log_files"`
	DBSize        string         `json:"db_size"`
	DBList        []DBInfo       `json:"db_list"`
	AccessToday   int            `json:"access_today"`
	StatusCodes   map[string]int `json:"status_codes"`
	CountryCounts map[string]int `json:"country_counts"`
	Unavailable   bool           `json:"unavailable,omitempty"`
}

// --- Updates ---

// UpdatesData はシステムアップデート情報
type UpdatesData struct {
	UpdateSvc      string   `json:"update_svc"`
	UpdateAuto     string   `json:"update_auto"`
	AutoEnabled    bool     `json:"auto_enabled"` // 自動更新が有効か
	UpdateCount    int      `json:"update_count"`
	UpdateList     []string `json:"update_list"`
	UpdateLog      string   `json:"update_log"`
	UpdateLast     string   `json:"update_last"`      // 最終インストール（/var/log/apt/history.log mtime）
	UpdateListLast string   `json:"update_list_last"` // 最終リスト更新（/var/lib/apt/periodic/update-success-stamp mtime）
	UbuntuVer      string   `json:"ubuntu_version"`
	KernelCurrent  string   `json:"kernel_current"`
	KernelLatest   string   `json:"kernel_latest"`
	KernelOutdated bool     `json:"kernel_outdated"`
	HeldCount      int      `json:"held_count"`
	HeldPackages   []string `json:"held_packages"`
	Unavailable    bool     `json:"unavailable,omitempty"`
	// IsLocal は Monitor 本体（default_agent）か否か。
	// テンプレート側で apt-get 操作ボタン群を出すかどうかの判定に使う。
	IsLocal bool `json:"is_local,omitempty"`
}

// --- Realtime ---

// CPURaw は /proc/stat から取得したCPU raw値
type CPURaw struct {
	User    int64 `json:"user"`
	Nice    int64 `json:"nice"`
	System  int64 `json:"system"`
	Idle    int64 `json:"idle"`
	IOWait  int64 `json:"iowait"`
	IRQ     int64 `json:"irq"`
	SoftIRQ int64 `json:"softirq"`
	Steal   int64 `json:"steal"`
}

// MemStat はメモリ/SWAP使用状況
type MemStat struct {
	Total int64   `json:"total"`
	Used  int64   `json:"used"`
	Pct   float64 `json:"pct"`
}

// DiskStat はディスク使用状況
type DiskStat struct {
	Pct   int   `json:"pct"`
	Used  int64 `json:"used"`
	Total int64 `json:"total"`
}

// NetStat はネットワーク帯域情報
type NetStat struct {
	RX    float64 `json:"rx"`
	TX    float64 `json:"tx"`
	Iface string  `json:"iface"`
}

// LoadStat はロードアベレージ
type LoadStat struct {
	Min1  float64 `json:"1m"`
	Min5  float64 `json:"5m"`
	Min15 float64 `json:"15m"`
}

// RealtimeData は /api/monitor/realtime のレスポンス
type RealtimeData struct {
	CPURaw    *CPURaw  `json:"cpu_raw"`
	Memory    MemStat  `json:"memory"`
	Swap      MemStat  `json:"swap"`
	Disk      DiskStat `json:"disk"`
	Network   NetStat  `json:"network"`
	Load      LoadStat `json:"load"`
	Timestamp int64    `json:"timestamp"`
}

// --- AlertRules / NotificationRules ---

// AlertRuleDef はアラートルールの静的定義
type AlertRuleDef struct {
	Label        string
	Desc         string
	HasThreshold bool
	HasRecovery  bool
	HasSustain   bool
	// ThresholdMax はしきい値の上限。0 なら従来どおり 100（% やスコアのルール）。
	// 件数で判定するルール（Nextcloud の取得件数など）は 100 を超える値を入れるので広げる。
	ThresholdMax float64
	// ThresholdMin はしきい値の下限（0 なら従来どおり 0）。IntegerThreshold は整数だけを受け付けるか
	// （件数のルール用。小数は保存時に弾く）。
	ThresholdMin     float64
	IntegerThreshold bool
	// DefaultThreshold / DefaultCooldownSec は未保存のルールを画面に出すときの初期値。
	// 0 なら従来どおり 0 を表示する。Nextcloud の取得ルール（nc_mass_access 等）は、
	// 評価側（internal/alerts の ncFADefaults）も 0 以下のときに同じ値を使う。
	DefaultThreshold   float64
	DefaultCooldownSec int
}

// AlertRuleConfig はアラートルールの設定値（JSON永続化）
type AlertRuleConfig struct {
	Threshold      float64 `json:"threshold,omitempty"`
	Recovery       float64 `json:"recovery,omitempty"`
	SustainSec     int     `json:"sustain_sec,omitempty"`
	CooldownSec    int     `json:"cooldown_sec"`
	Enabled        bool    `json:"enabled"`
	NotifyRecovery bool    `json:"notify_recovery,omitempty"`
}

// AlertRecipient は通知先1件
type AlertRecipient struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Email     string          `json:"email"`
	Enabled   bool            `json:"enabled"`
	Rules     map[string]bool `json:"rules,omitempty"`
	UpdatedAt string          `json:"updated_at,omitempty"`
}

// AlertRulesFile は alert_rules.json の全体構造
type AlertRulesFile struct {
	Rules      map[string]AlertRuleConfig `json:"rules"`
	Recipients []AlertRecipient           `json:"recipients"`
	// SMTP は internal/alerts が読む送信設定（smtp_host / smtp_pass 等）。画面では編集しないが、
	// 画面からの保存で消えないよう構造体に持つ（保存のたびに既存の値をそのまま書き戻す）。
	SMTP map[string]string `json:"smtp,omitempty"`
}

// AlertRuleRuntime は各ルールのライブ実行時状態
type AlertRuleRuntime struct {
	Evaluated bool   `json:"evaluated"`
	Active    bool   `json:"active"`
	LastValue string `json:"last_value"`
	ValueType string `json:"value_type,omitempty"`
}

// NotificationRulesAPIData は /api/monitor/alert_rules の GET レスポンス
type NotificationRulesAPIData struct {
	Rules   map[string]AlertRuleConfig  `json:"rules"`
	Runtime map[string]AlertRuleRuntime `json:"runtime"`
}

// NotificationRulesCardData はnotification_rules カードテンプレートに渡すデータ
type NotificationRulesCardData struct {
	DefOrder     []string
	Defs         map[string]AlertRuleDef
	Rules        map[string]AlertRuleConfig
	Recipients   []AlertRecipient
	EnabledCount int
	CSRFToken    string
}

// --- CronStatus ---

// CronJob はcronジョブ1件の状態
type CronJob struct {
	Label         string `json:"label"`
	Summary       string `json:"summary"`
	Schedule      string `json:"schedule"`
	ScheduleHuman string `json:"schedule_human"`
	Command       string `json:"command"`
	Registered    bool   `json:"registered"`
	LastTime      string `json:"last_time"`
	Result        string `json:"result"` // "success" / "fail" / "unknown"
}

// CronStatusData は cron_status カードのデータ
type CronStatusData struct {
	Jobs []CronJob `json:"jobs"`
}

// --- Database ---

// BackupFile はバックアップファイル1件
type BackupFile struct {
	Name string `json:"name"`
	Size string `json:"size"`
	Date string `json:"date"`
}

// DatabaseCardData は database カードのSSR初期データ
type DatabaseCardData struct{}

// BackupAPIData はバックアップ非同期 API のレスポンス
type BackupAPIData struct {
	BackupFiles   []BackupFile `json:"backup_files"`
	NCBackupFiles []BackupFile `json:"nc_backup_files"` // Nextcloud DBダンプ一覧（nc-db-backup.sh の出力先。NC非対象ホストでは空）
	R2BackupFiles []BackupFile `json:"r2_backup_files"`
	R2ConfigFiles []BackupFile `json:"r2_config_files"`
	DBSize        string       `json:"db_size"` // DB合計サイズ（MB数値文字列、例: "28.2"）
	DBList        []DBInfo     `json:"db_list"` // DB別容量（Size は MB数値文字列）
}

// --- SSL ---

// SSLData はSSL証明書・Let's Encrypt自動更新情報
type SSLData struct {
	SSLExpiry      string `json:"ssl_expiry"`
	SSLDays        int    `json:"ssl_days"`
	SSLRenewalDate string `json:"ssl_renewal_date"`
	LeStatus       string `json:"le_status"`
	LeStatusClass  string `json:"le_status_class"`
	LeLastDate     string `json:"le_last_date"`
	RenewAllowed   bool   `json:"renew_allowed"`
	Unavailable    bool   `json:"unavailable,omitempty"`
}

// --- Resources ---

// ResourcesData はサーバーリソース情報
type ResourcesData struct {
	Uptime      string  `json:"uptime"`
	UptimeSince string  `json:"uptime_since"`
	Load1       float64 `json:"load1"`
	Load5       float64 `json:"load5"`
	Load15      float64 `json:"load15"`
	CPUPct      float64 `json:"cpu_pct"`
	MemTotal    int64   `json:"mem_total"`
	MemFree     int64   `json:"mem_free"`
	MemBuffers  int64   `json:"mem_buffers"`
	MemCached   int64   `json:"mem_cached"`
	MemAvail    int64   `json:"mem_avail"`
	MemUsed     int64   `json:"mem_used"`
	MemPct      float64 `json:"mem_pct"`
	SwapTotal   int64   `json:"swap_total"`
	SwapFree    int64   `json:"swap_free"`
	DiskTotal   string  `json:"disk_total"`
	DiskUsed    string  `json:"disk_used"`
	DiskFree    string  `json:"disk_free"`
	DiskPct     string  `json:"disk_pct"`
	NetIface    string  `json:"net_iface"`
	NetRxBytes  int64   `json:"net_rx_bytes"`
	NetTxBytes  int64   `json:"net_tx_bytes"`
	NetRxHuman  string  `json:"net_rx_human"`
	NetTxHuman  string  `json:"net_tx_human"`
	CPUModel    string  `json:"cpu_model,omitempty"`
	CPUCores    int     `json:"cpu_cores,omitempty"`
	RAMTotal    string  `json:"ram_total,omitempty"`
	OSLabel     string  `json:"os_label,omitempty"`
	Kernel      string  `json:"kernel,omitempty"`
	IsMaint     bool    `json:"is_maint"`
	UpdatedAt   string  `json:"updated_at"`
	Unavailable bool    `json:"unavailable,omitempty"`
}

// --- Fail2ban ---

// BanTopIP は1期間のトップBAN対象IP
type BanTopIP struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// BanHistEntry は fail2ban jail の BAN 履歴エントリ
type BanHistEntry struct {
	IP         string `json:"ip"`
	BannedAt   string `json:"banned_at"`
	UnbannedAt string `json:"unbanned_at,omitempty"`
	Active     bool   `json:"active"`
}

// Fail2banJail は1 jailの状態
type Fail2banJail struct {
	Name        string         `json:"name"`
	BanCount    int            `json:"ban_count"`    // Currently banned
	TotalBanned int            `json:"total_banned"` // Total banned（累計）
	TotalFound  int            `json:"total_found"`  // Total found（検知数）
	BannedIPs   []string       `json:"banned_ips"`
	History     []BanHistEntry `json:"history"` // BAN 履歴（jail カードクリック時に使用）
}

// ManualBanEntry は手動 BAN ログエントリ（manual_bans_log.csv）
type ManualBanEntry struct {
	DateTime string `json:"datetime"`
	IP       string `json:"ip"`
}

// BanHistoryEntry は fail2ban イベントから生成したBAN履歴の1エントリ
type BanHistoryEntry struct {
	DateTime string `json:"datetime"`
	IP       string `json:"ip"`
	Jail     string `json:"jail"`
}

// BanHistoryData は ban_history API のレスポンス
type BanHistoryData struct {
	History    []BanHistoryEntry `json:"history"`
	Flags      map[string]string `json:"flags"`
	ManualBans []ManualBanEntry  `json:"manual_bans"`
}

// Fail2banData は fail2ban API のレスポンス
type Fail2banData struct {
	Jails          []Fail2banJail        `json:"jails"`
	JailTooltips   map[string]string     `json:"jail_tooltips"`     // jail別 BAN 成立条件（組み込みの既定文言）
	BanTrend7d     map[string]int        `json:"ban_trend_7d"`      // date → count（直近7日）
	BanTrend14d    map[string]int        `json:"ban_trend_14d"`     // date → count（直近14日）
	BanTrend4w     map[string]int        `json:"ban_trend_4w"`      // weekLabel → count（直近4週）
	BanTrendTop    map[string][]BanTopIP `json:"ban_trend_top"`     // date → top5 IPs（7日）
	BanTrend14dTop map[string][]BanTopIP `json:"ban_trend_14d_top"` // date → top5 IPs（14日）
	BanTrend4wTop  map[string][]BanTopIP `json:"ban_trend_4w_top"`  // weekLabel → top5 IPs（4週）
	Flags          map[string]string     `json:"flags"`             // IP → 国旗付き国名
	ManualBans     []ManualBanEntry      `json:"manual_bans"`       // 手動 BAN ログ（jail モーダルで使用）
	BanTotal       int                   `json:"ban_total"`
	Total          int                   `json:"total"`  // 全BAN累積件数（分母）
	Active         int                   `json:"active"` // 現在有効なBAN件数（分子）
	UpdatedAt      string                `json:"updated_at"`
	Unavailable    bool                  `json:"unavailable,omitempty"`
}

// --- IP Management ---

// SSHAllowedIP は managed_ips 台帳の1エントリ
type SSHAllowedIP struct {
	IP               string `toml:"ip" json:"ip"`
	Name             string `toml:"name" json:"name"`
	Type             string `toml:"type" json:"type"` // "wlm" / "wla" / "known" / "wl"
	User             string `toml:"user,omitempty" json:"user,omitempty"`
	Added            string `toml:"added,omitempty" json:"added,omitempty"`
	UpdatedBy        string `toml:"updated_by,omitempty" json:"updated_by,omitempty"`
	UpdatedAt        string `toml:"updated_at,omitempty" json:"updated_at,omitempty"`
	UpdatedAtDisplay string `toml:"-" json:"updated_at_display,omitempty"` // "YYYY-MM-DD(曜) HH:MM:SS" 形式
	// 追加取得データ（GetIPMgmt で付与）
	NCRegistered bool   `toml:"-" json:"nc_registered"`
	BFAttempts   int    `toml:"-" json:"bf_attempts"`
	LastAccess   string `toml:"-" json:"last_access,omitempty"`
	// AdminProtected は [security].admin_protect_names に載った保護対象管理者の行か
	// （削除・名称変更・種別変更が拒否される）。画面はこれで操作ボタンを出し分ける。
	AdminProtected bool `toml:"-" json:"admin_protected"`
}

// IPMgmtData は IP 管理カードのレスポンス
type IPMgmtData struct {
	IPs         []SSHAllowedIP `json:"ips"`
	TotalWLM    int            `json:"total_wlm"`
	TotalWLA    int            `json:"total_wla"`
	TotalKnown  int            `json:"total_known"`
	TotalWL     int            `json:"total_wl"`
	UpdatedAt   string         `json:"updated_at"`
	Unavailable bool           `json:"unavailable,omitempty"`
}

// --- IP Search ---

// IPSearchEntry は search_ip API の1件の検索結果
type IPSearchEntry struct {
	Time   string `json:"time"`
	IP     string `json:"ip"`
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

// IPSearchData は search_ip API のレスポンス
type IPSearchData struct {
	Results []IPSearchEntry `json:"results"`
	Count   int             `json:"count"`
	Country string          `json:"country"`
	IsJapan bool            `json:"is_japan"`
}

// --- User Management ---

// UserMgmtRow はユーザー管理カードの1行データ
type UserMgmtRow struct {
	Username          string `json:"username"`
	Name              string `json:"name"`
	Role              string `json:"role"`
	TOTPEnabled       bool   `json:"totp_enabled"`
	Locked            bool   `json:"locked"`
	IsSelf            bool   `json:"is_self"`
	IsLastVendorStaff bool   `json:"is_last_vendor_staff"`
	UpdatedBy         string `json:"updated_by"`
	UpdatedAt         string `json:"updated_at"`
	UpdatedAtDisplay  string `json:"updated_at_display"`
}

// UserMgmtData はユーザー管理カードのレスポンス
type UserMgmtData struct {
	UpdatedAt   string        `json:"updated_at"`
	Total       int           `json:"total"`
	CurrentUser string        `json:"current_user"`
	CurrentRole string        `json:"current_role"`
	Users       []UserMgmtRow `json:"users"`
}

// ActionResponse はPOSTアクションの汎用レスポンス
type ActionResponse struct {
	OK               bool   `json:"ok"`
	Message          string `json:"message,omitempty"`
	UpdatedBy        string `json:"updated_by,omitempty"`         // rename/changetype で返す
	UpdatedAt        string `json:"updated_at,omitempty"`         // rename/changetype で返す
	UpdatedAtDisplay string `json:"updated_at_display,omitempty"` // フォーマット済み
}
