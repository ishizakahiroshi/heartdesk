package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type AppConfig struct {
	// TenantID は LoadAppConfigForTenant が解決したテナント ID。TOML には現れず、
	// 読み込み後に代入する（tenants/<id>/ を組み立て直す側が env を再読しないで済むように）。
	TenantID string `toml:"-"`

	Server struct {
		ListenAddr string   `toml:"listen_addr"`
		Name       string   `toml:"name"`
		Host       string   `toml:"host"`
		Domain     string   `toml:"domain"`
		IPs        []string `toml:"ips"`
	} `toml:"server"`

	Routing struct {
		Mode       string `toml:"mode"`
		TenantSlug string `toml:"tenant_slug"`
		BaseHost   string `toml:"base_host"`
		// PublicMonitorURL は heartdesk の公開 URL（末尾スラッシュ込み）。
		// 通知本文の末尾に置く導線に使う。mode / tenant_slug から組み立てないのは、
		// **公開しているかどうかが nginx 側の設定次第**で host ごとに違うため。
		// 空なら通知本文に URL 行を出さない。
		PublicMonitorURL string `toml:"public_monitor_url"`
	} `toml:"routing"`

	SSH struct {
		Port           int    `toml:"port"`
		AllowedIPsJSON string `toml:"allowed_ips_json"`
	} `toml:"ssh"`

	Security struct {
		// IPMgmtPin は WLM 操作用 PIN。
		// 平文 PIN を文字列で保持する。比較は subtle.ConstantTimeCompare で行う。
		// 最低 6 桁の英数字を推奨（検証は VerifyPIN 側で行う）。
		// より強固にする場合は ip_mgmt_pin_hash（bcrypt）を設定すると優先される。
		IPMgmtPin string `toml:"ip_mgmt_pin"`
		// IPMgmtPinHash は bcrypt ハッシュ化 PIN（`bcrypt$<hash>` 形式、任意）。
		// 設定されていれば平文 ip_mgmt_pin より優先して bcrypt 比較する。
		IPMgmtPinHash   string   `toml:"ip_mgmt_pin_hash"`
		AuditTrustedIPs []string `toml:"audit_trusted_ips"`
		PinLockMin      int      `toml:"pin_lock_min"`
		// AdminProtectNames は managed_ips 台帳で削除・改名・種別変更から保護する
		// 管理者の表示名一覧。未設定時は誰も保護しない（既定は空）。
		AdminProtectNames []string `toml:"admin_protect_names"`
		// TrustedProxies は X-Real-IP / X-Forwarded-For を信用してよい
		// リバースプロキシ（nginx 等）の IP / CIDR 一覧（ヘッダ偽装による IP 詐称を防ぐ）。
		// 未設定時はループバック（127.0.0.0/8, ::1）のみを信頼する。heartdesk は通常
		// nginx から 127.0.0.1:8765 へプロキシされるため既定で十分。:8765 へ直結された
		// 接続は信頼プロキシ外なので RemoteAddr が採用され、ヘッダ偽装が効かない。
		TrustedProxies []string `toml:"trusted_proxies"`
	} `toml:"security"`

	Session struct {
		TTLHours int `toml:"ttl_hours"`
	} `toml:"session"`

	Paths struct {
		BaseDir        string `toml:"base_dir"`
		NextcloudDir   string `toml:"nextcloud_dir"`
		NginxAccessLog string `toml:"nginx_access_log"`
		AuthLog        string `toml:"auth_log"`
		Fail2banLog    string `toml:"fail2ban_log"`
		BackupDir      string `toml:"backup_dir"`
		GeoIPDB        string `toml:"geoip_db"`
		UsersTOML      string `toml:"users_toml"`
	} `toml:"paths"`

	NextcloudCache struct {
		StorageCacheFile string `toml:"storage_cache_file"`
		StorageCacheTTL  int    `toml:"storage_cache_ttl"`
	} `toml:"nextcloud_cache"`

	UI struct {
		SSHAttacksLimit    int                          `toml:"ssh_attacks_limit"`
		CardDefaultLimit   int                          `toml:"card_default_limit"`
		Icon               string                       `toml:"icon"`
		IconMonitorFavicon string                       `toml:"icon_monitor_favicon"`
		HeaderLinks        map[string][]HeaderLinkEntry `toml:"header_links"`
		DefaultAgent       string                       `toml:"default_agent"`
		IPTypeLabels       map[string]IPTypeLabel       `toml:"ip_type_labels"`
	} `toml:"ui"`

	ResourceThresholds struct {
		BarWarning int `toml:"bar_threshold_warning"`
		BarDanger  int `toml:"bar_threshold_danger"`
	} `toml:"resource_thresholds"`

	NextcloudCron struct {
		WarnSec   int `toml:"warn_sec"`
		DangerSec int `toml:"danger_sec"`
	} `toml:"nextcloud_cron"`

	ThreatScore struct {
		Warn            int `toml:"warn"`
		Danger          int `toml:"danger"`
		NCOverrideScore int `toml:"nc_override_score"`
	} `toml:"threat_score"`

	NginxErrors struct {
		Threshold1h  int `toml:"threshold_1h"`
		Threshold24h int `toml:"threshold_24h"`
	} `toml:"nginx_errors"`

	SSL struct {
		ConnectPort int    `toml:"connect_port"`
		ConnectHost string `toml:"connect_host"`
		SNIDomain   string `toml:"sni_domain"`
	} `toml:"ssl"`

	Alerts struct {
		Enabled       bool   `toml:"enabled"`
		EmailTo       string `toml:"email_to"`
		SubjectPrefix string `toml:"subject_prefix"`
		StateFile     string `toml:"state_file"`
		RulesFile     string `toml:"rules_file"`

		Memory struct {
			ThresholdPct float64 `toml:"threshold_pct"`
			RecoveryPct  float64 `toml:"recovery_pct"`
			SustainSec   int     `toml:"sustain_sec"`
			CooldownSec  int     `toml:"cooldown_sec"`
		} `toml:"alerts.memory"`

		Disk struct {
			ThresholdPct float64 `toml:"threshold_pct"`
			RecoveryPct  float64 `toml:"recovery_pct"`
			SustainSec   int     `toml:"sustain_sec"`
			CooldownSec  int     `toml:"cooldown_sec"`
		} `toml:"alerts.disk"`

		Service struct {
			Watch       []string `toml:"watch"`
			SustainSec  int      `toml:"sustain_sec"`
			CooldownSec int      `toml:"cooldown_sec"`
		} `toml:"alerts.service"`

		Threat struct {
			Threshold   int `toml:"threshold"`
			Recovery    int `toml:"recovery"`
			CooldownSec int `toml:"cooldown_sec"`
		} `toml:"alerts.threat"`
	} `toml:"alerts"`

	GeoIP struct {
		Mode              string `toml:"mode"`
		CacheTTLDays      int    `toml:"cache_ttl_days"`
		Token             string `toml:"token"`
		DBDownloadURL     string `toml:"db_download_url"`
		DBRefreshHours    int    `toml:"db_refresh_hours"`
		DBDownloadTimeout int    `toml:"db_download_timeout_sec"`
	} `toml:"geoip"`

	Scheduler struct {
		ResourceLogPath  string `toml:"resource_log_path"`
		ScoreCSVPath     string `toml:"score_csv_path"`
		BackupOutputDir  string `toml:"backup_output_dir"`
		SchedulerLogPath string `toml:"scheduler_log_path"`
		CollectLogPath   string `toml:"collect_log_path"`
		ScoreLogPath     string `toml:"score_log_path"`
		ExtractLogPath   string `toml:"extract_log_path"`
		AlertsLogPath    string `toml:"alerts_log_path"`
		BackupLogPath    string `toml:"backup_log_path"`
		NCEventBaseDir   string `toml:"nc_event_base_dir"`
		NC4xxDir         string `toml:"nc_4xx_dir"`
		AlertRulesPath   string `toml:"alert_rules_path"`
		AlertStatePath   string `toml:"alert_state_path"`
		SSHIPListPath    string `toml:"ssh_ip_list_path"`
		// BaseDir は scheduler の baseDir（nc_pdf_rename 等が参照）。未設定時は既定。
		BaseDir string `toml:"base_dir"`
		// StateFile は scheduler_state.json の配置先（未設定時は既定パス）。
		StateFile string `toml:"state_file"`
		// AlertsIntervalMinutes は alerts daemon ジョブの実行間隔（分）。
		// 0（未設定）なら registry の既定 5 分を使う。
		AlertsIntervalMinutes int `toml:"alerts_interval_minutes"`
		// VendorPurgeIntervalHours は purge_old_reports / purge_archived_tenants の
		// 実行間隔（時間）。0（未設定）なら NewScheduler が
		// purge ジョブを無効化する（VendorDBPath なし環境向けの既存ロジック）。
		VendorPurgeIntervalHours int             `toml:"vendor_purge_interval_hours"`
		Jobs                     map[string]bool `toml:"jobs"`
	} `toml:"scheduler"`

	Cards CardsConfig `toml:"cards"`

	// Components はコンポーネント単位の有効・無効フラグ（config.toml [components] セクション）。
	// 未設定のコンポーネントは既定で有効（true）。コードは削除せず設定 1 つで機能ごと止める用途
	// （廃止予定の連携を止める等）に使う。
	// LoadAppConfigForTenant の重ね読み（グローバル config → グローバル secrets → テナント config →
	// テナント secrets）でも、BurntSushi/toml は同一 map フィールドへの複数回デコードをキー単位で
	// マージする（既存キー上書き + 新規キー追加、他キーは保持）ため、テナント側で特定コンポーネント
	// だけを上書きできる。
	Components map[string]bool `toml:"components"`

	SystemInfo struct {
		AppName    string `toml:"app_name"`
		AppVersion string `toml:"app_version"`
		Licenses   []struct {
			Name        string `toml:"name"`
			URL         string `toml:"url"`
			License     string `toml:"license"`
			Attribution string `toml:"attribution"`
		} `toml:"licenses"`
	} `toml:"system_info"`

	AgentReport struct {
		RetentionMonths  int `toml:"retention_months"`
		TimestampSkewSec int `toml:"timestamp_skew_sec"`
		// StrictLicense は Bearer(JWT) 無しの agent report を拒否するか。
		// *bool で保持し、未設定時の既定は
		// true（厳格）。新規テナント/Agent は config 未記載なら自動で
		// strict 受信になる。JWT 未対応の既存 Agent を抱えるテナントは移行期間中だけ
		// 明示的に `strict_license = false` を書き、JWT 取得確認後に削除する。
		StrictLicense *bool `toml:"strict_license"`
	} `toml:"agent_report"`

	AgentHealth struct {
		VPSAlertMin    int `toml:"vps_alert_min"`
		RentalAlertMin int `toml:"rental_alert_min"`
	} `toml:"agent_health"`

	// Agents はエージェントごとの設定（config.toml [agent.<id>] セクション）。
	Agents map[string]AgentConfig `toml:"agent"`

	// AgentKeys は secrets.toml の [agent_keys] セクションで管理する（agent_id → secret_key）
	AgentKeys map[string]string `toml:"agent_keys"`

	// AgentAllowedIPs は secrets.toml の [agent_allowed_ips] セクションで管理する（agent_id → 許可IPリスト）。
	// 空リストまたは未設定の場合は IP 制限なし。
	AgentAllowedIPs map[string][]string `toml:"agent_allowed_ips"`

	// AgentQuota は secrets.toml の [agent_quota] セクションで管理する（tenant_id → 最大Agent台数）。
	// 未設定の場合は制限なし。
	AgentQuota map[string]int `toml:"agent_quota"`

	// VendorLicense は secrets.toml の [vendor_license] セクションで管理する
	VendorLicense struct {
		TenantID   string `toml:"tenant_id"`
		LicenseKey string `toml:"license_key"`
		// ActiveKID は現在署名に使用するed25519鍵のkid。
		ActiveKID string `toml:"active_kid"`
		// SigningKeys はkid→SigningKeyEntry のマップ（Monitor/Vendor側のみ）。
		// secrets.toml の [vendor_license.signing_keys.<kid>] セクションで管理する。
		SigningKeys map[string]SigningKeyEntry `toml:"signing_keys"`
	} `toml:"vendor_license"`

	Database struct {
		DSN string `toml:"dsn"`
	} `toml:"database"`

	Nextcloud struct {
		URL     string `toml:"url"`
		AppUser string `toml:"app_user"`
		AppPass string `toml:"app_pass"`
	} `toml:"nextcloud"`

	CloudflareR2 struct {
		AccountID string   `toml:"account_id"`
		APIToken  string   `toml:"api_token"`
		Buckets   []string `toml:"buckets"`
		Bucket    string   `toml:"bucket"`
	} `toml:"cloudflare_r2"`

	AWS struct {
		Region          string `toml:"region"`
		Profile         string `toml:"profile"`
		AccessKeyID     string `toml:"access_key_id"`
		SecretAccessKey string `toml:"secret_access_key"`
	} `toml:"aws"`

	SMTP struct {
		Host string `toml:"host"`
		Port int    `toml:"port"`
		User string `toml:"user"`
		Pass string `toml:"pass"`
		From string `toml:"from"`
	} `toml:"smtp"`

	// AuditAggregated は Vendor Console 集約 SQLite の設定。
	// 集約 Monitor（複数テナントの report を受ける 1 台）でのみ enabled=true にする。
	AuditAggregated AuditAggregatedConfig `toml:"audit_aggregated"`

	// AggregatorAgentKeys は集約 Monitor で aggregator 経路（collector_id="audit_log"）に
	// 適用する agent_id → HMAC 秘密鍵マップ。secrets.toml の [aggregator_agent_keys] で管理する。
	// 通常の [agent_keys] とは別キーで運用し、漏洩時の影響範囲を分離する。
	AggregatorAgentKeys map[string]string `toml:"aggregator_agent_keys"`
}

// AuditAggregatedConfig は config.toml [audit_aggregated] の構造体表現。
type AuditAggregatedConfig struct {
	Enabled        bool   `toml:"enabled"`
	DBPath         string `toml:"db_path"`
	RetentionYears int    `toml:"retention_years"`
}

// SystemInfoData はシステム情報・ライセンス表示用のデータ構造
type SystemInfoData struct {
	AppName         string
	AppVersion      string
	AssetVersion    string // 静的アセットのキャッシュバスティング用ビルドID（?v= に付与）
	VendorName      string
	TenantID        string
	TenantSlug      string
	LicenseVerified bool
	Licenses        []LicenseEntry
}

// LicenseEntry は使用ライブラリ・データの帰属情報
type LicenseEntry struct {
	Name        string
	URL         string
	License     string
	Attribution string
}

type IPTypeLabel struct {
	Short string `toml:"short" json:"short"`
	Full  string `toml:"full" json:"full"`
}

func (cfg *AppConfig) applyDefaults() {
	if cfg == nil {
		return
	}
	if cfg.UI.IPTypeLabels == nil {
		cfg.UI.IPTypeLabels = make(map[string]IPTypeLabel)
	}
	defaults := map[string]IPTypeLabel{
		"wl":    {Short: "WL", Full: "WL（サーバー）"},
		"wlm":   {Short: "WLM", Full: "WLM（フルアクセス）"},
		"wla":   {Short: "WLA", Full: "WLA（Adminのみ）"},
		"known": {Short: "既知", Full: "既知"},
	}
	for key, def := range defaults {
		cur := cfg.UI.IPTypeLabels[key]
		if cur.Short == "" {
			cur.Short = def.Short
		}
		if cur.Full == "" {
			cur.Full = def.Full
		}
		cfg.UI.IPTypeLabels[key] = cur
	}
	// strict_license 未設定時の既定は true。
	// 既存 Agent 互換のため明示的に false を書いたテナントはその値を尊重する。
	if cfg.AgentReport.StrictLicense == nil {
		def := true
		cfg.AgentReport.StrictLicense = &def
	}
}

// BuildSystemInfo は AppConfig + 実行時情報から SystemInfoData を構築する。
// ログイン画面・モーダルなど複数箇所で同一データを共有するための共通ファクトリ。
func BuildSystemInfo(cfg *AppConfig, appVersion, assetVersion, vendorName, tenantID, tenantSlug string) SystemInfoData {
	info := SystemInfoData{
		AppName:         cfg.SystemInfo.AppName,
		AppVersion:      appVersion,
		AssetVersion:    assetVersion,
		VendorName:      vendorName,
		TenantID:        tenantID,
		TenantSlug:      tenantSlug,
		LicenseVerified: true,
	}
	for _, l := range cfg.SystemInfo.Licenses {
		info.Licenses = append(info.Licenses, LicenseEntry{
			Name:        l.Name,
			URL:         l.URL,
			License:     l.License,
			Attribution: l.Attribution,
		})
	}
	return info
}

// HeaderLinkEntry は [ui.header_links.<app>] の1エントリ
// icon_type: "svg" = static/img/<icon_svg>.svg, "url" = icon_url をそのまま使用, "emoji" = icon_emoji を文字として表示
type HeaderLinkEntry struct {
	Order     int    `toml:"order"`
	Title     string `toml:"title"`
	URL       string `toml:"url"`        // "{AppBase}", "{VendorBase}" プレースホルダ使用可
	Action    string `toml:"action"`     // "export_all" など内部アクション（URLの代わりに使用）
	IconType  string `toml:"icon_type"`  // "svg" / "url" / "emoji"
	IconSVG   string `toml:"icon_svg"`   // icon_type="svg" 時: static/img/<value>.svg
	IconURL   string `toml:"icon_url"`   // icon_type="url" 時: 外部URL or 絶対パス
	IconEmoji string `toml:"icon_emoji"` // icon_type="emoji" 時: 絵文字文字列
}

// SigningKeyEntry はsecrets.toml の [vendor_license.signing_keys.<kid>] 1エントリ。
type SigningKeyEntry struct {
	PrivateKeyB64 string `toml:"private_key_b64"`
	PublicKeyB64  string `toml:"public_key_b64"`
	State         string `toml:"state"`      // "active" | "valid" | "retired"
	RetiredAt     string `toml:"retired_at"` // ISO8601、空文字なら未退役
}

// CardsConfig はカード表示デフォルト設定（config.toml [cards] セクション）
type CardsConfig struct {
	DefaultMode   string                       `toml:"default_mode"`
	Defaults      map[string]string            `toml:"defaults"`
	ChildDefaults map[string]map[string]string `toml:"child_defaults"`
	Meta          map[string]CardMetaConfig    `toml:"meta"`
}

// CardMetaConfig はカードごとの親分類・表示順メタデータ。
// [cards.meta."<card_id>"] で設定する。
type CardMetaConfig struct {
	Group string `toml:"group"`
	Order int    `toml:"order"`
}

// AgentConfig はエージェントごとの設定（config.toml [agent.<id>] セクション）。
type AgentConfig struct {
	AgentID      string   `toml:"agent_id"`
	AgentType    string   `toml:"agent_type"` // "vps" | "rental"
	AgentLabel   string   `toml:"agent_label"`
	AgentIP      string   `toml:"agent_ip"`
	IsPrimary    bool     `toml:"is_primary"`   // true = heartdesk本体サーバー（Main Server）
	Capabilities []string `toml:"capabilities"` // カード表示制御に使う能力キー
}

var defaultAgentCapabilitiesByType = map[string][]string{
	"vps": {
		"snapshot.resources",
		"snapshot.process",
		"snapshot.cron",
		"snapshot.backup",
		"snapshot.r2",
		"snapshot.services",
		"snapshot.updates",
		"snapshot.fail2ban",
		"action.ip_mgmt",
		"event.ssh",
		"event.web_access",
		"event.fail2ban",
		"event.nextcloud",
		"event.honeypot",
		"score.threat",
		"module.nextcloud",
		"alert.notification",
	},
	"rental": {
		"snapshot.resources",
		"snapshot.process",
		"snapshot.cron",
		"snapshot.backup",
		"snapshot.r2",
		"event.web_access",
	},
}

// DefaultAgentCapabilitiesByType は agent_type ごとの既定 capability 一覧を返す。
func DefaultAgentCapabilitiesByType(agentType string) []string {
	key := strings.ToLower(strings.TrimSpace(agentType))
	caps, ok := defaultAgentCapabilitiesByType[key]
	if !ok || len(caps) == 0 {
		return nil
	}
	out := make([]string, len(caps))
	copy(out, caps)
	return out
}

// AgentCapabilities は agent_id に対する有効 capability 一覧を返す。
// 明示設定がある場合はそれを優先し、未設定時は agent_type 既定値を返す。
func (cfg *AppConfig) AgentCapabilities(agentID string) []string {
	if cfg == nil || agentID == "" || cfg.Agents == nil {
		return nil
	}
	agent, ok := cfg.Agents[agentID]
	if !ok {
		return nil
	}
	if len(agent.Capabilities) > 0 {
		return normalizeCapabilities(agent.Capabilities)
	}
	return normalizeCapabilities(DefaultAgentCapabilitiesByType(agent.AgentType))
}

// ComponentEnabled は指定コンポーネントが有効かを返す。
// 未設定・cfg が nil のときは true（既定で有効）。name は前後空白除去 + 小文字化して正規化する
// （config.toml [components] のキーは小文字で書く運用のため、比較前に呼び出し側の表記ゆれのみ吸収する）。
func (cfg *AppConfig) ComponentEnabled(name string) bool {
	if cfg == nil || len(cfg.Components) == 0 {
		return true
	}
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return true
	}
	enabled, ok := cfg.Components[key]
	if !ok {
		return true
	}
	return enabled
}

func normalizeCapabilities(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(src))
	out := make([]string, 0, len(src))
	for _, raw := range src {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// LoadAppConfig は config.toml と secrets.toml を読み込む
// HEARTDESK_CONFIG_DIR 環境変数で設定ディレクトリを指定可能（デフォルト: /var/lib/heartdesk/config）
func LoadAppConfig() (*AppConfig, error) {
	configDir := os.Getenv("HEARTDESK_CONFIG_DIR")
	if configDir == "" {
		configDir = "/var/lib/heartdesk/config"
	}

	cfg := &AppConfig{}

	configPath := filepath.Join(configDir, "config.toml")
	if _, err := toml.DecodeFile(configPath, cfg); err != nil {
		return nil, fmt.Errorf("config.toml decode failed: %w", err)
	}

	secretsPath := filepath.Join(configDir, "secrets.toml")
	if _, err := toml.DecodeFile(secretsPath, cfg); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("secrets.toml decode failed: %w", err)
		}
	}

	cfg.applyDefaults()

	return cfg, nil
}

// LoadAppConfigForTenant はインフラ共通設定にテナント固有設定をマージして返す
// 優先度: テナント固有secrets > テナント固有config > インフラ共通secrets > インフラ共通config
// HEARTDESK_CONFIG_DIR 環境変数で設定ディレクトリを指定可能（デフォルト: /var/lib/heartdesk/config）
// tenantID が空の場合は DefaultTenantID をデフォルトとして使用する
func LoadAppConfigForTenant(tenantID string) (*AppConfig, error) {
	tenantID = ResolveTenantID(tenantID)
	configDir := os.Getenv("HEARTDESK_CONFIG_DIR")
	if configDir == "" {
		configDir = "/var/lib/heartdesk/config"
	}

	cfg := &AppConfig{TenantID: tenantID}

	// 1. インフラ共通設定
	if _, err := toml.DecodeFile(filepath.Join(configDir, "config.toml"), cfg); err != nil {
		return nil, fmt.Errorf("config.toml decode failed: %w", err)
	}
	// 2. インフラ共通機密
	if _, err := toml.DecodeFile(filepath.Join(configDir, "secrets.toml"), cfg); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("secrets.toml decode failed: %w", err)
		}
	}
	// 3. テナント固有設定で上書き
	tenantDir := filepath.Join(configDir, "tenants", tenantID)
	if _, err := toml.DecodeFile(filepath.Join(tenantDir, "config.toml"), cfg); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("tenants/%s/config.toml decode failed: %w", tenantID, err)
		}
	}
	// 4. テナント固有機密で上書き
	if _, err := toml.DecodeFile(filepath.Join(tenantDir, "secrets.toml"), cfg); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("tenants/%s/secrets.toml decode failed: %w", tenantID, err)
		}
	}

	if err := mergeTenantAgentConfigs(tenantDir, cfg); err != nil {
		return nil, err
	}

	// 孤児 agent secrets entry を検出し reject + warn。
	// [agent_keys] / [agent_allowed_ips] のうち、当該テナント prefix を持ちながら
	// [agent."<id>"] 定義が config.toml に無い entry は、攻撃者が IP allowlist と
	// HMAC を満たせば偽造 report を投げ込める入口になる（テナント分離破壊）。
	// 検出時は entry を map から削除し log で警告する。
	// [aggregator_agent_keys] と他テナント Agent 用の IP allowlist entry はクロステナント
	// 受信に使うため検証対象外（例: tenant alpha の集約 Monitor が beta-vps-host1 の鍵を持つのは正常）。
	rejectOrphanAgentSecrets(tenantID, cfg)

	cfg.applyDefaults()

	return cfg, nil
}

// rejectOrphanAgentSecrets は当該テナント prefix の agent_id を持つ
// [agent_keys] / [agent_allowed_ips] entry のうち、[agent."<id>"] 定義に
// 紐付かないものを削除して警告ログを出す。
// 削除した entry を返却（テスト用途、外部からは無視可）。
func rejectOrphanAgentSecrets(tenantID string, cfg *AppConfig) []string {
	if cfg == nil || tenantID == "" {
		return nil
	}
	prefix := tenantID + "-"
	orphans := map[string]struct{}{}

	collect := func(agentID string) {
		if agentID == "" {
			return
		}
		if !strings.HasPrefix(agentID, prefix) {
			return
		}
		if _, ok := cfg.Agents[agentID]; ok {
			return
		}
		orphans[agentID] = struct{}{}
	}

	for id := range cfg.AgentKeys {
		collect(id)
	}
	for id := range cfg.AgentAllowedIPs {
		collect(id)
	}

	if len(orphans) == 0 {
		return nil
	}

	// 決定的な順序でログ出力し、map からも削除する。
	ids := make([]string, 0, len(orphans))
	for id := range orphans {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		delete(cfg.AgentKeys, id)
		delete(cfg.AgentAllowedIPs, id)
		log.Printf("config: rejected orphan agent secrets entry tenant=%s agent_id=%s (no [agent.%q] definition in config.toml)", tenantID, id, id)
	}
	return ids
}

type tenantAgentFileConfig struct {
	Agent struct {
		ID    string `toml:"id"`
		Label string `toml:"label"`
		Type  string `toml:"type"`
	} `toml:"agent"`
	Deploy struct {
		AgentIP string `toml:"agent_ip"`
	} `toml:"deploy"`
}

func mergeTenantAgentConfigs(tenantDir string, cfg *AppConfig) error {
	if cfg == nil {
		return nil
	}
	if cfg.Agents == nil {
		cfg.Agents = make(map[string]AgentConfig)
	}

	tenantAgents := make(map[string]AgentConfig)
	for _, kind := range []string{"vps", "rental"} {
		pattern := filepath.Join(tenantDir, kind, "*.agent.toml")
		files, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("agent config glob failed (%s): %w", kind, err)
		}
		for _, path := range files {
			fileCfg := tenantAgentFileConfig{}
			if _, err := toml.DecodeFile(path, &fileCfg); err != nil {
				return fmt.Errorf("agent config decode failed (%s): %w", path, err)
			}
			agentID := fileCfg.Agent.ID
			if agentID == "" {
				continue
			}

			agentCfg := cfg.Agents[agentID]
			agentCfg.AgentID = agentID
			if agentCfg.AgentLabel == "" {
				agentCfg.AgentLabel = fileCfg.Agent.Label
			}
			if agentCfg.AgentType == "" {
				agentCfg.AgentType = fileCfg.Agent.Type
			}
			if agentCfg.AgentType == "" {
				agentCfg.AgentType = kind
			}
			if agentCfg.AgentIP == "" {
				agentCfg.AgentIP = fileCfg.Deploy.AgentIP
			}
			tenantAgents[agentID] = agentCfg
		}
	}
	if len(tenantAgents) > 0 {
		cfg.Agents = tenantAgents
	}
	return nil
}

// LoadAppConfigFrom は指定パスから config.toml と secrets.toml を読み込む
func LoadAppConfigFrom(baseDir string) (*AppConfig, error) {
	cfg := &AppConfig{}

	configPath := filepath.Join(baseDir, "config.toml")
	if _, err := toml.DecodeFile(configPath, cfg); err != nil {
		return nil, fmt.Errorf("config.toml decode failed: %w", err)
	}

	secretsPath := filepath.Join(baseDir, "secrets.toml")
	if _, err := toml.DecodeFile(secretsPath, cfg); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("secrets.toml decode failed: %w", err)
		}
	}

	cfg.applyDefaults()

	return cfg, nil
}

// ToSchedulerConfig は AppConfig から scheduler 用の config を生成
func (ac *AppConfig) ToSchedulerConfig() *SchedulerConfig {
	r2Buckets := append([]string(nil), ac.CloudflareR2.Buckets...)
	if len(r2Buckets) == 0 && ac.CloudflareR2.Bucket != "" {
		r2Buckets = []string{ac.CloudflareR2.Bucket}
	}
	cfg := &SchedulerConfig{
		ResourceLogPath:         ac.Scheduler.ResourceLogPath,
		ScoreCSVPath:            ac.Scheduler.ScoreCSVPath,
		BackupOutputDir:         ac.Scheduler.BackupOutputDir,
		SchedulerLogPath:        ac.Scheduler.SchedulerLogPath,
		CollectLogPath:          ac.Scheduler.CollectLogPath,
		ScoreLogPath:            ac.Scheduler.ScoreLogPath,
		ExtractLogPath:          ac.Scheduler.ExtractLogPath,
		AlertsLogPath:           ac.Scheduler.AlertsLogPath,
		BackupLogPath:           ac.Scheduler.BackupLogPath,
		NCEventBaseDir:          ac.Scheduler.NCEventBaseDir,
		NC4xxDir:                ac.Scheduler.NC4xxDir,
		AlertRulesPath:          ac.Scheduler.AlertRulesPath,
		AlertStatePath:          ac.Scheduler.AlertStatePath,
		SSHIPListPath:           ac.Scheduler.SSHIPListPath,
		GeoIPDBPath:             ac.Paths.GeoIPDB,
		GeoIPToken:              ac.GeoIP.Token,
		GeoIPDBURL:              ac.GeoIP.DBDownloadURL,
		GeoIPRefreshHours:       ac.GeoIP.DBRefreshHours,
		GeoIPDownloadTimeoutSec: ac.GeoIP.DBDownloadTimeout,
		R2AccountID:             ac.CloudflareR2.AccountID,
		R2APIToken:              ac.CloudflareR2.APIToken,
		R2Buckets:               r2Buckets,
		VendorDBPath:            ac.AuditAggregated.DBPath,
		VendorRawReportDays:     ac.AuditAggregated.RetentionYears * 365,
		VendorHourlySummaryDays: ac.AuditAggregated.RetentionYears * 365,
		VendorDailySummaryDays:  ac.AuditAggregated.RetentionYears * 365,
		VendorAuditLogDays:      ac.AuditAggregated.RetentionYears * 365,
		NginxAccessLog:          ac.Paths.NginxAccessLog,
		AgentID:                 ac.UI.DefaultAgent,
		BaseDir:                 ac.Paths.BaseDir,
		StateFile:               ac.Scheduler.StateFile,
		// 設定値を反映する。未代入だと常に 0 となり、daemon.go の purge 有効化分岐に入らず
		// ジョブが無効化される。
		VendorPurgeIntervalHours: ac.Scheduler.VendorPurgeIntervalHours,
		TenantID:                 ac.TenantID,
	}
	if ac.Scheduler.BaseDir != "" {
		cfg.BaseDir = ac.Scheduler.BaseDir
	}
	if ac.GeoIP.DBRefreshHours > 0 {
		cfg.UpdateGeoIPDBInterval = time.Duration(ac.GeoIP.DBRefreshHours) * time.Hour
	}
	// AlertsInterval を設定値（分）から組み立てる。
	if ac.Scheduler.AlertsIntervalMinutes > 0 {
		cfg.AlertsInterval = time.Duration(ac.Scheduler.AlertsIntervalMinutes) * time.Minute
	}
	if len(ac.Scheduler.Jobs) > 0 {
		disabled := make(map[string]bool)
		for id, enabled := range ac.Scheduler.Jobs {
			if !enabled {
				disabled[id] = true
			}
		}
		if len(disabled) > 0 {
			cfg.DisabledJobs = disabled
		}
	}
	return cfg
}
