package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const defaultDaemonEnvPath = "/home/sab/daemon.env" // secrets-scan: allow

// DefaultTenantID は SAB_TENANT_ID 未設定時に使用するデフォルトテナントID。
// 既定値を 1 箇所に集約する。BuildSystemInfo の表示も LoadAppConfigForTenant も
// この値を既定とする。
const DefaultTenantID = "default"

// ResolveTenantID は空文字を DefaultTenantID へ寄せる。LoadAppConfigForTenant と
// env フォールバック経路で既定値の解釈がずれないよう 1 箇所に集約する。
func ResolveTenantID(tenantID string) string {
	if strings.TrimSpace(tenantID) == "" {
		return DefaultTenantID
	}
	return strings.TrimSpace(tenantID)
}

type SchedulerConfig struct {
	ResourceLogPath         string
	ScoreCSVPath            string
	BackupOutputDir         string
	SchedulerLogPath        string
	CollectLogPath          string
	ScoreLogPath            string
	ExtractLogPath          string
	AlertsLogPath           string
	BackupLogPath           string
	NCEventBaseDir          string
	NC4xxDir                string
	AlertRulesPath          string
	AlertStatePath          string
	SSHIPListPath           string
	GeoIPDBPath             string
	GeoIPToken              string
	GeoIPDBURL              string
	GeoIPRefreshHours       int
	GeoIPDownloadTimeoutSec int
	CollectInterval         time.Duration
	ScoreInterval           time.Duration
	ExtractInterval         time.Duration
	AlertsInterval          time.Duration
	UpdateGeoIPDBInterval   time.Duration
	APIRunMap               map[string]string
	DisabledJobs            map[string]bool
	R2AccountID             string
	R2APIToken              string
	R2Buckets               []string
	R2Bucket                string
	// ハートビートパス（空なら daemon 内デフォルト使用）
	CollectHeartbeatPath string
	BackupHeartbeatPath  string
	// Vendor Console 集約 SQLite
	VendorDBPath             string
	VendorRawReportDays      int // agent_reports_raw 保持日数
	VendorHourlySummaryDays  int // agent_reports_hourly 保持日数
	VendorDailySummaryDays   int // agent_reports_daily 保持日数
	VendorAuditLogDays       int // audit_log 保持日数
	BaseDir                  string
	StateFile                string
	VendorPurgeIntervalHours int
	// スコアエンジン設定
	ScoreStaticWhitelist string
	ScoreConfigPath      string
	ScoreHistoryPath     string
	AutobanLogPath       string
	BanHistoryPath       string
	HoneypotDir          string
	NginxAccessLog       string
	NextcloudLog         string
	LoginEventsPath      string
	AgentEventDir        string
	AgentID              string
	// TenantID は稼働中ホストのテナント ID（SAB_TENANT_ID / DefaultTenantID）。
	// tenants/<id>/secrets.toml を直接読む外部スクリプトの起動に使う。
	TenantID string
}

// LoadSchedulerConfig は config.toml を優先で読み込み、なければ daemon.env から読み込む
// SAB_TENANT_ID 環境変数でテナントIDを受け取る（未設定時は DefaultTenantID）
func LoadSchedulerConfig() (*SchedulerConfig, error) {
	// TOML を試す（テナント対応）。SAB_TENANT_ID 未設定時は LoadAppConfigForTenant 内で
	// DefaultTenantID が適用される。
	appCfg, err := LoadAppConfigForTenant(os.Getenv("SAB_TENANT_ID"))
	if err == nil {
		return appCfg.ToSchedulerConfig(), nil
	}

	// TOML がなければ daemon.env にフォールバック
	if err := LoadDaemonEnvOptional(); err != nil {
		return nil, fmt.Errorf("daemon env load failed: %w", err)
	}

	cfg := &SchedulerConfig{
		ResourceLogPath:         mustGetEnv("RESOURCE_LOG_PATH"),
		ScoreCSVPath:            mustGetEnv("SCORE_CSV_PATH"),
		BackupOutputDir:         mustGetEnv("BACKUP_OUTPUT_DIR"),
		SchedulerLogPath:        mustGetEnv("SCHEDULER_LOG_PATH"),
		CollectLogPath:          mustGetEnv("COLLECT_LOG_PATH"),
		ScoreLogPath:            mustGetEnv("SCORE_LOG_PATH"),
		ExtractLogPath:          mustGetEnv("EXTRACT_LOG_PATH"),
		AlertsLogPath:           mustGetEnv("ALERTS_LOG_PATH"),
		BackupLogPath:           mustGetEnv("BACKUP_LOG_PATH"),
		NCEventBaseDir:          mustGetEnv("NC_EVENT_BASE_DIR"),
		NC4xxDir:                mustGetEnv("NC4XX_DIR"),
		AlertRulesPath:          mustGetEnv("ALERT_RULES_PATH"),
		AlertStatePath:          mustGetEnv("ALERT_STATE_PATH"),
		SSHIPListPath:           mustGetEnv("SSH_IP_LIST_PATH"),
		GeoIPDBPath:             strings.TrimSpace(os.Getenv("SAB_GEOIP_DB")),
		GeoIPToken:              strings.TrimSpace(os.Getenv("SAB_IPINFO_TOKEN")),
		GeoIPDBURL:              strings.TrimSpace(os.Getenv("SAB_GEOIP_DB_URL")),
		GeoIPRefreshHours:       parseIntEnv("SAB_GEOIP_DB_REFRESH_HOURS", 24),
		GeoIPDownloadTimeoutSec: parseIntEnv("SAB_GEOIP_DB_DOWNLOAD_TIMEOUT_SEC", 180),
		CollectInterval:         parseDurationEnv("SCHED_COLLECT_INTERVAL", 5*time.Minute),
		ScoreInterval:           parseDurationEnv("SCHED_SCORE_INTERVAL", 5*time.Minute),
		ExtractInterval:         parseDurationEnv("SCHED_EXTRACT_INTERVAL", 1*time.Minute),
		AlertsInterval:          parseDurationEnv("SCHED_ALERTS_INTERVAL", 5*time.Minute),
		UpdateGeoIPDBInterval:   parseDurationEnv("SCHED_UPDATE_GEOIP_DB_INTERVAL", 24*time.Hour),
		APIRunMap:               parseAPIRunMap(os.Getenv("SCHED_API_RUN_MAP")),
		TenantID:                ResolveTenantID(os.Getenv("SAB_TENANT_ID")),
	}
	return cfg, nil
}

// TryLoadSchedulerConfig は panic をエラーへ変換して返す。
func TryLoadSchedulerConfig() (_ *SchedulerConfig, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("scheduler config panic: %v", rec)
		}
	}()
	return LoadSchedulerConfig()
}

// LoadDaemonEnvOptional は daemon.env を読み込み、未存在は許容する。
func LoadDaemonEnvOptional() error {
	envPath := strings.TrimSpace(os.Getenv("SAB_DAEMON_ENV_PATH"))
	if envPath == "" {
		envPath = defaultDaemonEnvPath
	}
	if err := loadEnvFile(envPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func mustGetEnv(key string) string {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		panic(fmt.Sprintf("required env var %s is not set", key))
	}
	return val
}

func loadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, `"'`)
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		_ = os.Setenv(key, val)
	}
	return scanner.Err()
}

func parseDurationEnv(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

func parseIntEnv(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func parseAPIRunMap(raw string) map[string]string {
	out := map[string]string{
		"backup_run": "backup_mariadb",
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return out
	}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) != 2 {
			continue
		}
		api := strings.TrimSpace(kv[0])
		job := strings.TrimSpace(kv[1])
		if api == "" || job == "" {
			continue
		}
		out[api] = job
	}
	return out
}
