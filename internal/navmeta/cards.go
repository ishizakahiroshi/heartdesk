// Package navmeta は Monitor / Admin 間で共有するナビ・カード表示メタデータを提供する。
package navmeta

import "github.com/ishizakahiroshi/heartdesk/internal/config"

// Card IDs（Monitor / Admin で利用するカード識別子）。
const (
	CardSecServices          = "sec-services"
	CardSecUpdates           = "sec-updates"
	CardSecRealtimeMonitor   = "sec-realtime-monitor"
	CardSecResources         = "sec-resources"
	CardSecNotificationRules = "sec-notification-rules"
	CardSecResourceGraph     = "sec-resource-graph"
	CardSecCPUTop            = "sec-cpu-top"
	CardSecMemTop            = "sec-mem-top"
	CardSecCronStatus        = "sec-cron-status"
	CardSecDatabase          = "sec-database"
	CardSecR2                = "sec-r2"
	CardSecNcStorage         = "sec-nc-storage"
	CardSecStorageForecast   = "sec-storage-forecast"
	CardSecIPMgmt            = "sec-ip-mgmt"
	CardSecFail2ban          = "sec-fail2ban"
	CardSecBanHeatmap        = "sec-ban-heatmap"
	CardSecSSHChart          = "sec-ssh-chart"
	CardSecHoneypotSummary   = "sec-honeypot-summary"
	CardSecHoneypotHeatmap   = "sec-honeypot-heatmap"
	CardSecHoneypotAccess    = "sec-honeypot-access"
	CardSecNc4xxAccess       = "sec-nc4xx-access"
	CardSecNcHighScore       = "sec-nc-high-score"
	CardSecThreatScore       = "sec-threat-score"
	CardSecSSHLoginHistory   = "sec-ssh-login-history"
	CardSecLoginHistory      = "sec-login-history"
	CardSecPhpmyadminLogin   = "sec-phpmyadmin-login-history"
	CardSecNcLogin           = "sec-nc-login"
	CardSecAuditAnomaly      = "sec-audit-anomaly"
	CardSecNginxHealth       = "sec-nginx-health"
	CardSecNginxLog          = "sec-nginx-log"
	CardSecGeoipCache        = "sec-geoip-cache"
	CardSecUserMgmt          = "sec-user-mgmt"
	CardSecAgentStatus       = "sec-agent-status"
	CardSecSSL               = "sec-ssl"

	// Vendor Console カード（vendor screen 専用）
	CardVendorDashboard       = "vendor-dashboard"
	CardVendorTenants         = "vendor-tenants"
	CardVendorAgents          = "vendor-agents"
	CardVendorLicenseAudit    = "vendor-license-audit"
	CardVendorAuditLog        = "vendor-audit-log"
	CardVendorLicenses        = "vendor-licenses"
	CardVendorLicenseOffline  = "vendor-license-offline"
	CardVendorLicenseRotation = "vendor-license-rotation"
	CardVendorNcOverview      = "vendor-nc-overview"
	CardVendorServerHealth    = "vendor-server-health"
)

// MonitorCardMeta は Monitor カードのレジストリ定義。
// Key はテンプレート/JS で参照する識別子、API は loadSection 用の ?api= キー。
// JSModule はカード専用 JS のパス（`static/js/` からの相対）。空なら shared.js / monitor_page.js 側実装。
// Renderer は card_runtime.js の CardRegistry.register() に渡す論理名（診断用、現時点では参照のみ）。
type MonitorCardMeta struct {
	Key      string
	ID       string
	API      string
	JSModule string
	Renderer string
}

var monitorCardRegistry = []MonitorCardMeta{
	{Key: "SERVICES", ID: CardSecServices, API: "services", JSModule: "cards/services.js", Renderer: "Services"},
	{Key: "UPDATES", ID: CardSecUpdates, API: "updates"},
	{Key: "REALTIME_MONITOR", ID: CardSecRealtimeMonitor, API: "realtime_monitor"},
	{Key: "RESOURCES", ID: CardSecResources, API: "resources", JSModule: "cards/resources.js", Renderer: "Resources"},
	{Key: "NOTIFICATION_RULES", ID: CardSecNotificationRules, API: "notification_rules"},
	{Key: "RESOURCE_GRAPH", ID: CardSecResourceGraph, API: "resource_graph", JSModule: "cards/resource_graph.js", Renderer: "ResourceGraph"},
	{Key: "CPU_TOP", ID: CardSecCPUTop, API: "processes", JSModule: "cards/cpu_top.js", Renderer: "CPUTop"},
	{Key: "MEM_TOP", ID: CardSecMemTop, API: "processes", JSModule: "cards/mem_top.js", Renderer: "MemTop"},
	{Key: "CRON_STATUS", ID: CardSecCronStatus, API: "cron_status"},
	{Key: "DATABASE", ID: CardSecDatabase, API: "backups", JSModule: "cards/backups.js", Renderer: "Backups"},
	{Key: "R2", ID: CardSecR2, API: "r2"},
	{Key: "NC_STORAGE", ID: CardSecNcStorage, API: "nc_storage", JSModule: "cards/nc_storage.js", Renderer: "NcStorage"},
	{Key: "STORAGE_FORECAST", ID: CardSecStorageForecast, API: "storage_forecast"},
	{Key: "IP_MGMT", ID: CardSecIPMgmt, API: "ip_mgmt", JSModule: "cards/ip_mgmt.js", Renderer: "IPMgmt"},
	{Key: "FAIL2BAN", ID: CardSecFail2ban, API: "fail2ban", JSModule: "cards/fail2ban.js", Renderer: "Fail2ban"},
	{Key: "BAN_HEATMAP", ID: CardSecBanHeatmap, API: "ban_heatmap", JSModule: "cards/ban_heatmap.js", Renderer: "BanHeatmap"},
	{Key: "SSH_CHART", ID: CardSecSSHChart, API: "ssh_chart", JSModule: "cards/ssh_chart.js", Renderer: "SSHChart"},
	{Key: "HONEYPOT_SUMMARY", ID: CardSecHoneypotSummary, API: "honeypot_all", JSModule: "cards/honeypot_summary.js", Renderer: "HoneypotSummary"},
	{Key: "HONEYPOT_HEATMAP", ID: CardSecHoneypotHeatmap, API: "honeypot_all", JSModule: "cards/honeypot_heatmap.js", Renderer: "HoneypotHeatmap"},
	{Key: "HONEYPOT_ACCESS", ID: CardSecHoneypotAccess, API: "honeypot_all", JSModule: "cards/honeypot_access.js", Renderer: "HoneypotAccess"},
	{Key: "NC4XX_ACCESS", ID: CardSecNc4xxAccess, API: "nc4xx_access", JSModule: "cards/nc4xx_access.js", Renderer: "Nc4xxAccess"},
	{Key: "NC_HIGH_SCORE", ID: CardSecNcHighScore, API: "nc_high_score", JSModule: "cards/nc_high_score.js", Renderer: "NcHighScore"},
	{Key: "THREAT_SCORE", ID: CardSecThreatScore, API: "threat_score", JSModule: "cards/threat_score.js", Renderer: "ThreatScore"},
	{Key: "SSH_LOGIN_HISTORY", ID: CardSecSSHLoginHistory, API: "ssh_login_history", JSModule: "cards/ssh_login_history.js", Renderer: "SSHLoginHistory"},
	{Key: "HEARTDESK_LOGIN_HISTORY", ID: CardSecLoginHistory, API: "nginx_login_histories", JSModule: "cards/login_history.js", Renderer: "LoginHistory"},
	{Key: "PHPMYADMIN_LOGIN_HISTORY", ID: CardSecPhpmyadminLogin, API: "nginx_login_histories", JSModule: "cards/phpmyadmin_login_history.js", Renderer: "PmaLoginHistory"},
	{Key: "NC_LOGIN", ID: CardSecNcLogin, API: "nc_login", JSModule: "cards/nc_login.js", Renderer: "NcLogin"},
	{Key: "AUDIT_ANOMALY", ID: CardSecAuditAnomaly, API: "audit_anomaly", JSModule: "cards/audit_anomaly.js", Renderer: "AuditAnomaly"},
	{Key: "NGINX_HEALTH", ID: CardSecNginxHealth, API: "nginx_health", JSModule: "cards/nginx_health.js", Renderer: "NginxHealth"},
	{Key: "NGINX_LOG", ID: CardSecNginxLog, API: "nginx_log", JSModule: "cards/nginx_log.js", Renderer: "NginxLog"},
	{Key: "GEOIP_CACHE", ID: CardSecGeoipCache, API: "geoip_cache", JSModule: "cards/geoip_cache.js", Renderer: "GeoIPCache"},
	{Key: "USER_MGMT", ID: CardSecUserMgmt, API: "user_mgmt", JSModule: "cards/user_mgmt.js", Renderer: "UserMgmt"},
	{Key: "AGENT_STATUS", ID: CardSecAgentStatus, API: "agent_status"},
	{Key: "VENDOR_DASHBOARD", ID: CardVendorDashboard, API: "vendor_dashboard", JSModule: "cards/vendor_dashboard.js", Renderer: "VendorDashboard"},
	{Key: "VENDOR_TENANTS", ID: CardVendorTenants, API: "vendor_tenants", JSModule: "cards/vendor_tenants.js", Renderer: "VendorTenants"},
	{Key: "VENDOR_AGENTS", ID: CardVendorAgents, API: "vendor_agents", JSModule: "cards/vendor_agents.js", Renderer: "VendorAgents"},
	{Key: "VENDOR_LICENSE_AUDIT", ID: CardVendorLicenseAudit, API: "vendor_license_audit", JSModule: "cards/vendor_license_audit.js", Renderer: "VendorLicenseAudit"},
	{Key: "VENDOR_AUDIT_LOG", ID: CardVendorAuditLog, API: "vendor_audit_log", JSModule: "cards/vendor_audit_log.js", Renderer: "VendorAuditLog"},
	{Key: "VENDOR_LICENSES", ID: CardVendorLicenses, API: "vendor_licenses", JSModule: "cards/vendor_licenses.js", Renderer: "VendorLicenses"},
	{Key: "VENDOR_LICENSE_OFFLINE", ID: CardVendorLicenseOffline, API: "vendor_license_offline", JSModule: "cards/vendor_license_offline.js", Renderer: "VendorLicenseOffline"},
	{Key: "VENDOR_LICENSE_ROTATION", ID: CardVendorLicenseRotation, API: "vendor_license_rotation", JSModule: "cards/vendor_license_rotation.js", Renderer: "VendorLicenseRotation"},
	{Key: "VENDOR_NC_OVERVIEW", ID: CardVendorNcOverview, API: "vendor_nc_overview", JSModule: "cards/vendor_nc_overview.js", Renderer: "VendorNcOverview"},
	{Key: "SSL", ID: CardSecSSL, API: "ssl", JSModule: "cards/ssl.js", Renderer: "SSL"},
	{Key: "VENDOR_SERVER_HEALTH", ID: CardVendorServerHealth, API: "vendor_server_health", JSModule: "cards/vendor_server_health.js", Renderer: "VendorServerHealth"},
}

// cardNav はカードの既定ナビ分類（グループ・表示順）を保持する。
// グループ/順序の真実源をここに一元化している。
// 以前は core/monitor/views.go の defaultMonitorCardNavMetaByID に二重定義されていた。
type cardNav struct {
	Group string
	Order int
}

var defaultCardNav = map[string]cardNav{
	CardSecAgentStatus:       {Group: "監視・運用", Order: 10},
	CardSecServices:          {Group: "監視・運用", Order: 20},
	CardSecUpdates:           {Group: "監視・運用", Order: 30},
	CardSecRealtimeMonitor:   {Group: "監視・運用", Order: 40},
	CardSecResources:         {Group: "監視・運用", Order: 50},
	CardSecResourceGraph:     {Group: "監視・運用", Order: 60},
	CardSecCPUTop:            {Group: "監視・運用", Order: 70},
	CardSecMemTop:            {Group: "監視・運用", Order: 80},
	CardSecCronStatus:        {Group: "監視・運用", Order: 90},
	CardSecNotificationRules: {Group: "監視・運用", Order: 100},
	CardSecSSL:               {Group: "監視・運用", Order: 110},

	CardSecDatabase:        {Group: "ストレージ・バックアップ", Order: 210},
	CardSecR2:              {Group: "ストレージ・バックアップ", Order: 220},
	CardSecNcStorage:       {Group: "ストレージ・バックアップ", Order: 230},
	CardSecStorageForecast: {Group: "ストレージ・バックアップ", Order: 240},

	CardSecIPMgmt:     {Group: "アクセス・防御", Order: 310},
	CardSecFail2ban:   {Group: "アクセス・防御", Order: 320},
	CardSecBanHeatmap: {Group: "アクセス・防御", Order: 330},

	CardSecSSHChart:        {Group: "攻撃分析・検知", Order: 410},
	CardSecHoneypotSummary: {Group: "攻撃分析・検知", Order: 420},
	CardSecHoneypotHeatmap: {Group: "攻撃分析・検知", Order: 430},
	CardSecHoneypotAccess:  {Group: "攻撃分析・検知", Order: 440},
	CardSecNc4xxAccess:     {Group: "攻撃分析・検知", Order: 450},
	CardSecNcHighScore:     {Group: "攻撃分析・検知", Order: 460},
	CardSecThreatScore:     {Group: "攻撃分析・検知", Order: 470},

	CardSecSSHLoginHistory: {Group: "ログ・監査", Order: 510},
	CardSecLoginHistory:    {Group: "ログ・監査", Order: 520},
	CardSecPhpmyadminLogin: {Group: "ログ・監査", Order: 530},
	CardSecNcLogin:         {Group: "ログ・監査", Order: 540},
	CardSecAuditAnomaly:    {Group: "ログ・監査", Order: 550},
	CardSecNginxHealth:     {Group: "ログ・監査", Order: 560},
	CardSecNginxLog:        {Group: "ログ・監査", Order: 570},
	CardSecGeoipCache:      {Group: "ログ・監査", Order: 580},

	CardSecUserMgmt: {Group: "管理", Order: 910},
}

// DefaultNavMeta はカードの既定グループと表示順を返す。
// 未登録カードは group="" / order=0 を返す（呼び出し側で order<=0 を 9999 等へ正規化する）。
func DefaultNavMeta(cardID string) (group string, order int) {
	if m, ok := defaultCardNav[cardID]; ok {
		return m.Group, m.Order
	}
	return "", 0
}

// TemplateNameFromID はカードIDから cards.html の define 名を導出する。
func TemplateNameFromID(id string) string {
	if id == "" {
		return ""
	}
	return "card-" + id
}

// MonitorCardByAPIKey は ?api= / /card?card= のキーからカード定義を返す。
func MonitorCardByAPIKey(api string) (MonitorCardMeta, bool) {
	for _, card := range monitorCardRegistry {
		if card.API == api {
			return card, true
		}
	}
	return MonitorCardMeta{}, false
}

// MonitorCardIDs は Key -> Card ID の辞書を返す。
func MonitorCardIDs() map[string]string {
	out := make(map[string]string, len(monitorCardRegistry))
	for _, card := range monitorCardRegistry {
		out[card.Key] = card.ID
	}
	return out
}

// MonitorAPIByCardID は Card ID -> API キーの辞書を返す（API未定義カードは除外）。
func MonitorAPIByCardID() map[string]string {
	out := make(map[string]string, len(monitorCardRegistry))
	for _, card := range monitorCardRegistry {
		if card.API == "" {
			continue
		}
		out[card.ID] = card.API
	}
	return out
}

var sharedLabelByID = map[string]string{
	CardSecServices:           "🟢 サービス稼働状況",
	CardSecUpdates:            "📦 システムアップデート",
	CardSecRealtimeMonitor:    "📡 リアルタイムモニター",
	CardSecResources:          "🖥️ システム・リソース情報",
	CardSecNotificationRules:  "📣 通知設定",
	CardSecResourceGraph:      "📈 リソース使用率 推移",
	CardSecCPUTop:             "⚡ CPU Top 3",
	CardSecMemTop:             "🧠 メモリ Top 3",
	CardSecCronStatus:         "⏱️ Cron 実行状況",
	CardSecDatabase:           "🗃️ バックアップ情報",
	CardSecR2:                 "☁️ Cloudflare R2",
	CardSecNcStorage:          "💽 Nextcloudストレージ",
	CardSecStorageForecast:    "📦 ストレージ逼迫予兆",
	CardSecIPMgmt:             "🔑 IP管理",
	CardSecFail2ban:           "🛡️ fail2ban状況",
	CardSecBanHeatmap:         "🔥 BANヒートマップ",
	CardSecSSHChart:           "📊 SSH攻撃 時間帯別",
	CardSecHoneypotSummary:    "🍯 ハニーポット概要",
	CardSecHoneypotHeatmap:    "🗺️ HPヒートマップ",
	CardSecHoneypotAccess:     "🚨 不審アクセス一覧",
	CardSecNc4xxAccess:        "🔍 NC 4xxアクセス",
	CardSecNcHighScore:        "⚠️ 要確認IP（高スコア・手動BAN候補）",
	CardSecThreatScore:        "🎯 脅威スコア",
	CardSecSSHLoginHistory:    "🔑 SSH / SFTP履歴",
	CardSecLoginHistory:       "✅ heartdeskログイン履歴",
	CardSecPhpmyadminLogin:    "🗄️ phpMyAdminログイン履歴",
	CardSecNcLogin:            "📋 Nextcloudログイン履歴",
	CardSecAuditAnomaly:       "🧪 監査ログ異常検知",
	CardSecNginxHealth:        "📊 Nginxヘルス",
	CardSecNginxLog:           "🌐 Nginxアクセスログ",
	CardSecGeoipCache:         "🌍 GeoIPキャッシュ",
	CardSecUserMgmt:           "👤 ユーザー管理",
	CardSecAgentStatus:        "🤖 Agent 死活監視",
	CardVendorDashboard:       "📊 Vendor Dashboard",
	CardVendorTenants:         "🏢 テナント × Agent ビュー",
	CardVendorAgents:          "🤖 Agent 一覧",
	CardVendorLicenseAudit:    "📋 ライセンス台帳監査",
	CardVendorAuditLog:        "🔍 監査ログ（集約）",
	CardVendorLicenses:        "🔑 ライセンス管理",
	CardVendorLicenseOffline:  "📴 オフラインライセンス発行",
	CardVendorLicenseRotation: "🔄 署名鍵ローテーション",
	CardVendorNcOverview:      "🌐 Nextcloud 運用監視",
	CardSecSSL:                "🔒 SSL 証明書",
	CardVendorServerHealth:    "🌡️ サーバー健全性",
}

// Label は共有ラベルを返す。未登録IDの場合は ok=false。
func Label(id string) (label string, ok bool) {
	label, ok = sharedLabelByID[id]
	return label, ok
}

// LabelOr は共有ラベルがあればそれを返し、なければ fallback を返す。
func LabelOr(id, fallback string) string {
	if label, ok := Label(id); ok {
		return label
	}
	return fallback
}

// LabelOrID は共有ラベルがあればそれを返し、なければ id を返す。
func LabelOrID(id string) string {
	if label, ok := Label(id); ok {
		return label
	}
	return id
}

// AllCardIDs は登録済み全カードIDのスライスを返す。
func AllCardIDs() []string {
	ids := make([]string, 0, len(monitorCardRegistry))
	for _, card := range monitorCardRegistry {
		ids = append(ids, card.ID)
	}
	return ids
}

// cardScreens はカードが表示される画面を定義する（開発者がカード追加時のみ変更）。
var cardScreens = map[string][]string{
	// Monitor 専用
	CardSecResources:          {"monitor"},
	CardSecFail2ban:           {"monitor"},
	CardSecServices:           {"monitor"},
	CardSecUpdates:            {"monitor"},
	CardSecIPMgmt:             {"monitor"},
	CardSecBanHeatmap:         {"monitor"},
	CardSecSSHChart:           {"monitor"},
	CardSecSSHLoginHistory:    {"monitor"},
	CardSecLoginHistory:       {"monitor"},
	CardSecPhpmyadminLogin:    {"monitor"},
	CardSecThreatScore:        {"monitor"},
	CardSecNcHighScore:        {"monitor"},
	CardSecHoneypotSummary:    {"monitor"},
	CardSecHoneypotHeatmap:    {"monitor"},
	CardSecHoneypotAccess:     {"monitor"},
	CardSecAuditAnomaly:       {"monitor"},
	CardSecNginxHealth:        {"monitor"},
	CardSecNginxLog:           {"monitor"},
	CardSecGeoipCache:         {"monitor"},
	CardSecUserMgmt:           {"monitor"},
	CardSecAgentStatus:        {"monitor"},
	CardSecRealtimeMonitor:    {"monitor"},
	CardSecResourceGraph:      {"monitor"},
	CardVendorDashboard:       {"vendor"},
	CardVendorTenants:         {"vendor"},
	CardVendorAgents:          {"vendor"},
	CardVendorLicenseAudit:    {"vendor"},
	CardVendorAuditLog:        {"vendor"},
	CardVendorLicenses:        {"vendor"},
	CardVendorLicenseOffline:  {"vendor"},
	CardVendorLicenseRotation: {"vendor"},
	CardVendorNcOverview:      {"vendor"},
	CardVendorServerHealth:    {"vendor"},
	CardSecSSL:                {"monitor"},
	CardSecStorageForecast:    {"monitor"},
	CardSecCPUTop:             {"monitor"},
	CardSecMemTop:             {"monitor"},
	CardSecNotificationRules:  {"monitor"},

	// Monitor + Admin 両方
	CardSecNcStorage:   {"monitor", "admin"},
	CardSecNcLogin:     {"monitor", "admin"},
	CardSecCronStatus:  {"monitor", "admin"},
	CardSecDatabase:    {"monitor", "admin"},
	CardSecR2:          {"monitor", "admin"},
	CardSecNc4xxAccess: {"monitor", "admin"},
}

// cardRequiredCapabilities はカード表示に必要な capability を定義する。
// capability が空のカードは agent に依存せず表示可能とみなす。
var cardRequiredCapabilities = map[string][]string{
	CardSecServices:          {"snapshot.services"},
	CardSecUpdates:           {"snapshot.updates"},
	CardSecRealtimeMonitor:   {"snapshot.resources"},
	CardSecResources:         {"snapshot.resources"},
	CardSecResourceGraph:     {"snapshot.resources"},
	CardSecCPUTop:            {"snapshot.process"},
	CardSecMemTop:            {"snapshot.process"},
	CardSecCronStatus:        {"snapshot.cron"},
	CardSecDatabase:          {"snapshot.backup"},
	CardSecR2:                {"snapshot.r2"},
	CardSecNcStorage:         {"module.nextcloud"},
	CardSecStorageForecast:   {"snapshot.resources"},
	CardSecIPMgmt:            {"action.ip_mgmt"},
	CardSecFail2ban:          {"snapshot.fail2ban", "event.fail2ban"},
	CardSecBanHeatmap:        {"event.fail2ban"},
	CardSecSSHChart:          {"event.ssh"},
	CardSecHoneypotSummary:   {"event.honeypot"},
	CardSecHoneypotHeatmap:   {"event.honeypot"},
	CardSecHoneypotAccess:    {"event.honeypot"},
	CardSecNc4xxAccess:       {"event.nextcloud"},
	CardSecNcHighScore:       {"score.threat"},
	CardSecThreatScore:       {"score.threat"},
	CardSecSSHLoginHistory:   {"event.ssh"},
	CardSecPhpmyadminLogin:   {"event.web_access"},
	CardSecNcLogin:           {"event.nextcloud"},
	CardSecAuditAnomaly:      {"event.nextcloud"},
	CardSecNginxHealth:       {"event.web_access"},
	CardSecNginxLog:          {"event.web_access"},
	CardSecNotificationRules: {"alert.notification"},
}

// cardRequiredComponents はカード表示に必要な config.toml [components] のコンポーネント名を定義する。
// 未登録（値なし）のカードはコンポーネントフラグに依存せず常時表示可能とみなす。
// agent 単位の capability 軸ではなくコンポーネント軸で表示可否を判定したいカード
// （特定の agent 画面ではなく Monitor 画面に出る連携カード等）に使う。
// 汎用カードにはこの紐付けを持つものが無いため、既定では空。
var cardRequiredComponents = map[string]string{}

// CardComponentEnabled はカードが属する config.toml [components] のコンポーネントが有効かを返す。
// 紐付けの無いカードは常に true（コンポーネントフラグに依存しない）。cfg が nil のときも
// config.AppConfig.ComponentEnabled の既定（未設定 = 有効）に従う。
func CardComponentEnabled(cardID string, cfg *config.AppConfig) bool {
	component, ok := cardRequiredComponents[cardID]
	if !ok || component == "" {
		return true
	}
	return cfg.ComponentEnabled(component)
}

// IsCardVisible は component / screen / capabilities の3軸でカード表示可否を判定する。
func IsCardVisible(cardID, agentID, screen string, cfg *config.AppConfig) bool {
	// 軸0: 無効化されたコンポーネントに属するカードは screen/capability 判定より前に落とす
	// （fail-closed）。config.toml [components] <name> = false のとき常に非表示。
	if !CardComponentEnabled(cardID, cfg) {
		return false
	}
	// 軸1: cardScreens にこの画面が含まれるか
	screens, ok := cardScreens[cardID]
	if !ok || !containsStr(screens, screen) {
		return false
	}
	// 軸2: card が要求する capabilities を agent が満たすか
	if agentID != "" {
		required := cardRequiredCapabilities[cardID]
		if len(required) > 0 {
			if cfg == nil || cfg.Agents == nil {
				return true
			}
			if _, ok := cfg.Agents[agentID]; !ok {
				return true
			}
			caps := cfg.AgentCapabilities(agentID)
			if !hasAllCapabilities(caps, required) {
				return false
			}
		}
	}
	return true
}

// VisibleCards は screen / agentID に応じた表示可能カード一覧を返す。
func VisibleCards(agentID, screen string, cfg *config.AppConfig) []MonitorCardMeta {
	result := make([]MonitorCardMeta, 0, len(monitorCardRegistry))
	for _, card := range monitorCardRegistry {
		if IsCardVisible(card.ID, agentID, screen, cfg) {
			result = append(result, card)
		}
	}
	return result
}

// VisibleJSModules は表示可能カードから JS モジュールパス一覧を重複排除して返す。
// レジストリの定義順を保持するため、同一 JSModule は初出のカード位置で登録する。
func VisibleJSModules(agentID, screen string, cfg *config.AppConfig) []string {
	seen := make(map[string]struct{}, len(monitorCardRegistry))
	modules := make([]string, 0, len(monitorCardRegistry))
	for _, card := range monitorCardRegistry {
		if card.JSModule == "" {
			continue
		}
		if !IsCardVisible(card.ID, agentID, screen, cfg) {
			continue
		}
		if _, ok := seen[card.JSModule]; ok {
			continue
		}
		seen[card.JSModule] = struct{}{}
		modules = append(modules, card.JSModule)
	}
	return modules
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func hasAllCapabilities(have, required []string) bool {
	if len(required) == 0 {
		return true
	}
	if len(have) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(have))
	for _, cap := range have {
		set[cap] = struct{}{}
	}
	for _, cap := range required {
		if _, ok := set[cap]; !ok {
			return false
		}
	}
	return true
}
