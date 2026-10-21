package monitor

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
	"github.com/ishizakahiroshi/heartdesk/internal/scheduler"
)

var monitorSimpleAPIByName = map[string]func() interface{}{
	"realtime_resources": func() interface{} { return APIRealtimeResources() },
	"login_history":      func() interface{} { return GetLoginHistory() },
	"geoip_cache":        func() interface{} { return GetGeoIPCache() },
}

// vendorOnlySimpleAPIByName は vendor_staff 限定の Monitor 単純 API。
var vendorOnlySimpleAPIByName = map[string]func() interface{}{
	"user_mgmt":         func() interface{} { return GetAuthzPolicyUsers() },
	"user_mgmt_catalog": func() interface{} { return GetAuthzCatalog() },
	"scheduler_states":  func() interface{} { return scheduler.SnapshotStates() },
}

// agentSimpleAPIByName は ?agent= を受け取る agentID 対応 API マップ
var agentSimpleAPIByName = map[string]func(agentID string) interface{}{
	"resources": func(id string) interface{} { return GetResources(id) },
	"processes": func(id string) interface{} { return GetProcesses(id) },
	"fail2ban":  func(id string) interface{} { return GetFail2ban(id) },
	"ip_mgmt":   func(id string) interface{} { return GetIPMgmt(id) },
	"updates":   func(id string) interface{} { return GetUpdatesData(id) },
	"ban_history": func(id string) interface{} {
		return GetBanHistory(id)
	},
	"cron_status": func(id string) interface{} {
		return GetCronStatus(id)
	},
	"ssh_login_history":        func(id string) interface{} { return GetSSHLoginHistory(id) },
	"phpmyadmin_login_history": func(id string) interface{} { return GetPhpMyAdminLoginHistory(id) },
	"nginx_login_histories":    func(id string) interface{} { return GetNginxLoginHistories(id) },
	"nc_login":                 func(id string) interface{} { return GetNCLoginHistory(id) },
	"audit_anomaly":            func(id string) interface{} { return GetAuditAnomaly(id) },
	"nginx_health":             func(id string) interface{} { return GetNginxHealth(id) },
	"ban_heatmap":              func(id string) interface{} { return GetBanHeatmap(id) },
	"ssh_chart":                func(id string) interface{} { return GetSSHChart(id) },
	"honeypot_summary":         func(id string) interface{} { return GetHoneypotSummary(id) },
	"honeypot_heatmap":         func(id string) interface{} { return GetHoneypotHeatmap(id) },
	"nc_high_score":            func(id string) interface{} { return GetNCHighScore(id) },
	"threat_score":             func(id string) interface{} { return GetThreatScore(id) },
}

// ---- GET APIディスパッチャ ----

// dispatchAPI は ?api=xxx に応じた JSON を返す
func (h *Handler) dispatchAPI(w http.ResponseWriter, r *http.Request, api string) {
	// config.toml の [components] で無効化されたコンポーネントに
	// 属する API は、認可判定やセッション有無に関わらず 404 で塞ぐ（fail-closed）。
	// CardModes の hidden（セッション単位の表示切替）とは独立した経路。10 個近い個別 API を
	// 直接書き換えず、既存の resolveCardIDForAPI（GET API → カード ID の唯一のマップ）を
	// 再利用してここ 1 か所で判定する。
	if cardID, mapped := resolveCardIDForAPI(api); mapped && !navmeta.CardComponentEnabled(cardID, h.appCfg) {
		http.NotFound(w, r)
		return
	}

	// Vendor Console 専用の GET API は ScreenVendor を持つセッションのみ許可し、
	// 未認可なら実 HTTP 403 を返す（各ハンドラで map{"error":"forbidden"} を返すと
	// json.Encode で HTTP 200 になってしまうため）。認可判定を requireVendorScreen 1 箇所に集約する。
	if isVendorAPI(api) {
		if !requireVendorScreen(w, r) {
			return
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// user_mgmt / catalog / scheduler_states は vendor_staff のみ。
	if handler, ok := vendorOnlySimpleAPIByName[api]; ok {
		if requireVendorStaff(w, r) {
			return
		}
		if err := json.NewEncoder(w).Encode(handler()); err != nil {
			log.Printf("ERROR: monitor: api/%s encode error: %v", api, err)
		}
		return
	}

	// カード ACL。未マップ API は合成 ID で fail-open しない。
	if sess, ok := auth.DefaultSessionManager().SessionFromRequest(r); ok {
		cardID, mapped := resolveCardIDForAPI(api)
		if !mapped {
			// 明示マップ外は vendor 専用 API 以外を拒否（未知キーのすり抜け防止）。
			// switch / map に存在するサブ API は resolveCardIDForAPI 側で親カードへマップする。
			if !isVendorAPI(api) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		} else if cardID != "" && normalizeCardModes(sess.CardModes)[cardID] == "hidden" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	// agentID 対応 API は ?agent= を読み取って渡す。
	// heartdesk 自身のサーバー（is_primary = true の agent）への要求はローカル実行と同等なので agentID="" 扱いにする。
	// default_agent は最初に表示する agent を決めるだけで、ここでは見ない（遠隔の agent を本体の値で表示しないため）。
	// ただし resource_graph は JSONL をエージェントID で引くため生の agentID を保持する。
	rawAgentID := strings.TrimSpace(r.URL.Query().Get("agent"))
	// ?agent= は最終的に eventJSONLPath / loadGraphReportsJSONL 等で
	// filepath.Join / filepath.Glob に連結されるため、パストラバーサル（../）や他テナント agent_id の
	// 指定を防ぐべく、空文字（=ローカル扱い）以外は ingestion 側と同じ厳格パターンで検証する。
	if rawAgentID != "" && !isValidAgentID(rawAgentID) {
		http.Error(w, `{"error":"invalid agent"}`, http.StatusBadRequest)
		return
	}
	// ?agent= を受ける API は agent_id 先頭の tenant prefix と
	// セッションテナントの一致を要求する（vendor_staff のみ bypass）。
	// 集約 Monitor で別テナントの agent_report を読み出される越境を塞ぐ。
	if rawAgentID != "" && !enforceAgentTenantBoundary(r, rawAgentID) {
		http.Error(w, `{"error":"forbidden agent"}`, http.StatusForbidden)
		return
	}
	agentID := rawAgentID
	if h.appCfg.IsLocalAgent(agentID) {
		agentID = ""
	}
	if handler, ok := agentSimpleAPIByName[api]; ok {
		if err := json.NewEncoder(w).Encode(handler(agentID)); err != nil {
			log.Printf("ERROR: monitor: api/%s encode error: %v", api, err)
		}
		return
	}

	// agent_overview はセッション tenant でフィルタ。
	if api == "agent_overview" {
		if err := json.NewEncoder(w).Encode(agentOverviewForRequest(r)); err != nil {
			log.Printf("ERROR: monitor: api/%s encode error: %v", api, err)
		}
		return
	}
	// agent_memo 一覧はカード非紐付けだが Monitor 画面権限下で許可（テナント横断メモは vendor 運用想定）。
	// 書込は action 側で agent_id 検証。
	if api == "agent_memo" {
		if err := json.NewEncoder(w).Encode(GetAgentMemoAll()); err != nil {
			log.Printf("ERROR: monitor: api/%s encode error: %v", api, err)
		}
		return
	}

	if handler, ok := monitorSimpleAPIByName[api]; ok {
		if err := json.NewEncoder(w).Encode(handler()); err != nil {
			log.Printf("ERROR: monitor: api/%s encode error: %v", api, err)
		}
		return
	}
	var data interface{}
	switch api {
	case "nc_storage":
		data = GetNcStorage(h.appCfg)
	case "r2_metrics":
		data = GetR2Metrics(h.appCfg, agentID)
	case "backups":
		data = GetBackupAPIData(h.appCfg, agentID)
	case "alert_rules":
		data = GetNotificationRulesAPIData(h.appCfg)
	case "disk":
		data = GetDisk(h.appCfg, agentID)
	case "services":
		data = GetServices(h.appCfg, agentID)
	case "ssl":
		data = GetSSL(h.appCfg, agentID)
	case "agent_status":
		data = GetAgentStatusForConfig(h.appCfg)
	case "resource_graph":
		rangeParam := strings.TrimSpace(r.URL.Query().Get("range"))
		data = GetResourceMetricsGraph(rawAgentID, rangeParam)
	case "nginx_log":
		limit := 10000
		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if n := parseIntParam(lStr, 10000); n > 0 && n <= 10000 {
				limit = n
			}
		}
		data = GetNginxStats(limit, agentID)
	case "nginx_url_detail":
		urlParam := r.URL.Query().Get("url")
		detailLimit := parseIntParam(r.URL.Query().Get("limit"), 200)
		if detailLimit <= 0 || detailLimit > 500 {
			detailLimit = 200
		}
		data = GetNginxURLDetail(urlParam, detailLimit, agentID)
	case "ban_heatmap_cell":
		jail := r.URL.Query().Get("jail")
		if jail == "" {
			jail = "all"
		}
		dow := parseIntParam(r.URL.Query().Get("dow"), -1)
		hour := parseIntParam(r.URL.Query().Get("hour"), -1)
		data = GetBanHeatmapCell(jail, dow, hour, agentID)
	case "honeypot_heatmap_cell":
		trigger := r.URL.Query().Get("trigger")
		if trigger == "" {
			trigger = "all"
		}
		dow := parseIntParam(r.URL.Query().Get("dow"), -1)
		hour := parseIntParam(r.URL.Query().Get("hour"), -1)
		data = GetHoneypotHeatmapCell(trigger, dow, hour, agentID)
	case "honeypot_access":
		days := parseIntParam(r.URL.Query().Get("days"), 7)
		if days < 1 || days > 30 {
			days = 7
		}
		limit := parseIntParam(r.URL.Query().Get("limit"), 1000)
		if limit < 200 || limit > 3000 {
			limit = 1000
		}
		data = GetHoneypotAccess(days, limit, agentID)
	case "honeypot_all":
		days := parseIntParam(r.URL.Query().Get("days"), 7)
		if days < 1 || days > 30 {
			days = 7
		}
		limit := parseIntParam(r.URL.Query().Get("limit"), 1000)
		if limit < 200 || limit > 3000 {
			limit = 1000
		}
		data = GetHoneypotAll(days, limit, agentID)
	case "nc4xx_access":
		days := parseIntParam(r.URL.Query().Get("days"), 1)
		limit := parseIntParam(r.URL.Query().Get("limit"), 500)
		data = GetNC4xxAccess(days, limit, agentID)
	case "threat_score_history":
		ip := r.URL.Query().Get("ip")
		data = GetThreatScoreHistory(ip, agentID)
	case "threat_event_history":
		ip := r.URL.Query().Get("ip")
		data = GetThreatEventHistory(ip, agentID)
	case "search_ip":
		ip := r.URL.Query().Get("ip")
		data = GetSearchIP(ip, agentID)
	case "vendor_dashboard":
		data = GetVendorDashboard(r, h.appCfg)
	case "vendor_tenants":
		data = GetVendorTenantsForRequest(r, h.appCfg)
	case "vendor_agents":
		data = GetVendorAgents(r, h.appCfg)
	case "vendor_license_audit":
		data = GetVendorLicenseAudit(r, h.appCfg)
	case "vendor_licenses":
		data = GetVendorLicenses(r, h.appCfg)
	case "vendor_license_offline":
		data = GetVendorLicenseOfflineConfig(r, h.appCfg)
	case "vendor_license_rotation":
		data = GetVendorLicenseRotation(r, h.appCfg)
	case "vendor_nc_overview":
		data = GetVendorNcOverview(r, h.appCfg)
	case "vendor_audit_log":
		data = GetVendorAuditLog(r, h.appCfg)
	case "vendor_server_health":
		data = GetVendorServerHealth(r, h.appCfg)
	default:
		http.Error(w, `{"error":"unknown api"}`, http.StatusNotFound)
		return
	}
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("ERROR: monitor: api/%s encode error: %v", api, err)
	}
}

// resolveCardIDForAPI は API キーからカード ID とマップ有無を返す。
// 未登録 API に合成 ID を返して CardModes すり抜け（常時許可）しない。
// cardID が空かつ mapped=true は「カード ACL 対象外だが明示許可」（agent_overview 等）。
func resolveCardIDForAPI(api string) (cardID string, mapped bool) {
	// レジストリ API キーとクエリキーが一致するものは優先。
	if card, ok := navmeta.MonitorCardByAPIKey(api); ok {
		return card.ID, true
	}
	// 別名・サブ API・レガシーキーの明示マップ（合成 ID は使わない）。
	switch api {
	case "backups", "disk":
		return navmeta.CardSecDatabase, true
	case "r2_metrics":
		return navmeta.CardSecR2, true
	case "alert_rules":
		return navmeta.CardSecNotificationRules, true
	case "realtime_resources":
		return navmeta.CardSecRealtimeMonitor, true
	case "login_history":
		return navmeta.CardSecLoginHistory, true
	case "phpmyadmin_login_history":
		return navmeta.CardSecPhpmyadminLogin, true
	case "ban_history":
		return navmeta.CardSecFail2ban, true
	case "ban_heatmap_cell":
		return navmeta.CardSecBanHeatmap, true
	case "honeypot_heatmap_cell", "honeypot_access":
		return navmeta.CardSecHoneypotSummary, true
	case "threat_score_history", "threat_event_history":
		return navmeta.CardSecThreatScore, true
	case "search_ip":
		return navmeta.CardSecIPMgmt, true
	case "nginx_url_detail":
		return navmeta.CardSecNginxLog, true
	case "agent_overview", "agent_memo", "scheduler_states":
		return "", true
	case "user_mgmt_catalog":
		return navmeta.CardSecUserMgmt, true
	}
	if isVendorAPI(api) {
		return "", true
	}
	return "", false
}

// ---- fail2ban アクション ----
