package monitor

import (
	"fmt"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

// =============================================================================
// Nginx アクセスログ（nginx_log カード）
// =============================================================================

// NginxLogItem は1件のNginxアクセスログエントリ（PHP nginx_stats API 互換）
type NginxLogItem struct {
	IP      string `json:"ip"`
	Time    string `json:"time"`    // RFC3339 タイムスタンプ（logs/nginx.jsonl の ts フィールド）
	Request string `json:"request"` // "GET /path" 形式（PHP の request フィールド互換）
	Status  string `json:"status"`  // "200" 等の文字列（PHP 互換）
	Size    string `json:"size"`    // "1234" 等の文字列（PHP 互換）
	Port    string `json:"port"`    // 未使用（互換性のため残す）
}

// NginxLogRate は直近/前30分のアクセス率情報（PHP nginx_stats rate フィールド互換）
type NginxLogRate struct {
	WindowMin int      `json:"window_min"` // 30
	Recent    int      `json:"recent"`     // 直近30分の件数
	Prev      int      `json:"prev"`       // 前30分の件数
	Ratio     *float64 `json:"ratio"`      // recent/prev（nil if prev==0）
	Delta     int      `json:"delta"`      // recent - prev
}

// NginxStatsResponse は /api/monitor/nginx_log の JSON レスポンス（PHP nginx_stats 互換）
type NginxStatsResponse struct {
	Logs  []NginxLogItem    `json:"logs"`
	Flags map[string]string `json:"flags"`
	Rate  NginxLogRate      `json:"rate"`
}

// GetNginxStats は logs/nginx.jsonl の最新エントリを返す（PHP nginx_stats API 互換）
func GetNginxStats(limit int, agentID ...string) NginxStatsResponse {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}

	events, _ := TailJSONL[NginxLogEvent](webAccessJSONLPath(agentID...), 20000)
	if len(events) == 0 {
		return NginxStatsResponse{
			Logs:  []NginxLogItem{},
			Flags: map[string]string{},
			Rate:  NginxLogRate{WindowMin: 30},
		}
	}

	// 最新優先に逆順
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}

	now := time.Now()
	cutRecent := now.Add(-30 * time.Minute).Unix()
	cutPrev := now.Add(-60 * time.Minute).Unix()
	rateRecent := 0
	ratePrev := 0

	var items []NginxLogItem
	ipSet := map[string]struct{}{}

	for _, ev := range events {
		t, err := time.Parse(time.RFC3339, ev.TS)
		if err == nil {
			unix := t.Unix()
			if unix >= cutRecent {
				rateRecent++
			} else if unix >= cutPrev {
				ratePrev++
			}
		}

		if len(items) < limit {
			items = append(items, NginxLogItem{
				IP:      ev.IP,
				Time:    ev.TS,
				Request: ev.Method + " " + ev.Path,
				Status:  fmt.Sprintf("%d", ev.Status),
				Size:    fmt.Sprintf("%d", ev.Bytes),
				Port:    "",
			})
		}
		if ev.IP != "" && ev.IP != "127.0.0.1" {
			ipSet[ev.IP] = struct{}{}
		}
	}
	if items == nil {
		items = []NginxLogItem{}
	}

	ipList := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ipList = append(ipList, ip)
	}
	flags := GetCountryFlags(ipList)

	rate := NginxLogRate{
		WindowMin: 30,
		Recent:    rateRecent,
		Prev:      ratePrev,
		Delta:     rateRecent - ratePrev,
	}
	if ratePrev > 0 {
		ratio := roundFloat(float64(rateRecent)/float64(ratePrev), 2)
		rate.Ratio = &ratio
	}

	return NginxStatsResponse{
		Logs:  items,
		Flags: flags,
		Rate:  rate,
	}
}

// roundFloat は小数点以下 precision 桁で四捨五入する
func roundFloat(v float64, precision int) float64 {
	pow := 1.0
	for i := 0; i < precision; i++ {
		pow *= 10
	}
	return float64(int(v*pow+0.5)) / pow
}

// =============================================================================
// Nginx URL 詳細（nginx_url_detail API）
// =============================================================================

// NginxURLDetailEntry は1件の詳細ログエントリ（PHP nginx_url_detail API 互換）
type NginxURLDetailEntry struct {
	Time    string `json:"time"` // "2026-04-17 12:34:56"
	IP      string `json:"ip"`
	Method  string `json:"method"`
	Status  int    `json:"status"`
	Path    string `json:"path"`
	Referer string `json:"referer"`
	UA      string `json:"ua"`
}

// NginxURLDetailTopIP は上位IPとアクセス件数
type NginxURLDetailTopIP struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// NginxURLDetailResponse は /api/monitor/nginx_url_detail のレスポンス（PHP 互換）
type NginxURLDetailResponse struct {
	URL          string                `json:"url"`
	Window       string                `json:"window"`
	Cutoff       string                `json:"cutoff"`
	Total        int                   `json:"total"`
	ByStatus     map[string]int        `json:"by_status"`
	TopIPs       []NginxURLDetailTopIP `json:"top_ips"`
	Entries      []NginxURLDetailEntry `json:"entries"`
	Flags        map[string]string     `json:"flags"`
	IsJapanFlags map[string]bool       `json:"is_japan_flags"`
}

// GetNginxURLDetail は特定URLの直近24時間のエラーログ詳細を返す（PHP nginx_url_detail API 互換）
func GetNginxURLDetail(targetURL string, limit int, agentID ...string) NginxURLDetailResponse {
	empty := func() NginxURLDetailResponse {
		return NginxURLDetailResponse{
			URL: targetURL, ByStatus: map[string]int{},
			TopIPs: []NginxURLDetailTopIP{}, Entries: []NginxURLDetailEntry{},
			Flags: map[string]string{}, IsJapanFlags: map[string]bool{},
		}
	}
	if targetURL == "" || targetURL[0] != '/' || len(targetURL) > 300 {
		return empty()
	}
	for _, c := range targetURL {
		if c <= 0x1F || c == 0x7F || c == ' ' {
			return empty()
		}
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	now := time.Now()
	cut24h := now.Add(-24 * time.Hour)
	cutUnix := cut24h.Unix()

	events, _ := TailJSONL[NginxLogEvent](webAccessJSONLPath(agentID...), 25000)

	var entries []NginxURLDetailEntry
	byStatus := map[string]int{}
	byIP := map[string]int{}
	var ipList []string

	for _, ev := range events {
		if ev.Status < 400 {
			continue
		}
		pathNoQ := strings.SplitN(ev.Path, "?", 2)[0]
		if pathNoQ != targetURL {
			continue
		}
		t, err := time.Parse(time.RFC3339, ev.TS)
		if err != nil || t.Unix() < cutUnix {
			continue
		}

		statusStr := fmt.Sprintf("%d", ev.Status)
		byStatus[statusStr]++
		byIP[ev.IP]++

		entries = append(entries, NginxURLDetailEntry{
			Time:    t.In(heartdesk.JST()).Format("2006-01-02 15:04:05"),
			IP:      ev.IP,
			Method:  ev.Method,
			Status:  ev.Status,
			Path:    ev.Path,
			Referer: ev.Referer,
			UA:      ev.UA,
		})
		ipList = append(ipList, ev.IP)
	}

	// 新しい順ソート
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	if len(entries) > limit {
		entries = entries[:limit]
	}

	// 上位IP（最大10件）
	type ipCount struct {
		ip    string
		count int
	}
	ipCounts := make([]ipCount, 0, len(byIP))
	for ip, c := range byIP {
		ipCounts = append(ipCounts, ipCount{ip, c})
	}
	for i := 0; i < len(ipCounts); i++ {
		for j := i + 1; j < len(ipCounts); j++ {
			if ipCounts[j].count > ipCounts[i].count {
				ipCounts[i], ipCounts[j] = ipCounts[j], ipCounts[i]
			}
		}
	}
	topIPs := make([]NginxURLDetailTopIP, 0, 10)
	for _, ic := range ipCounts {
		if len(topIPs) >= 10 {
			break
		}
		topIPs = append(topIPs, NginxURLDetailTopIP{IP: ic.ip, Count: ic.count})
	}

	ipSeen := map[string]struct{}{}
	var uniqIPs []string
	for _, ip := range ipList {
		if ip == "127.0.0.1" || ip == "::1" {
			continue
		}
		if _, seen := ipSeen[ip]; !seen {
			ipSeen[ip] = struct{}{}
			uniqIPs = append(uniqIPs, ip)
		}
	}

	flags := GetCountryFlags(uniqIPs)
	isJapanFlags := make(map[string]bool, len(uniqIPs))
	for _, ip := range uniqIPs {
		isJapanFlags[ip] = strings.Contains(flags[ip], "日本")
	}

	if entries == nil {
		entries = []NginxURLDetailEntry{}
	}
	if topIPs == nil {
		topIPs = []NginxURLDetailTopIP{}
	}

	return NginxURLDetailResponse{
		URL:          targetURL,
		Window:       "24h",
		Cutoff:       cut24h.Format("2006-01-02 15:04:05"),
		Total:        len(entries),
		ByStatus:     byStatus,
		TopIPs:       topIPs,
		Entries:      entries,
		Flags:        flags,
		IsJapanFlags: isJapanFlags,
	}
}

// ---- 後方互換（export 用）----

// NginxLogEntry は旧 API 型（export.go が参照するため残す）
type NginxLogEntry struct {
	IP      string `json:"ip"`
	User    string `json:"user"`
	Time    string `json:"time"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Status  int    `json:"status"`
	Size    int    `json:"size"`
	UA      string `json:"ua"`
	Device  string `json:"device"`
	UALabel string `json:"ua_label"`
}

// NginxLogResponse は旧 API レスポンス型（export.go が参照するため残す）
type NginxLogResponse struct {
	Entries []NginxLogEntry `json:"entries"`
	Total   int             `json:"total"`
}

// GetNginxLog は export.go 用の旧 API（最大500件）
func GetNginxLog(limit int, agentID ...string) NginxLogResponse {
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	events, _ := TailJSONL[NginxLogEvent](webAccessJSONLPath(agentID...), limit*2)
	if len(events) == 0 {
		return NginxLogResponse{Entries: []NginxLogEntry{}, Total: 0}
	}
	// 最新優先
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}

	var entries []NginxLogEntry
	for _, ev := range events {
		uaInfo := ParseUA(ev.UA)
		displayTime := ev.TS
		if t, err := time.Parse(time.RFC3339, ev.TS); err == nil {
			displayTime = heartdesk.FormatDatetime(t.In(heartdesk.JST()))
		}
		entries = append(entries, NginxLogEntry{
			IP:      ev.IP,
			User:    "",
			Time:    displayTime,
			Method:  ev.Method,
			Path:    ev.Path,
			Status:  ev.Status,
			Size:    ev.Bytes,
			UA:      ev.UA,
			Device:  uaInfo.Device,
			UALabel: uaInfo.Label,
		})
		if len(entries) >= limit {
			break
		}
	}
	if entries == nil {
		entries = []NginxLogEntry{}
	}
	return NginxLogResponse{Entries: entries, Total: len(entries)}
}
