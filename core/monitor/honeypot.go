package monitor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

func hpLogDirPath() string { return heartdesk.Path("data/json/honeypot") }

var knownTriggers = []string{"dotfile", "wordpress", "db_tool", "microsoft", "framework", "backdoor", "query_string", "other"}

// hpRecord は JSONL ハニーポットログの1レコード
type hpRecord struct {
	Ts            string            `json:"ts"`
	IP            string            `json:"ip"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Query         string            `json:"query"`
	PostBody      string            `json:"post_body"`
	Trigger       string            `json:"trigger"`
	IsWhitelisted bool              `json:"is_whitelisted"`
	Headers       map[string]string `json:"headers"`
}

// HoneypotSummaryResponse は /api/monitor/honeypot_summary のレスポンス
type HoneypotSummaryResponse struct {
	Count24h     int                    `json:"count_24h"`
	Count7d      int                    `json:"count_7d"`
	Count30d     int                    `json:"count_30d"`
	UniqueIPs24h int                    `json:"unique_ips_24h"`
	NewIpsToday  int                    `json:"new_ips_today"`
	TopTriggers  []HoneypotTriggerCount `json:"top_triggers"`
}

// HoneypotTriggerCount はトリガー別件数
type HoneypotTriggerCount struct {
	Trigger string `json:"trigger"`
	Count   int    `json:"count"`
}

// HoneypotHeatmapResponse は /api/monitor/honeypot_heatmap のレスポンス
type HoneypotHeatmapResponse struct {
	Heatmap      map[string][][]int `json:"heatmap"`       // [trigger][dow=0-6][hour=0-23]
	HeatmapTotal [][]int            `json:"heatmap_total"` // [dow=0-6][hour=0-23]
	HeatmapMax   int                `json:"heatmap_max"`
}

// HoneypotAccessRecord は不審アクセス1件
type HoneypotAccessRecord struct {
	Ts            string `json:"ts"`
	IP            string `json:"ip"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	Query         string `json:"query"`
	UserAgent     string `json:"user_agent"`
	Device        string `json:"device"`
	UA            string `json:"ua"`
	PostBody      string `json:"post_body"`
	Referer       string `json:"referer"`
	Trigger       string `json:"trigger"`
	IsWhitelisted bool   `json:"is_whitelisted"`
	IsBanned      bool   `json:"is_banned"`
}

// HoneypotAccessResponse は /api/monitor/honeypot_access のレスポンス
type HoneypotAccessResponse struct {
	Records    []HoneypotAccessRecord `json:"records"`
	Total      int                    `json:"total"`
	Flags      map[string]string      `json:"flags"`
	DaysSpan   int                    `json:"days_span"`
	PeriodDays int                    `json:"period_days"`
	Limit      int                    `json:"limit"`
}

// HoneypotAllResponse は /api/monitor/honeypot_all のレスポンス
type HoneypotAllResponse struct {
	Summary HoneypotSummaryResponse `json:"summary"`
	Access  HoneypotAccessResponse  `json:"access"`
	Heatmap HoneypotHeatmapResponse `json:"heatmap"`
}

// hpReadRecords は指定開始時刻以降のレコードを読み込む（新しい順）
func hpReadRecords(sinceTs int64, agentID string) []hpRecord {
	if agentID != "" {
		return hpReadAgentRecords(sinceTs, agentID)
	}

	now := time.Now()
	var files []string
	for i := 0; i <= 1; i++ {
		ym := now.AddDate(0, -i, 0).Format("200601")
		f := fmt.Sprintf("%s/honeypot_%s.jsonl", hpLogDirPath(), ym)
		if _, err := os.Stat(f); err == nil {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return nil
	}

	var records []hpRecord
	// 古い順に読み込む
	for i := len(files) - 1; i >= 0; i-- {
		f, err := os.Open(files[i])
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 512*1024), 512*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			var r hpRecord
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				continue
			}
			if r.Ts == "" {
				continue
			}
			if sinceTs > 0 {
				ts, err := heartdesk.ParseTimestamp(r.Ts)
				if err != nil || ts.Unix() < sinceTs {
					continue
				}
			}
			records = append(records, r)
		}
		f.Close()
	}

	// 新しい順にソート
	sort.Slice(records, func(i, j int) bool {
		return records[i].Ts > records[j].Ts
	})
	return records
}

func hpReadAgentRecords(sinceTs int64, agentID string) []hpRecord {
	path := honeypotJSONLPath(agentID)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var records []hpRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 512*1024), 512*1024)
	for scanner.Scan() {
		var r hpRecord
		if json.Unmarshal(scanner.Bytes(), &r) != nil || r.Ts == "" {
			continue
		}
		if sinceTs > 0 {
			ts, err := heartdesk.ParseTimestamp(r.Ts)
			if err != nil || ts.Unix() < sinceTs {
				continue
			}
		}
		records = append(records, r)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Ts > records[j].Ts
	})
	return records
}

// hpBuildSummary は 30d レコードからサマリーを生成する
func hpBuildSummary(records []hpRecord) HoneypotSummaryResponse {
	now := time.Now().In(heartdesk.JST())
	ts24h := now.Add(-24 * time.Hour).Unix()
	ts7d := now.Add(-7 * 24 * time.Hour).Unix()
	todayYMD := now.Format("2006-01-02")

	count24h := 0
	count7d := 0
	uniqueIPs24h := make(map[string]bool)
	triggerCounts := make(map[string]int)
	ipsBefore := make(map[string]bool) // 今日より前に登場したIP

	for _, r := range records {
		ts, err := heartdesk.ParseTimestamp(r.Ts)
		if err != nil {
			continue
		}
		tsJST := ts.In(heartdesk.JST())
		unix := tsJST.Unix()
		if unix >= ts24h {
			count24h++
			if r.IP != "" {
				uniqueIPs24h[r.IP] = true
			}
		}
		if unix >= ts7d {
			count7d++
		}
		trig := r.Trigger
		if trig == "" {
			trig = "other"
		}
		triggerCounts[trig]++

		if r.IP != "" && tsJST.Format("2006-01-02") < todayYMD {
			ipsBefore[r.IP] = true
		}
	}

	// 今日の新規IP（今日登場した IP で、今日より前に出現がないもの）
	newIPsToday := make(map[string]bool)
	for _, r := range records {
		ts, err := heartdesk.ParseTimestamp(r.Ts)
		if err != nil {
			continue
		}
		tsJST := ts.In(heartdesk.JST())
		if r.IP != "" && tsJST.Format("2006-01-02") == todayYMD && !ipsBefore[r.IP] {
			newIPsToday[r.IP] = true
		}
	}

	// トリガー降順ソート
	type kv struct {
		k string
		v int
	}
	var pairs []kv
	for k, v := range triggerCounts {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].v > pairs[j].v
	})
	topTriggers := make([]HoneypotTriggerCount, 0, len(pairs))
	for _, p := range pairs {
		topTriggers = append(topTriggers, HoneypotTriggerCount{Trigger: p.k, Count: p.v})
	}

	return HoneypotSummaryResponse{
		Count24h:     count24h,
		Count7d:      count7d,
		Count30d:     len(records),
		UniqueIPs24h: len(uniqueIPs24h),
		NewIpsToday:  len(newIPsToday),
		TopTriggers:  topTriggers,
	}
}

// hpBuildHeatmap は直近7日のヒートマップを生成する
func hpBuildHeatmap(records []hpRecord) HoneypotHeatmapResponse {
	cutoff, _ := time.ParseInLocation("2006-01-02 15:04:05",
		time.Now().In(heartdesk.JST()).AddDate(0, 0, -6).Format("2006-01-02")+" 00:00:00",
		heartdesk.JST())
	cutoffUnix := cutoff.Unix()

	heatmap := make(map[string][][]int)
	for _, t := range knownTriggers {
		heatmap[t] = newHeatmap()
	}
	heatmapTotal := newHeatmap()
	maxVal := 0

	for _, r := range records {
		ts, err := heartdesk.ParseTimestamp(r.Ts)
		if err != nil || ts.Unix() < cutoffUnix {
			continue
		}
		tsJST := ts.In(heartdesk.JST())
		dow := int(tsJST.Weekday()+6) % 7 // 0=月..6=日
		hour := tsJST.Hour()
		trig := r.Trigger
		if trig == "" {
			trig = "other"
		}
		if _, ok := heatmap[trig]; !ok {
			heatmap[trig] = newHeatmap()
		}
		heatmap[trig][dow][hour]++
		heatmapTotal[dow][hour]++
		if heatmap[trig][dow][hour] > maxVal {
			maxVal = heatmap[trig][dow][hour]
		}
		if heatmapTotal[dow][hour] > maxVal {
			maxVal = heatmapTotal[dow][hour]
		}
	}

	// ゼロのトリガーを除去
	for _, t := range knownTriggers {
		sum := 0
		for d := 0; d < 7; d++ {
			for h := 0; h < 24; h++ {
				sum += heatmap[t][d][h]
			}
		}
		if sum == 0 {
			delete(heatmap, t)
		}
	}

	return HoneypotHeatmapResponse{
		Heatmap:      heatmap,
		HeatmapTotal: heatmapTotal,
		HeatmapMax:   maxVal,
	}
}

// GetActiveBannedIPsWithJail は fail2ban からアクティブな BAN 済み IP と jail 名の map を返す
var bannedIPListRe = regexp.MustCompile(`Banned IP list:\s*(.+)`)

func GetActiveBannedIPsWithJail(agentID string) map[string]string {
	if agentID != "" {
		events, _ := TailJSONL[F2BEvent](f2bJSONLPath(agentID), 50000)
		return f2bActiveBannedIPsWithJail(events)
	}
	result := make(map[string]string)
	for _, jail := range knownJails {
		out := heartdesk.RunArgs(10*time.Second, "sudo", "/usr/bin/fail2ban-client", "status", jail)
		if m := bannedIPListRe.FindStringSubmatch(out); m != nil {
			for _, ip := range strings.Fields(m[1]) {
				if ip != "" {
					result[ip] = jail
				}
			}
		}
	}
	return result
}

// getBannedIPs は fail2ban からアクティブな BAN 済み IP セットを返す
func getBannedIPs(agentID ...string) map[string]bool {
	withJail := GetActiveBannedIPsWithJail(normalizeAgentID(agentID))
	result := make(map[string]bool, len(withJail))
	for ip := range withJail {
		result[ip] = true
	}
	return result
}

// hpBuildAccess はアクセスリストを生成する
func hpBuildAccess(records []hpRecord, periodDays, limit int, banned map[string]bool) HoneypotAccessResponse {
	sinceUnix := time.Now().Unix() - int64(periodDays)*86400

	var filtered []hpRecord
	for _, r := range records {
		ts, err := heartdesk.ParseTimestamp(r.Ts)
		if err != nil || ts.Unix() < sinceUnix {
			continue
		}
		filtered = append(filtered, r)
		if len(filtered) >= limit {
			break
		}
	}

	// days_span 計算
	minTs, maxTs := int64(0), int64(0)
	for _, r := range filtered {
		ts, err := heartdesk.ParseTimestamp(r.Ts)
		if err != nil {
			continue
		}
		unix := ts.Unix()
		if minTs == 0 || unix < minTs {
			minTs = unix
		}
		if unix > maxTs {
			maxTs = unix
		}
	}
	daysSpan := 0
	if minTs > 0 && maxTs > 0 {
		daysSpan = int((maxTs-minTs)/86400) + 1
	}

	// ユニークIP の国旗取得
	ipSet := make(map[string]bool)
	for _, r := range filtered {
		if r.IP != "" && r.IP != "127.0.0.1" {
			ipSet[r.IP] = true
		}
	}
	var uniqueIPs []string
	for ip := range ipSet {
		uniqueIPs = append(uniqueIPs, ip)
	}
	flags := GetCountryFlags(uniqueIPs)

	result := make([]HoneypotAccessRecord, 0, len(filtered))
	for _, r := range filtered {
		ua := ""
		referer := ""
		if r.Headers != nil {
			ua = r.Headers["user-agent"]
			referer = r.Headers["referer"]
		}
		uaInfo := parseUserAgent(ua)
		trig := r.Trigger
		if trig == "" {
			trig = "other"
		}
		// タイムスタンプを JST 表示形式に変換
		tsDisplay := r.Ts
		if t, err := heartdesk.ParseTimestamp(r.Ts); err == nil {
			tsDisplay = heartdesk.FormatDatetime(t.In(heartdesk.JST()))
		}
		result = append(result, HoneypotAccessRecord{
			Ts:            tsDisplay,
			IP:            r.IP,
			Method:        r.Method,
			Path:          r.Path,
			Query:         r.Query,
			UserAgent:     ua,
			Device:        uaInfo.Device,
			UA:            uaInfo.Label,
			PostBody:      r.PostBody,
			Referer:       referer,
			Trigger:       trig,
			IsWhitelisted: r.IsWhitelisted,
			IsBanned:      banned[r.IP],
		})
	}

	return HoneypotAccessResponse{
		Records:    result,
		Total:      len(result),
		Flags:      flags,
		DaysSpan:   daysSpan,
		PeriodDays: periodDays,
		Limit:      limit,
	}
}

// uaInfo は UA パース結果
type uaInfo struct {
	Device string
	Label  string
}

// parseUserAgent は UA 文字列をパースして device/label を返す (PHP parse_user_agent_info() 相当)
func parseUserAgent(ua string) uaInfo {
	if ua == "" || ua == "-" {
		return uaInfo{Device: "unknown", Label: "UA不明"}
	}

	// Nextcloud クライアント（正規表現は ua.go のパッケージ変数を再利用）
	if m := reNCAndroid.FindStringSubmatch(ua); m != nil {
		return uaInfo{Device: "mobile", Label: "Nextcloud Android " + m[1]}
	}
	if m := reNCIOS.FindStringSubmatch(ua); m != nil {
		return uaInfo{Device: "mobile", Label: "Nextcloud iOS " + m[1]}
	}
	if m := reMirall.FindStringSubmatch(ua); m != nil {
		return uaInfo{Device: "pc", Label: "Nextcloud Desktop " + m[1]}
	}
	if strings.Contains(strings.ToLower(ua), "nextcloud-talk") {
		return uaInfo{Device: "mobile", Label: "Nextcloud Talk"}
	}

	// セキュリティスキャナ
	scanners := map[string]string{
		"nuclei": "Nuclei", "zgrab": "zgrab", "masscan": "masscan", "nikto": "Nikto",
		"sqlmap": "sqlmap", "nmap": "Nmap", "shodan": "Shodan", "censys": "Censys",
		"acunetix": "Acunetix", "dirbuster": "DirBuster", "gobuster": "Gobuster",
		"wfuzz": "WFuzz", "burp": "Burp Suite", "metasploit": "Metasploit",
		"nessus": "Nessus", "openvas": "OpenVAS",
	}
	uaLower := strings.ToLower(ua)
	for key, label := range scanners {
		if strings.Contains(uaLower, key) {
			return uaInfo{Device: "scanner", Label: label}
		}
	}

	// HTTP ツール（正規表現は ua.go のパッケージ変数を再利用）
	if m := reCurl.FindStringSubmatch(ua); m != nil {
		return uaInfo{Device: "tool", Label: "curl " + m[1]}
	}
	if m := reWget.FindStringSubmatch(ua); m != nil {
		return uaInfo{Device: "tool", Label: "wget " + m[1]}
	}
	if rePyReq.MatchString(ua) {
		return uaInfo{Device: "tool", Label: "Python-requests"}
	}
	if strings.Contains(uaLower, "python") {
		return uaInfo{Device: "tool", Label: "Python"}
	}
	if strings.Contains(uaLower, "go-http") {
		return uaInfo{Device: "tool", Label: "Go-http"}
	}
	if strings.Contains(uaLower, "java/") {
		return uaInfo{Device: "tool", Label: "Java"}
	}

	// OS 判定
	os := ""
	switch {
	case strings.Contains(ua, "iPhone"):
		os = "iPhone"
	case strings.Contains(ua, "iPad"):
		os = "iPad"
	case strings.Contains(ua, "Android"):
		os = "Android"
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "Mac OS X") || strings.Contains(ua, "Macintosh"):
		os = "macOS"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	}

	// ブラウザ判定（正規表現は ua.go のパッケージ変数を再利用。順序重要: Edge → Opera → Firefox → Chrome → Safari）
	br := ""
	switch {
	case reEdge.MatchString(ua):
		if m := reEdge.FindStringSubmatch(ua); m != nil {
			br = "Edge " + majorVersion(m[1])
		}
	case reOpera.MatchString(ua):
		if m := reOpera.FindStringSubmatch(ua); m != nil {
			br = "Opera " + majorVersion(m[1])
		}
	case reFirefox.MatchString(ua):
		if m := reFirefox.FindStringSubmatch(ua); m != nil {
			br = "Firefox " + majorVersion(m[1])
		}
	case reChrome.MatchString(ua):
		if m := reChrome.FindStringSubmatch(ua); m != nil {
			br = "Chrome " + majorVersion(m[1])
		}
	case reSafari.MatchString(ua):
		if m := reSafari.FindStringSubmatch(ua); m != nil {
			br = "Safari " + majorVersion(m[1])
		}
	}

	isMobile := os == "iPhone" || os == "iPad" || os == "Android" || strings.Contains(ua, "Mobile")
	device := "unknown"
	if isMobile {
		device = "mobile"
	} else if br != "" || os != "" {
		device = "pc"
	}

	label := br
	if label == "" {
		label = "その他"
	}
	if os != "" {
		label += " / " + os
	}

	return uaInfo{Device: device, Label: label}
}

// GetHoneypotSummary は 30d レコードから概要を返す
func GetHoneypotSummary(agentID ...string) HoneypotSummaryResponse {
	since := time.Now().Add(-30 * 24 * time.Hour).Unix()
	records := hpReadRecords(since, normalizeAgentID(agentID))
	return hpBuildSummary(records)
}

// GetHoneypotHeatmap は直近7日のヒートマップを返す
func GetHoneypotHeatmap(agentID ...string) HoneypotHeatmapResponse {
	since := time.Now().In(heartdesk.JST()).AddDate(0, 0, -6).Truncate(24 * time.Hour).Unix()
	records := hpReadRecords(since, normalizeAgentID(agentID))
	return hpBuildHeatmap(records)
}

// GetHoneypotAccess は不審アクセス一覧を返す
func GetHoneypotAccess(periodDays, limit int, agentID ...string) HoneypotAccessResponse {
	id := normalizeAgentID(agentID)
	since := time.Now().Add(-time.Duration(periodDays) * 24 * time.Hour).Unix()
	records := hpReadRecords(since, id)
	return hpBuildAccess(records, periodDays, limit, getBannedIPs(id))
}

// HoneypotHeatmapCellEntry はヒートマップセル詳細1件
type HoneypotHeatmapCellEntry struct {
	Ts      string `json:"ts"`
	IP      string `json:"ip"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Trigger string `json:"trigger"`
	UA      string `json:"ua"`
}

// HoneypotHeatmapCellResponse はヒートマップセル詳細レスポンス
type HoneypotHeatmapCellResponse struct {
	Entries []HoneypotHeatmapCellEntry `json:"entries"`
	Total   int                        `json:"total"`
	Flags   map[string]string          `json:"flags"`
}

// GetHoneypotHeatmapCell は指定セル（dow/hour/trigger）の詳細アクセスを返す
func GetHoneypotHeatmapCell(trigger string, dow, hour int, agentID ...string) HoneypotHeatmapCellResponse {
	if dow < 0 || dow > 6 || hour < 0 || hour > 23 {
		return HoneypotHeatmapCellResponse{Entries: []HoneypotHeatmapCellEntry{}, Flags: map[string]string{}}
	}
	cutoff := time.Now().In(heartdesk.JST()).AddDate(0, 0, -6).Truncate(24 * time.Hour)
	records := hpReadRecords(cutoff.Unix(), normalizeAgentID(agentID))

	var entries []HoneypotHeatmapCellEntry
	ipSet := make(map[string]bool)
	for _, r := range records {
		ts, err := heartdesk.ParseTimestamp(r.Ts)
		if err != nil {
			continue
		}
		tsJST := ts.In(heartdesk.JST())
		rDow := int(tsJST.Weekday()+6) % 7
		if rDow != dow || tsJST.Hour() != hour {
			continue
		}
		rTrig := r.Trigger
		if rTrig == "" {
			rTrig = "other"
		}
		if trigger != "all" && rTrig != trigger {
			continue
		}
		ua := ""
		if r.Headers != nil {
			ua = r.Headers["user-agent"]
		}
		path := r.Path
		if r.Query != "" {
			path += "?" + r.Query
		}
		tsDisplay := r.Ts
		if t, err2 := heartdesk.ParseTimestamp(r.Ts); err2 == nil {
			tsDisplay = heartdesk.FormatDatetime(t.In(heartdesk.JST()))
		}
		entries = append(entries, HoneypotHeatmapCellEntry{
			Ts:      tsDisplay,
			IP:      r.IP,
			Method:  r.Method,
			Path:    path,
			Trigger: rTrig,
			UA:      ua,
		})
		if r.IP != "" && r.IP != "127.0.0.1" {
			ipSet[r.IP] = true
		}
	}

	var uniqueIPs []string
	for ip := range ipSet {
		uniqueIPs = append(uniqueIPs, ip)
	}
	flags := GetCountryFlags(uniqueIPs)

	if entries == nil {
		entries = []HoneypotHeatmapCellEntry{}
	}
	return HoneypotHeatmapCellResponse{
		Entries: entries,
		Total:   len(entries),
		Flags:   flags,
	}
}

// GetHoneypotAll はサマリー・アクセス・ヒートマップを1回のI/Oで返す
func GetHoneypotAll(periodDays, limit int, agentID ...string) HoneypotAllResponse {
	id := normalizeAgentID(agentID)
	since30d := time.Now().Add(-30 * 24 * time.Hour).Unix()
	records := hpReadRecords(since30d, id)
	return HoneypotAllResponse{
		Summary: hpBuildSummary(records),
		Access:  hpBuildAccess(records, periodDays, limit, getBannedIPs(id)),
		Heatmap: hpBuildHeatmap(records),
	}
}
