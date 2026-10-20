package monitor

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

func threatScoreCSVPath() string {
	return sab.SabPath("data/csv/threat_score.csv")
}
func threatScoreHistoryCSVPath() string {
	return sab.SabPath("data/csv/threat_score_history.csv")
}
func scoreConfigJSONPath() string {
	return sab.SabPath("data/json/score_config.json")
}
func dismissJSONPath() string {
	return sab.SabPath("data/json/nc_high_score_dismiss.json")
}

// ThreatScoreEntry は脅威スコアの1エントリ
type ThreatScoreEntry struct {
	Timestamp     string `json:"timestamp"`
	IP            string `json:"ip"`
	Score         int    `json:"score"`
	SSHFails      int    `json:"ssh_fails"`
	ScanHits      int    `json:"scan_hits"`
	ScanCriticals int    `json:"scan_criticals"`
	AuthFails     int    `json:"auth_fails"`
	NCFails       int    `json:"nc_fails"`
	NC4xx         int    `json:"nc_4xx"`
	IsBanned      int    `json:"is_banned"`
	IsForeign     int    `json:"is_foreign"`
}

// ThreatScoreConfig は脅威スコアの設定（閾値・重み）
type ThreatScoreConfig struct {
	Thresholds struct {
		Warning int `json:"warning"`
		Danger  int `json:"danger"`
	} `json:"thresholds"`
	Weights map[string]int `json:"weights,omitempty"`
}

// ThreatScoreResponse は /nab/api/monitor/threat_score のレスポンス
type ThreatScoreResponse struct {
	Scores []ThreatScoreEntry `json:"scores"`
	Flags  map[string]string  `json:"flags"`
	Count  int                `json:"count"`
	Config ThreatScoreConfig  `json:"config"`
}

type threatCollectorResult struct {
	Entries []struct {
		Timestamp string `json:"timestamp"`
		IP        string `json:"ip"`
		Score     int    `json:"score"`
		ScanHits  int    `json:"scan_hits"`
		ScanCrits int    `json:"scan_criticals"`
		AuthFails int    `json:"auth_fails"`
		NcFails   int    `json:"nc_fails"`
		Nc4xx     int    `json:"nc_4xx"`
		IsBanned  bool   `json:"is_banned"`
		IsForeign bool   `json:"is_foreign"`
	} `json:"entries"`
}

// NCHighScoreResponse は /nab/api/monitor/nc_high_score のレスポンス
type NCHighScoreResponse struct {
	Scores []ThreatScoreEntry `json:"scores"`
	Flags  map[string]string  `json:"flags"`
	Count  int                `json:"count"`
}

// loadScoreConfig は score_config.json を読み込んで閾値を返す（デフォルト: 警告50, 危険100）
func loadScoreConfig() ThreatScoreConfig {
	cfg := ThreatScoreConfig{}
	cfg.Thresholds.Warning = 50
	cfg.Thresholds.Danger = 100

	raw, err := os.ReadFile(scoreConfigJSONPath())
	if err != nil {
		return cfg
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return cfg
	}
	if v, ok := obj["warning_threshold"]; ok {
		cfg.Thresholds.Warning = toInt(v)
	}
	if v, ok := obj["danger_threshold"]; ok {
		cfg.Thresholds.Danger = toInt(v)
	}
	if v, ok := obj["weights"]; ok {
		if wm, ok := v.(map[string]interface{}); ok {
			cfg.Weights = make(map[string]int, len(wm))
			for k, wv := range wm {
				cfg.Weights[k] = toInt(wv)
			}
		}
	}
	return cfg
}

// toInt は interface{} を int に変換する
func toInt(v interface{}) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}

// parseThreatScoreCSV は threat_score.csv を読み込んでエントリ一覧を返す
func parseThreatScoreCSV() []ThreatScoreEntry {
	f, err := os.Open(threatScoreCSVPath())
	if err != nil {
		return nil
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.TrimLeadingSpace = true

	header, err := r.Read()
	if err != nil {
		return nil
	}

	// v3 判定: header[3] == "scan_hits"
	isV3 := len(header) > 3 && strings.TrimSpace(header[3]) == "scan_hits"

	var entries []ThreatScoreEntry
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		e := ThreatScoreEntry{}
		if isV3 {
			// v3: timestamp, ip, score, scan_hits, scan_criticals, auth_fails, nc_fails, nc_4xx, is_banned, is_foreign
			if len(row) < 10 {
				continue
			}
			e.Timestamp = strings.TrimSpace(row[0])
			e.IP = strings.TrimSpace(row[1])
			e.Score = atoiTrim(row[2])
			e.SSHFails = 0
			e.ScanHits = atoiTrim(row[3])
			e.ScanCriticals = atoiTrim(row[4])
			e.AuthFails = atoiTrim(row[5])
			e.NCFails = atoiTrim(row[6])
			e.NC4xx = atoiTrim(row[7])
			e.IsBanned = atoiTrim(row[8])
			e.IsForeign = atoiTrim(row[9])
		} else {
			// v2/v1: timestamp, ip, score, ssh_fails, scan_hits, [scan_criticals], auth_fails, nc_fails, [nc_4xx], is_banned, is_foreign
			if len(row) < 9 {
				continue
			}
			isNewV2 := len(row) >= 11
			isNewV1 := len(row) >= 10
			e.Timestamp = strings.TrimSpace(row[0])
			e.IP = strings.TrimSpace(row[1])
			e.Score = atoiTrim(row[2])
			e.SSHFails = atoiTrim(row[3])
			e.ScanHits = atoiTrim(row[4])
			if isNewV1 || isNewV2 {
				e.ScanCriticals = atoiTrim(row[5])
			}
			if isNewV2 {
				e.AuthFails = atoiTrim(row[6])
				e.NCFails = atoiTrim(row[7])
				e.NC4xx = atoiTrim(row[8])
				e.IsBanned = atoiTrim(row[9])
				e.IsForeign = atoiTrim(row[10])
			} else if isNewV1 {
				e.AuthFails = atoiTrim(row[6])
				e.NCFails = atoiTrim(row[7])
				e.IsBanned = atoiTrim(row[8])
				e.IsForeign = atoiTrim(row[9])
			} else {
				e.AuthFails = atoiTrim(row[5])
				e.NCFails = atoiTrim(row[6])
				e.IsBanned = atoiTrim(row[7])
				e.IsForeign = atoiTrim(row[8])
			}
		}
		entries = append(entries, e)
	}
	return entries
}

func parseThreatScoreEntries(agentID ...string) []ThreatScoreEntry {
	id := normalizeAgentID(agentID)
	if id == "" {
		return parseThreatScoreCSV()
	}

	raw := loadCollectorRaw(id, "threat")
	if len(raw) == 0 {
		return nil
	}
	var rep threatCollectorResult
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil
	}
	out := make([]ThreatScoreEntry, 0, len(rep.Entries))
	for _, e := range rep.Entries {
		out = append(out, ThreatScoreEntry{
			Timestamp:     e.Timestamp,
			IP:            e.IP,
			Score:         e.Score,
			ScanHits:      e.ScanHits,
			ScanCriticals: e.ScanCrits,
			AuthFails:     e.AuthFails,
			NCFails:       e.NcFails,
			NC4xx:         e.Nc4xx,
			IsBanned:      boolToInt(e.IsBanned),
			IsForeign:     boolToInt(e.IsForeign),
		})
	}
	return out
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func atoiTrim(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// GetThreatScore は脅威スコア一覧（スコア降順）を返す
func GetThreatScore(agentID ...string) ThreatScoreResponse {
	entries := parseThreatScoreEntries(agentID...)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Score > entries[j].Score
	})

	var ips []string
	for _, e := range entries {
		ips = append(ips, e.IP)
	}
	flags := GetCountryFlags(ips)
	cfg := loadScoreConfig()

	return ThreatScoreResponse{
		Scores: entries,
		Flags:  flags,
		Count:  len(entries),
		Config: cfg,
	}
}

// loadDismissed は nc_high_score_dismiss.json から有効な（24時間以内）除外 IP を返す
// 期限切れエントリは削除して書き戻す
func loadDismissed() map[string]int64 {
	raw, err := os.ReadFile(dismissJSONPath())
	if err != nil {
		return make(map[string]int64)
	}
	var raw2 map[string]interface{}
	if err := json.Unmarshal(raw, &raw2); err != nil {
		return make(map[string]int64)
	}
	cutoff := time.Now().Unix() - 86400
	valid := make(map[string]int64)
	for ip, v := range raw2 {
		ts := int64(toInt(v))
		if ts >= cutoff {
			valid[ip] = ts
		}
	}
	// 期限切れエントリがあれば書き戻し
	if len(valid) != len(raw2) {
		writeDismissed(valid)
	}
	return valid
}

// writeDismissed は dismiss.json を書き込む
func writeDismissed(dismissed map[string]int64) {
	raw, err := json.MarshalIndent(dismissed, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(dismissJSONPath(), raw, 0644)
}

// GetNCHighScore はフィルタリングされた要確認IP一覧を返す
// 条件: scan_critical==0, score>100, 未BAN, 未dismiss
// かつ NC/認証失敗あり OR score >= nc_override_score（スキャン多発でも高スコアなら表示）
func GetNCHighScore(agentID ...string) NCHighScoreResponse {
	entries := parseThreatScoreEntries(agentID...)
	id := normalizeAgentID(agentID)
	dismissed := map[string]int64{}
	if id == "" {
		dismissed = loadDismissed()
	}

	overrideScore := 300
	// 起動時ロード済みキャッシュを参照する。
	if appCfg, err := config.CachedAppConfigForTenant(""); err == nil && appCfg.ThreatScore.NCOverrideScore > 0 {
		overrideScore = appCfg.ThreatScore.NCOverrideScore
	}

	// 高スコア判定の下限は scoreConfig.json の danger 閾値（既定 100）を使う。
	dangerThreshold := loadScoreConfig().Thresholds.Danger

	filtered := make([]ThreatScoreEntry, 0)
	for _, e := range entries {
		if e.ScanCriticals > 0 {
			continue
		}
		if e.Score <= dangerThreshold {
			continue
		}
		if e.IsBanned != 0 {
			continue
		}
		if _, ok := dismissed[e.IP]; ok {
			continue
		}
		if e.AuthFails == 0 && e.NCFails == 0 && e.NC4xx == 0 && e.Score < overrideScore {
			continue
		}
		filtered = append(filtered, e)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Score > filtered[j].Score
	})

	var ips []string
	for _, e := range filtered {
		ips = append(ips, e.IP)
	}
	flags := GetCountryFlags(ips)

	return NCHighScoreResponse{
		Scores: filtered,
		Flags:  flags,
		Count:  len(filtered),
	}
}

// DismissHighScore は IP を 24 時間無視リストに追加する
func DismissHighScore(ip string) error {
	dismissed := loadDismissed()
	dismissed[ip] = time.Now().Unix()
	writeDismissed(dismissed)
	return nil
}

// BanHighScore は IP を recidive jail に BAN する
func BanHighScore(ip string) error {
	// 呼び出し元でも検証済みだが、シェル/コマンドへ渡す前に防御的に再検証する。
	if !isValidIP(ip) {
		return fmt.Errorf("不正な IP: %s", ip)
	}
	// シェル文字列組立を避け、引数を配列で渡す（コマンドインジェクション余地を排除）。
	out, _ := sab.RunArgsCombined(10*time.Second, "sudo", "/usr/bin/fail2ban-client", "set", "recidive", "banip", ip)
	if strings.Contains(out, "1") || strings.Contains(out, "OK") {
		appendManualBan(ip)
		return nil
	}
	if strings.TrimSpace(out) == "" {
		return fmt.Errorf("fail2ban-client コマンドが失敗しました（出力なし）")
	}
	return fmt.Errorf("fail2ban-client エラー: %s", out)
}

// ---- 脅威スコア履歴・イベント履歴 API ----

// ThreatScoreHistoryEntry は脅威スコア履歴（グラフ用）の1エントリ
type ThreatScoreHistoryEntry struct {
	Ts            string `json:"ts"`
	Score         int    `json:"score"`
	ScanHits      int    `json:"scan_hits"`
	ScanCriticals int    `json:"scan_criticals"`
	AuthFails     int    `json:"auth_fails"`
	NCFails       int    `json:"nc_fails"`
	NC4xx         int    `json:"nc_4xx"`
	IsBanned      int    `json:"is_banned"`
	IsForeign     int    `json:"is_foreign"`
}

// ThreatScoreHistoryResponse は threat_score_history API のレスポンス
type ThreatScoreHistoryResponse struct {
	IP      string                    `json:"ip"`
	Entries []ThreatScoreHistoryEntry `json:"entries"`
}

// GetThreatScoreHistory は指定IPの脅威スコア履歴を返す
// PHP の handle_threat_score_history() 相当
func GetThreatScoreHistory(ip string, agentID ...string) ThreatScoreHistoryResponse {
	empty := ThreatScoreHistoryResponse{IP: ip, Entries: []ThreatScoreHistoryEntry{}}
	if !isValidIP(ip) {
		return empty
	}
	id := normalizeAgentID(agentID)
	if id != "" {
		entries := parseThreatScoreEntries(id)
		for _, e := range entries {
			if strings.TrimSpace(e.IP) != ip {
				continue
			}
			return ThreatScoreHistoryResponse{
				IP: ip,
				Entries: []ThreatScoreHistoryEntry{
					{
						Ts:            e.Timestamp,
						Score:         e.Score,
						ScanHits:      e.ScanHits,
						ScanCriticals: e.ScanCriticals,
						AuthFails:     e.AuthFails,
						NCFails:       e.NCFails,
						NC4xx:         e.NC4xx,
						IsBanned:      e.IsBanned,
						IsForeign:     e.IsForeign,
					},
				},
			}
		}
		return empty
	}
	f, err := os.Open(threatScoreHistoryCSVPath())
	if err != nil {
		return empty
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.TrimLeadingSpace = true
	header, err := r.Read()
	if err != nil {
		return empty
	}
	isV3 := len(header) > 3 && strings.TrimSpace(header[3]) == "scan_hits"

	var entries []ThreatScoreHistoryEntry
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(row) < 10 || strings.TrimSpace(row[1]) != ip {
			continue
		}
		e := ThreatScoreHistoryEntry{}
		if isV3 {
			e.Ts = strings.TrimSpace(row[0])
			e.Score = atoiTrim(row[2])
			e.ScanHits = atoiTrim(row[3])
			e.ScanCriticals = atoiTrim(row[4])
			e.AuthFails = atoiTrim(row[5])
			e.NCFails = atoiTrim(row[6])
			e.NC4xx = atoiTrim(row[7])
			e.IsBanned = atoiTrim(row[8])
			e.IsForeign = atoiTrim(row[9])
		} else if len(row) >= 11 {
			e.Ts = strings.TrimSpace(row[0])
			e.Score = atoiTrim(row[2])
			e.ScanHits = atoiTrim(row[4])
			e.ScanCriticals = atoiTrim(row[5])
			e.AuthFails = atoiTrim(row[6])
			e.NCFails = atoiTrim(row[7])
			e.NC4xx = atoiTrim(row[8])
			e.IsBanned = atoiTrim(row[9])
			e.IsForeign = atoiTrim(row[10])
		}
		if e.Ts != "" {
			entries = append(entries, e)
		}
	}
	if entries == nil {
		entries = []ThreatScoreHistoryEntry{}
	}
	return ThreatScoreHistoryResponse{IP: ip, Entries: entries}
}

// ThreatEventEntry はイベント履歴の1件
type ThreatEventEntry struct {
	Ts         string `json:"ts"`
	Category   string `json:"category"`
	ScoreDelta int    `json:"score_delta"`
	Cumulative int    `json:"cumulative"`
	Detail     string `json:"detail"`
	UALabel    string `json:"ua_label,omitempty"`
	UADevice   string `json:"ua_device,omitempty"`
}

// ThreatEventHistoryResponse は threat_event_history API のレスポンス
type ThreatEventHistoryResponse struct {
	Events  []ThreatEventEntry `json:"events"`
	Weights map[string]int     `json:"weights"`
}

// weightVal は weights マップから値を返す（なければデフォルト値）
func weightVal(weights map[string]int, key string, def int) int {
	if v, ok := weights[key]; ok {
		return v
	}
	return def
}

// truncateRunes は文字列をrune単位でmax文字に切り詰める
func truncateRunes(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max])
}

// parseFlexTime は複数フォーマットを試みて unix 秒を返す（失敗時は 0）
func parseFlexTime(s string) (int64, string) {
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
	}
	for _, f := range formats {
		t, err := time.Parse(f, s)
		if err == nil {
			return t.Unix(), t.Format("2006-01-02 15:04:05")
		}
	}
	return 0, s
}

// GetThreatEventHistory は指定IPのイベント履歴を複数ログソースから収集して返す
// PHP の threat_event_history API 相当
func GetThreatEventHistory(ip string, agentID ...string) ThreatEventHistoryResponse {
	empty := ThreatEventHistoryResponse{Events: []ThreatEventEntry{}, Weights: map[string]int{}}
	if !isValidIP(ip) {
		return empty
	}
	id := normalizeAgentID(agentID)

	cfg := loadScoreConfig()
	weights := cfg.Weights
	if weights == nil {
		weights = map[string]int{}
	}
	wScan := weightVal(weights, "scan_hit", 5)
	wScanCrit := weightVal(weights, "scan_critical", 15)
	wAuth := weightVal(weights, "auth_fail", 50)
	wNC := weightVal(weights, "nc_fail", 20)
	wNC4xx := weightVal(weights, "nc_4xx", 10)

	type rawEvent struct {
		unixTs     int64
		ts         string
		category   string
		scoreDelta int
		detail     string
		uaLabel    string
		uaDevice   string
	}

	var events []rawEvent
	now := time.Now()

	// 1. ハニーポット（直近3ヶ月）
	if id != "" {
		records := hpReadRecords(now.AddDate(0, -3, 0).Unix(), id)
		for _, rec := range records {
			if rec.IP != ip {
				continue
			}
			unixTs, tsStr := parseFlexTime(rec.Ts)
			if unixTs == 0 {
				continue
			}
			isCritical := rec.Trigger == "backdoor" || rec.Trigger == "query_string"
			path := rec.Path
			if rec.Query != "" {
				path += "?" + rec.Query
			}
			detail := truncateRunes(rec.Method+" "+path, 100)
			ua := rec.Headers["user-agent"]
			uaInfo := ParseUA(ua)
			category := "スキャン"
			scoreDelta := wScan
			if isCritical {
				category = "高危険"
				scoreDelta = wScan + wScanCrit
			}
			events = append(events, rawEvent{
				unixTs: unixTs, ts: tsStr, category: category,
				scoreDelta: scoreDelta, detail: detail,
				uaLabel: uaInfo.Label, uaDevice: uaInfo.Device,
			})
		}
	} else {
		for i := 0; i <= 2; i++ {
			ym := now.AddDate(0, -i, 0).Format("200601")
			fPath := fmt.Sprintf("%s/honeypot_%s.jsonl", hpLogDirPath(), ym)
			fh, err := os.Open(fPath)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(fh)
			scanner.Buffer(make([]byte, 512*1024), 512*1024)
			for scanner.Scan() {
				var rec struct {
					Ts      string            `json:"ts"`
					IP      string            `json:"ip"`
					Method  string            `json:"method"`
					Path    string            `json:"path"`
					Query   string            `json:"query"`
					Trigger string            `json:"trigger"`
					Headers map[string]string `json:"headers"`
				}
				if err := json.Unmarshal([]byte(scanner.Text()), &rec); err != nil || rec.IP != ip {
					continue
				}
				unixTs, tsStr := parseFlexTime(rec.Ts)
				if unixTs == 0 {
					continue
				}
				isCritical := rec.Trigger == "backdoor" || rec.Trigger == "query_string"
				path := rec.Path
				if rec.Query != "" {
					path += "?" + rec.Query
				}
				detail := truncateRunes(rec.Method+" "+path, 100)
				ua := rec.Headers["user-agent"]
				uaInfo := ParseUA(ua)
				category := "スキャン"
				scoreDelta := wScan
				if isCritical {
					category = "高危険"
					scoreDelta = wScan + wScanCrit
				}
				events = append(events, rawEvent{
					unixTs: unixTs, ts: tsStr, category: category,
					scoreDelta: scoreDelta, detail: detail,
					uaLabel: uaInfo.Label, uaDevice: uaInfo.Device,
				})
			}
			fh.Close()
		}
	}

	// 2. Nginx 認証失敗 (HTTP 401)（logs/nginx.jsonl）
	_ = ScanJSONL[NginxLogEvent](webAccessJSONLPath(id), func(ev NginxLogEvent) bool {
		if ev.IP != ip || ev.Status != 401 {
			return true
		}
		t, err := time.Parse(time.RFC3339, ev.TS)
		unixTs := int64(0)
		formatted := ev.TS
		if err == nil {
			unixTs = t.Unix()
			formatted = t.Format("2006-01-02 15:04:05")
		}
		events = append(events, rawEvent{
			unixTs: unixTs, ts: formatted, category: "認証",
			scoreDelta: wAuth, detail: ev.Method + " " + ev.Path + " → 401",
		})
		return true
	})

	// 3. Nextcloud ログイン失敗（logs/nextcloud.jsonl）
	_ = ScanJSONL[NCEvent](ncJSONLPath(id), func(ev NCEvent) bool {
		if ev.IP != ip {
			return true
		}
		if !strings.Contains(strings.ToLower(ev.Msg), "login failed") {
			return true
		}
		unixTs, tsStr := parseFlexTime(ev.TS)
		events = append(events, rawEvent{
			unixTs: unixTs, ts: tsStr, category: "NC",
			scoreDelta: wNC, detail: truncateRunes(ev.Msg, 100),
		})
		return true
	})

	// 4. NC 4xx（直近3ヶ月）
	if id != "" {
		_ = ScanJSONL[NginxLogEvent](webAccessJSONLPath(id), func(ev NginxLogEvent) bool {
			if ev.IP != ip || ev.Status < 400 || ev.Status >= 500 {
				return true
			}
			pathOnly := strings.SplitN(ev.Path, "?", 2)[0]
			if pathOnly != nextcloudPath && !strings.HasPrefix(pathOnly, nextcloudPath+"/") {
				return true
			}
			unixTs, tsStr := parseFlexTime(ev.TS)
			if unixTs == 0 {
				return true
			}
			detail := truncateRunes(fmt.Sprintf("%s %s → %d", ev.Method, pathOnly, ev.Status), 100)
			uaInfo := ParseUA(ev.UA)
			events = append(events, rawEvent{
				unixTs: unixTs, ts: tsStr, category: "4XX",
				scoreDelta: wNC4xx, detail: detail,
				uaLabel: uaInfo.Label, uaDevice: uaInfo.Device,
			})
			return true
		})
	} else {
		for i := 0; i <= 2; i++ {
			ym := now.AddDate(0, -i, 0).Format("200601")
			fPath := fmt.Sprintf("%s/nc4xx_%s.jsonl", nc4xxLogDirPath(), ym)
			fh, err := os.Open(fPath)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(fh)
			scanner.Buffer(make([]byte, 512*1024), 512*1024)
			for scanner.Scan() {
				var rec struct {
					Ts     string `json:"ts"`
					IP     string `json:"ip"`
					Status string `json:"status"`
					Path   string `json:"path"`
					Method string `json:"method"`
					UA     string `json:"ua"`
				}
				if err := json.Unmarshal([]byte(scanner.Text()), &rec); err != nil || rec.IP != ip {
					continue
				}
				unixTs, tsStr := parseFlexTime(rec.Ts)
				if unixTs == 0 {
					continue
				}
				detail := truncateRunes(fmt.Sprintf("%s %s → %s", rec.Method, rec.Path, rec.Status), 100)
				uaInfo := ParseUA(rec.UA)
				events = append(events, rawEvent{
					unixTs: unixTs, ts: tsStr, category: "4XX",
					scoreDelta: wNC4xx, detail: detail,
					uaLabel: uaInfo.Label, uaDevice: uaInfo.Device,
				})
			}
			fh.Close()
		}
	}

	// 時刻昇順ソート
	sort.Slice(events, func(i, j int) bool {
		return events[i].unixTs < events[j].unixTs
	})

	// 累計スコア計算
	cumulative := 0
	result := make([]ThreatEventEntry, 0, len(events))
	for _, ev := range events {
		cumulative += ev.scoreDelta
		result = append(result, ThreatEventEntry{
			Ts:         ev.ts,
			Category:   ev.category,
			ScoreDelta: ev.scoreDelta,
			Cumulative: cumulative,
			Detail:     ev.detail,
			UALabel:    ev.uaLabel,
			UADevice:   ev.uaDevice,
		})
	}

	// 表示は新しい順（逆順）
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	if result == nil {
		result = []ThreatEventEntry{}
	}
	return ThreatEventHistoryResponse{Events: result, Weights: weights}
}
