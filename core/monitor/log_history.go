package monitor

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
)

// --- 共通型 ---

// LoginRate は直近/前期間の件数比較を保持する（PHP の $rate 配列相当）
type LoginRate struct {
	WindowMin int      `json:"window_min"`
	Recent    int      `json:"recent"`
	Prev      int      `json:"prev"`
	Ratio     *float64 `json:"ratio"` // nil if prev==0
	Delta     int      `json:"delta"`
}

func newLoginRate(windowMin, recent, prev int) LoginRate {
	r := LoginRate{
		WindowMin: windowMin,
		Recent:    recent,
		Prev:      prev,
		Delta:     recent - prev,
	}
	if prev > 0 {
		ratio := float64(recent) / float64(prev)
		r.Ratio = &ratio
	}
	return r
}

// =============================================================================
// SSH / SFTP ログイン履歴
// =============================================================================

// SSHLoginEntry は1件のSSH/SFTPログイン記録
type SSHLoginEntry struct {
	Time    string `json:"time"`
	Result  string `json:"result"` // "success" / "fail"
	Type    string `json:"type"`   // "SSH" / "SFTP"
	User    string `json:"user"`
	IP      string `json:"ip"`
	Method  string `json:"method"`   // "鍵認証" / "パスワード" / "不明"
	KeyName string `json:"key_name"` // 空文字 if not applicable
	SrcPort string `json:"src_port"` // 送信元ポート（空文字 if unknown）
	DstPort string `json:"dst_port"` // 攻撃先ポート（syslog の SSH BLOCKED DPT）
}

// SSHLoginResponse は /api/monitor/ssh_login_history のレスポンス
type SSHLoginResponse struct {
	Entries []SSHLoginEntry   `json:"entries"`
	Rate    LoginRate         `json:"rate"`
	Flags   map[string]string `json:"flags"`
}

// GetSSHLoginHistory は logs/ssh.jsonl を読み、SSH/SFTPログイン履歴を返す。
// Agent が生成した JSONL を利用し、auth.log への直接アクセスは行わない。
func GetSSHLoginHistory(agentID ...string) SSHLoginResponse {
	const windowMin = 30
	now := time.Now()
	cutRecent := now.Add(-time.Duration(windowMin) * time.Minute)
	cutPrev := cutRecent.Add(-time.Duration(windowMin) * time.Minute)

	jsonlPath := sshJSONLPath(agentID...)
	evs, _ := TailJSONL[SSHLogEvent](jsonlPath, 100000)

	var entries []SSHLoginEntry
	rateRecent, ratePrev := 0, 0

	// JSONL は古い順なので末尾から最大1000件を逆順で積む
	start := 0
	if len(evs) > 1000 {
		start = len(evs) - 1000
	}
	for i := len(evs) - 1; i >= start; i-- {
		ev := evs[i]
		if ev.IP == "" {
			continue
		}
		result := ""
		switch ev.Event {
		case "accepted":
			result = "success"
		case "failed", "invalid_user":
			result = "fail"
		default:
			continue
		}

		method := ""
		switch ev.Method {
		case "publickey":
			method = "鍵認証"
		case "password":
			method = "パスワード"
		default:
			method = "不明"
		}

		user := ev.User
		if user == "" {
			user = "?"
		}

		timeStr := ev.TS
		if t, err := time.Parse(time.RFC3339, ev.TS); err == nil {
			if t.After(cutRecent) {
				rateRecent++
			} else if t.After(cutPrev) {
				ratePrev++
			}
			timeStr = t.In(heartdesk.JST()).Format("02/Jan/2006:15:04:05 +0900")
		}

		entries = append(entries, SSHLoginEntry{
			Time:    timeStr,
			Result:  result,
			Type:    "SSH",
			User:    user,
			IP:      ev.IP,
			Method:  method,
			SrcPort: ev.Port,
		})
	}

	if entries == nil {
		entries = []SSHLoginEntry{}
	}

	ipSet := make(map[string]struct{})
	for _, e := range entries {
		if e.IP != "" && e.IP != "127.0.0.1" {
			ipSet[e.IP] = struct{}{}
		}
	}
	ipList := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ipList = append(ipList, ip)
	}

	return SSHLoginResponse{
		Entries: entries,
		Rate:    newLoginRate(windowMin, rateRecent, ratePrev),
		Flags:   GetCountryFlags(ipList),
	}
}

// =============================================================================
// heartdesk / phpMyAdmin ログイン履歴
// =============================================================================

// NginxLoginEntry は1件のNginxログイン記録
type NginxLoginEntry struct {
	Time     string `json:"time"`
	Result   string `json:"result"` // "success" / "fail"
	App      string `json:"app,omitempty"`
	AppLabel string `json:"app_label,omitempty"`
	User     string `json:"user"`
	IP       string `json:"ip"`
	Device   string `json:"device"` // "mobile"/"pc"/"tool"/"scanner"/"unknown"
	UA       string `json:"ua"`
	PwStats  string `json:"pw_stats,omitempty"` // 失敗時のみ: パスワード統計
	Reason   string `json:"reason,omitempty"`   // "totp_fail" / "lockout" / "bad_credential"
}

// NginxLoginResponse は heartdesk / phpMyAdmin ログイン履歴のレスポンス
type NginxLoginResponse struct {
	Entries []NginxLoginEntry `json:"entries"`
	Rate    LoginRate         `json:"rate"`
	Flags   map[string]string `json:"flags"`
}

// NginxLoginHistoriesResponse は /api/monitor/nginx_login_histories のレスポンス（統合版）
type NginxLoginHistoriesResponse struct {
	Heartdesk  NginxLoginResponse `json:"heartdesk"`
	PhpMyAdmin NginxLoginResponse `json:"phpmyadmin"`
}

// nginxLogTarget は解析対象アプリの定義
type nginxLogTarget struct {
	Key   string
	Label string
	Path  string
}

// getNginxLoginHistories は heartdesk（自前JSONL）+ phpMyAdmin（nginx.jsonl解析）の履歴を返す
func getNginxLoginHistories(agentID ...string) NginxLoginHistoriesResponse {
	const windowMin = 30
	now := time.Now()
	cutRecent := now.Add(-time.Duration(windowMin) * time.Minute)
	cutPrev := cutRecent.Add(-time.Duration(windowMin) * time.Minute)

	targets := []nginxLogTarget{
		{Key: "phpmyadmin", Label: "phpMyAdmin", Path: "/dbadmin-s3cur3"},
	}

	events, _ := TailJSONL[NginxLogEvent](webAccessJSONLPath(agentID...), 20000)

	var allEntries []NginxLoginEntry
	rateRecent, ratePrev := 0, 0
	seen := map[string]bool{}

	// 最新優先に逆順走査
	for i := len(events) - 1; i >= 0; i-- {
		ev := events[i]

		// アプリキー特定（パス前方一致）
		targetKey := ""
		var appLabel string
		for _, tgt := range targets {
			if strings.HasPrefix(ev.Path, tgt.Path) {
				targetKey = tgt.Key
				appLabel = tgt.Label
				break
			}
		}
		if targetKey == "" {
			continue
		}

		// ?api= を含むリクエストはスキップ
		if strings.Contains(ev.Path, "?api=") {
			continue
		}

		// ステータスコードで成功/失敗判定
		result := ""
		switch {
		case ev.Status >= 200 && ev.Status < 400:
			result = "success"
		case ev.Status == 401 || ev.Status == 403:
			result = "fail"
		default:
			continue
		}

		// 重複チェック（result+app+ipで; JSONL に user フィールドなし）
		dedupeKey := result + "|" + targetKey + "|" + ev.IP
		if seen[dedupeKey] {
			continue
		}
		seen[dedupeKey] = true

		// レート計算
		if t, err := time.Parse(time.RFC3339, ev.TS); err == nil {
			if t.After(cutRecent) {
				rateRecent++
			} else if t.After(cutPrev) {
				ratePrev++
			}
		}

		uaInfo := ParseUA(ev.UA)
		allEntries = append(allEntries, NginxLoginEntry{
			Time:     ev.TS,
			Result:   result,
			App:      targetKey,
			AppLabel: appLabel,
			User:     "",
			IP:       ev.IP,
			Device:   uaInfo.Device,
			UA:       uaInfo.Label,
		})
		if len(allEntries) >= 1000 {
			break
		}
	}

	pmaRate := newLoginRate(windowMin, rateRecent, ratePrev)

	// phpMyAdmin は app フィールド不要
	var pmaEntries []NginxLoginEntry
	for _, e := range allEntries {
		pmaEntries = append(pmaEntries, NginxLoginEntry{
			Time:   e.Time,
			Result: e.Result,
			User:   e.User,
			IP:     e.IP,
			Device: e.Device,
			UA:     e.UA,
		})
	}
	if pmaEntries == nil {
		pmaEntries = []NginxLoginEntry{}
	}

	ipSet := make(map[string]struct{})
	for _, e := range allEntries {
		if e.IP != "" && e.IP != "127.0.0.1" {
			ipSet[e.IP] = struct{}{}
		}
	}
	ipList := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ipList = append(ipList, ip)
	}
	pmaFlags := GetCountryFlags(ipList)

	// heartdesk 側は自前の JSONL を読み込む
	own := GetLoginHistory()

	return NginxLoginHistoriesResponse{
		Heartdesk:  own,
		PhpMyAdmin: NginxLoginResponse{Entries: pmaEntries, Rate: pmaRate, Flags: pmaFlags},
	}
}

// GetLoginHistory は heartdesk のログインイベントJSONLを読んで返す
func GetLoginHistory() NginxLoginResponse {
	const windowMin = 30
	now := time.Now()
	cutRecent := now.Add(-time.Duration(windowMin) * time.Minute)
	cutPrev := cutRecent.Add(-time.Duration(windowMin) * time.Minute)

	f, err := os.Open(auth.LoginLogResolvedPath())
	if err != nil {
		return NginxLoginResponse{Entries: []NginxLoginEntry{}, Rate: newLoginRate(windowMin, 0, 0)}
	}
	defer f.Close()

	type rawEntry = auth.LoginLogEntry
	var lines []rawEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e rawEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			lines = append(lines, e)
		}
	}

	rateRecent, ratePrev := 0, 0
	var entries []NginxLoginEntry
	for i := len(lines) - 1; i >= 0; i-- {
		e := lines[i]
		t, err := time.Parse(time.RFC3339, e.Time)
		if err != nil {
			continue
		}
		if t.After(cutRecent) {
			rateRecent++
		} else if t.After(cutPrev) {
			ratePrev++
		}
		uaInfo := ParseUA(e.UA)
		entries = append(entries, NginxLoginEntry{
			Time:     t.Format("02/Jan/2006:15:04:05 +0900"),
			Result:   e.Result,
			App:      CurrentMonitorIdentity().LoginLogAppName,
			AppLabel: CurrentMonitorIdentity().AppName,
			User:     e.User,
			IP:       e.IP,
			Device:   uaInfo.Device,
			UA:       uaInfo.Label,
			PwStats:  e.PwStats,
			Reason:   e.Reason,
		})
		if len(entries) >= 1000 {
			break
		}
	}
	if entries == nil {
		entries = []NginxLoginEntry{}
	}
	ipSet := make(map[string]struct{})
	for _, e := range entries {
		if e.IP != "" && e.IP != "127.0.0.1" {
			ipSet[e.IP] = struct{}{}
		}
	}
	ipList := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ipList = append(ipList, ip)
	}
	return NginxLoginResponse{Entries: entries, Rate: newLoginRate(windowMin, rateRecent, ratePrev), Flags: GetCountryFlags(ipList)}
}

// GetPhpMyAdminLoginHistory は phpMyAdmin のログイン履歴を返す
func GetPhpMyAdminLoginHistory(agentID ...string) NginxLoginResponse {
	h := getNginxLoginHistories(agentID...)
	return h.PhpMyAdmin
}

// GetNginxLoginHistories は heartdesk + phpMyAdmin 両方を返す統合API
func GetNginxLoginHistories(agentID ...string) NginxLoginHistoriesResponse {
	return getNginxLoginHistories(agentID...)
}
