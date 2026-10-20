package monitor

import (
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/nclog"
)

// =============================================================================
// Nextcloud ログイン履歴（nc_login カード）
// =============================================================================

// NCLoginEntry は1件のNextcloudログイン記録（api_nc_audit() 相当）
type NCLoginEntry struct {
	Time        string `json:"time"`
	Result      string `json:"result"` // "success" / "fail"
	User        string `json:"user"`
	DisplayName string `json:"display_name,omitempty"`
	IP          string `json:"ip"`
	UA          string `json:"ua"`
	UAType      string `json:"ua_type"` // "internal"/"win"/"ios"/"android"/"browser"
	Reason      string `json:"reason,omitempty"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	FailureKind string `json:"failure_kind,omitempty"` // "auth"/"request" (fail のみ)
}

// NCLoginResponse は /nab/api/monitor/nc_login のレスポンス
type NCLoginResponse struct {
	Logins []NCLoginEntry    `json:"logins"`
	Rate   LoginRate         `json:"rate"`
	Flags  map[string]string `json:"flags"`
}

// ncLogRecord は logs/nextcloud.jsonl の NCEvent を nc_login 処理用にラップする型。
// フィールド名は元の nextcloud.log JSONL と合わせる（後段ロジックへの影響を最小化）。
type ncLogRecord struct {
	Time       string
	ReqID      string
	Message    string
	RemoteAddr string
	URL        string
	Method     string
	User       string
	UserAgent  string
	Level      int
	Exception  *struct {
		Message string
	}
}

// =============================================================================
// Nextcloud 新規ユーザー作成・初回ログイン検出
// =============================================================================

// NCUserCreatedEvent は新規ユーザー作成イベント1件
type NCUserCreatedEvent struct {
	Time string
	UID  string
}

// NCFirstLoginEvent は新規ユーザーの初回ログインイベント1件
type NCFirstLoginEvent struct {
	Time string
	UID  string
}

// ncDetectUserCreatedEvents はレコード列から新規ユーザー作成イベントを抽出する
func ncDetectUserCreatedEvents(records []ncLogRecord) []NCUserCreatedEvent {
	var out []NCUserCreatedEvent
	for _, rec := range records {
		uid := nclog.ExtractUserCreated(rec.Message)
		if uid == "" {
			continue
		}
		out = append(out, NCUserCreatedEvent{Time: rec.Time, UID: uid})
	}
	return out
}

// ncDetectFirstLogins は新規ユーザー作成イベントとログインレコードをuidで突き合わせ、
// 作成後最初の Login successful だけを返す（2回目以降のログインは対象外）。
// 作成時刻と比較可能な場合、作成より前の成功ログイン（ログの並び順の乱れ等）は対象にしない。
func ncDetectFirstLogins(createdEvents []NCUserCreatedEvent, loginRecords []ncLogRecord) []NCFirstLoginEvent {
	createdAt := map[string]time.Time{}
	createdSeen := map[string]bool{}
	for _, ev := range createdEvents {
		if createdSeen[ev.UID] {
			continue
		}
		createdSeen[ev.UID] = true
		if t, ok := nclog.ParseTime(ev.Time); ok {
			createdAt[ev.UID] = t
		}
	}

	matched := map[string]bool{}
	var out []NCFirstLoginEvent
	for _, rec := range loginRecords {
		if nclog.ExtractLoginResult(rec.Message) != "success" {
			continue
		}
		uid := strings.TrimSpace(rec.User)
		if uid == "" {
			uid = nclog.ExtractLoginUserFromMessage(rec.Message)
		}
		if uid == "" || !createdSeen[uid] || matched[uid] {
			continue
		}
		if createdTime, ok := createdAt[uid]; ok {
			if loginTime, ok := nclog.ParseTime(rec.Time); ok && loginTime.Before(createdTime) {
				continue
			}
		}
		matched[uid] = true
		out = append(out, NCFirstLoginEvent{Time: rec.Time, UID: uid})
	}
	return out
}

// ncEventToRecord は NCEvent を ncLogRecord に変換する
func ncEventToRecord(ev NCEvent) ncLogRecord {
	rec := ncLogRecord{
		Time:       ev.TS,
		ReqID:      ev.ReqID,
		Message:    ev.Msg,
		RemoteAddr: ev.IP,
		URL:        ev.URL,
		Method:     ev.Method,
		User:       ev.User,
		UserAgent:  ev.UserAgent,
	}
	if ev.Exception != nil {
		rec.Exception = &struct{ Message string }{Message: ev.Exception.Message}
	}
	return rec
}

// ncLoadLoginRows は logs/nextcloud.jsonl からログイン関連レコードを返す
func ncLoadLoginRows(lines int, agentID ...string) []ncLogRecord {
	evs, _ := TailJSONL[NCEvent](ncJSONLPath(agentID...), lines)
	var out []ncLogRecord
	seen := make(map[string]bool)
	for _, ev := range evs {
		if nclog.ExtractLoginResult(ev.Msg) == "" {
			continue
		}
		key := ev.ReqID + "|" + ev.TS + "|" + ev.Msg
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ncEventToRecord(ev))
	}
	return out
}

// ncLoadContextRows は logs/nextcloud.jsonl からコンテキスト（失敗理由・ブルートフォース）レコードを返す
func ncLoadContextRows(lines int, agentID ...string) []ncLogRecord {
	evs, _ := TailJSONL[NCEvent](ncJSONLPath(agentID...), lines)
	var out []ncLogRecord
	seen := make(map[string]bool)
	for _, ev := range evs {
		hasException := ev.Exception != nil
		if nclog.ExtractLoginResult(ev.Msg) == "" &&
			!strings.Contains(ev.Msg, "Bruteforce attempt") &&
			!hasException {
			continue
		}
		key := ev.ReqID + "|" + ev.TS + "|" + ev.Msg
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ncEventToRecord(ev))
	}
	return out
}

// GetNCLoginHistory はNextcloudのログイン履歴を返す（api_nc_audit()相当）
func GetNCLoginHistory(agentID ...string) NCLoginResponse {
	const windowMin = 30
	now := time.Now()
	cutRecent := now.Add(-time.Duration(windowMin) * time.Minute)
	cutPrev := cutRecent.Add(-time.Duration(windowMin) * time.Minute)

	loginRows := ncLoadLoginRows(120000, agentID...)
	contextRows := ncLoadContextRows(120000, agentID...)

	// reqId → 失敗理由・ブルートフォースフラグ のマップ
	reqidReason := map[string]string{}
	reqidBruteforce := map[string]bool{}
	for _, rec := range contextRows {
		if rec.ReqID == "" {
			continue
		}
		if strings.Contains(rec.Message, "Bruteforce attempt") {
			reqidBruteforce[rec.ReqID] = true
		}
		if rec.Exception != nil && rec.Exception.Message != "" {
			excMsg := rec.Exception.Message
			if _, exists := reqidReason[rec.ReqID]; !exists {
				if strings.Contains(excMsg, "Username or password was incorrect") {
					reqidReason[rec.ReqID] = "PW誤り"
				} else {
					parts := strings.SplitN(excMsg, ",", 2)
					first := strings.TrimSpace(parts[0])
					if len(first) > 40 {
						first = first[:40] + "..."
					}
					reqidReason[rec.ReqID] = first
				}
			}
		}
	}

	var logins []NCLoginEntry
	rateRecent, ratePrev := 0, 0

	for _, rec := range loginRows {
		msg := rec.Message
		result := nclog.ExtractLoginResult(msg)
		if result == "" {
			continue
		}
		ip := rec.RemoteAddr
		// WebDAV / OCS / DAV API由来は除外
		url := rec.URL
		if strings.Contains(url, "/remote.php/") ||
			strings.Contains(url, "/ocs/v1.php/") ||
			strings.Contains(url, "/ocs/v2.php/") ||
			strings.Contains(url, "/apps/dav/") {
			continue
		}

		ts, tsOK := nclog.ParseTime(rec.Time)
		if tsOK {
			if ts.After(cutRecent) {
				rateRecent++
			} else if ts.After(cutPrev) {
				ratePrev++
			}
		}

		user := strings.TrimSpace(rec.User)
		if user == "" {
			user = nclog.ExtractLoginUserFromMessage(msg)
		}

		reason := ""
		failureKind := ""
		if result == "fail" && rec.ReqID != "" {
			var parts []string
			if r, ok := reqidReason[rec.ReqID]; ok {
				parts = append(parts, r)
			}
			if reqidBruteforce[rec.ReqID] {
				parts = append(parts, "BF検知")
			}
			reason = strings.Join(parts, " / ")
			// URLが壊れたリクエスト由来かどうか
			if strings.Contains(strings.ToLower(url), "index.phpar=") {
				failureKind = "request"
			} else {
				failureKind = "auth"
			}
		}

		ua := rec.UserAgent
		uaType := ""
		switch {
		case ua == "--" || ua == "":
			uaType = "internal"
		case containsCI(ua, "mirall/"):
			uaType = "win"
		case containsCI(ua, "Nextcloud-iOS"):
			uaType = "ios"
		case containsCI(ua, "Nextcloud-Android"):
			uaType = "android"
		default:
			uaType = "browser"
		}

		logins = append(logins, NCLoginEntry{
			Time:        rec.Time,
			Result:      result,
			User:        user,
			IP:          ip,
			UA:          ua,
			UAType:      uaType,
			Reason:      reason,
			URL:         url,
			Method:      strings.ToUpper(rec.Method),
			FailureKind: failureKind,
		})
	}

	// 逆順にして最新1000件
	reverseNCEntries(logins)
	if len(logins) > 1000 {
		logins = logins[:1000]
	}
	if logins == nil {
		logins = []NCLoginEntry{}
	}

	ipSet := make(map[string]struct{})
	for _, l := range logins {
		if l.IP != "" && l.IP != "127.0.0.1" {
			ipSet[l.IP] = struct{}{}
		}
	}
	ipList := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ipList = append(ipList, ip)
	}

	return NCLoginResponse{
		Logins: logins,
		Rate:   newLoginRate(windowMin, rateRecent, ratePrev),
		Flags:  GetCountryFlags(ipList),
	}
}

func reverseNCEntries(s []NCLoginEntry) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
