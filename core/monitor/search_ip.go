package monitor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// SearchIPEvent はIP検索結果の1件
type SearchIPEvent struct {
	Time   string `json:"time"`
	IP     string `json:"ip"`
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

// SearchIPResponse は search_ip API のレスポンス
type SearchIPResponse struct {
	Results []SearchIPEvent `json:"results"`
	Count   int             `json:"count"`
	Country string          `json:"country"`
	IsJapan *bool           `json:"is_japan"`
}

// GetSearchIP は指定IPに関連するすべてのログイベントを収集して返す
func GetSearchIP(ip string, agentID ...string) SearchIPResponse {
	if !isValidIP(ip) {
		return SearchIPResponse{Results: []SearchIPEvent{}}
	}

	var results []SearchIPEvent
	id := normalizeAgentID(agentID)

	// GeoIP 取得
	flags := GetCountryFlags([]string{ip})
	country := flags[ip]
	var isJapan *bool
	if country != "" {
		j := strings.Contains(country, "日本")
		isJapan = &j
	}

	// --- SSH (logs/ssh.jsonl) ---
	{
		var authResults []SearchIPEvent
		_ = ScanJSONL[SSHLogEvent](sshJSONLPath(id), func(ev SSHLogEvent) bool {
			if ev.IP != ip {
				return true
			}
			typ := "SSH"
			switch ev.Event {
			case "failed", "invalid_user":
				typ = "SSH (失敗)"
			case "accepted":
				typ = "SSH (成功)"
			case "disconnect":
				typ = "SSH (切断)"
			}
			detail := ev.Event + " user=" + ev.User + " port=" + ev.Port
			authResults = append(authResults, SearchIPEvent{
				Time:   ev.TS,
				IP:     ip,
				Type:   typ,
				Detail: siTruncate(detail, 120),
			})
			return true
		})
		if len(authResults) > 100 {
			authResults = authResults[len(authResults)-100:]
		}
		results = append(results, authResults...)
	}

	now := time.Now()
	// --- Honeypot JSONL（Agent指定時は Agent event 正本を優先）---
	if id != "" {
		results = append(results, siEventsFromHoneypotRecords(hpReadRecords(now.AddDate(0, -3, 0).Unix(), id), ip)...)
	} else {
		for i := 0; i <= 2; i++ {
			ym := now.AddDate(0, -i, 0).Format("200601")
			f := fmt.Sprintf("%s/honeypot_%s.jsonl", hpLogDirPath(), ym)
			results = append(results, siScanHoneypot(f, ip)...)
		}
	}

	// --- Nextcloud (logs/nextcloud.jsonl) ---
	{
		var ncResults []SearchIPEvent
		_ = ScanJSONL[NCEvent](ncJSONLPath(id), func(ev NCEvent) bool {
			if ev.IP != ip {
				return true
			}
			typ := "NextCloud"
			if strings.Contains(strings.ToLower(ev.Msg), "login failed") {
				typ = "NCログイン失敗"
			}
			ncResults = append(ncResults, SearchIPEvent{
				Time:   ev.TS,
				IP:     ip,
				Type:   typ,
				Detail: siTruncate(ev.Msg, 120),
			})
			return true
		})
		if len(ncResults) > 100 {
			ncResults = ncResults[len(ncResults)-100:]
		}
		results = append(results, ncResults...)
	}

	// --- fail2ban（logs/fail2ban.jsonl） — Agent が生成した JSONL を参照 ---
	{
		var f2bResults []SearchIPEvent
		_ = ScanJSONL[F2BEvent](f2bJSONLPath(id), func(ev F2BEvent) bool {
			if ev.IP != ip {
				return true
			}
			typ := "fail2ban"
			switch ev.Event {
			case "ban":
				typ = "fail2ban BAN"
			case "unban":
				typ = "fail2ban 解除"
			}
			detail := ev.Event + " jail=" + ev.Jail
			f2bResults = append(f2bResults, SearchIPEvent{
				Time:   ev.TS,
				IP:     ip,
				Type:   typ,
				Detail: siTruncate(detail, 120),
			})
			return true
		})
		if len(f2bResults) > 100 {
			f2bResults = f2bResults[len(f2bResults)-100:]
		}
		results = append(results, f2bResults...)
	}

	// --- Nginx（logs/nginx.jsonl）— Agent が生成した JSONL を参照 ---
	{
		var accessResults []SearchIPEvent
		_ = ScanJSONL[NginxLogEvent](webAccessJSONLPath(id), func(ev NginxLogEvent) bool {
			if ev.IP != ip {
				return true
			}
			statusStr := fmt.Sprintf("%d", ev.Status)
			typ := "Nginxアクセス"
			if statusStr == "401" {
				typ = "Nginx (認証失敗)"
			} else if ev.Status >= 400 {
				typ = "Nginx (" + statusStr + ")"
			}
			detail := ev.Method + " " + ev.Path + " → " + statusStr
			accessResults = append(accessResults, SearchIPEvent{
				Time:   ev.TS,
				IP:     ip,
				Type:   typ,
				Detail: siTruncate(detail, 120),
			})
			return true
		})
		if len(accessResults) > 200 {
			accessResults = accessResults[len(accessResults)-200:]
		}
		results = append(results, accessResults...)
	}

	// --- NC 4xx（Agent指定時は web_access.jsonl の /nextcloud 4xx から再構築）---
	if id != "" {
		var nc4xxResults []SearchIPEvent
		_ = ScanJSONL[NginxLogEvent](webAccessJSONLPath(id), func(ev NginxLogEvent) bool {
			if ev.IP != ip || ev.Status < 400 || ev.Status >= 500 {
				return true
			}
			pathOnly := strings.SplitN(ev.Path, "?", 2)[0]
			if pathOnly != nextcloudPath && !strings.HasPrefix(pathOnly, nextcloudPath+"/") {
				return true
			}
			nc4xxResults = append(nc4xxResults, SearchIPEvent{
				Time:   ev.TS,
				IP:     ip,
				Type:   fmt.Sprintf("NC 4xx (%d)", ev.Status),
				Detail: siTruncate(fmt.Sprintf("%s %s → %d", ev.Method, pathOnly, ev.Status), 120),
			})
			return true
		})
		if len(nc4xxResults) > 100 {
			nc4xxResults = nc4xxResults[len(nc4xxResults)-100:]
		}
		results = append(results, nc4xxResults...)
	} else {
		for i := 0; i <= 2; i++ {
			ym := now.AddDate(0, -i, 0).Format("200601")
			f := fmt.Sprintf("%s/nc4xx_%s.jsonl", nc4xxLogDirPath(), ym)
			results = append(results, siScanNC4xx(f, ip)...)
		}
	}

	// 時刻降順ソート
	sort.SliceStable(results, func(a, b int) bool {
		return results[a].Time > results[b].Time
	})

	if results == nil {
		results = []SearchIPEvent{}
	}
	return SearchIPResponse{
		Results: results,
		Count:   len(results),
		Country: country,
		IsJapan: isJapan,
	}
}

func siEventsFromHoneypotRecords(records []hpRecord, ip string) []SearchIPEvent {
	var results []SearchIPEvent
	for _, rec := range records {
		if rec.IP != ip {
			continue
		}
		results = append(results, siHoneypotEvent(rec, ip))
		if len(results) >= 100 {
			break
		}
	}
	return results
}

// siScanHoneypot はハニーポットJSONLから指定IP一致レコードを最大100件返す
func siScanHoneypot(filePath, ip string) []SearchIPEvent {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var results []SearchIPEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 512*1024), 512*1024)
	for scanner.Scan() && len(results) < 100 {
		line := scanner.Text()
		if !strings.Contains(line, ip) {
			continue
		}
		var rec hpRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil || rec.IP != ip {
			continue
		}
		results = append(results, siHoneypotEvent(rec, ip))
	}
	return results
}

func siHoneypotEvent(rec hpRecord, ip string) SearchIPEvent {
	ua := rec.Headers["user-agent"]
	path := rec.Path
	if rec.Query != "" {
		path += "?" + rec.Query
	}
	detail := rec.Method + " " + path
	if rec.PostBody != "" {
		detail += " POST:" + siTruncate(rec.PostBody, 40)
	}
	if ua != "" {
		detail += " [" + siTruncate(ua, 60) + "]"
	}
	ts := rec.Ts
	if len(ts) >= 19 {
		ts = ts[:19]
	}
	trigger := rec.Trigger
	if trigger == "" {
		trigger = "other"
	}
	return SearchIPEvent{
		Time:   ts,
		IP:     ip,
		Type:   "ハニーポット(" + trigger + ")",
		Detail: siTruncate(detail, 120),
	}
}

// siScanNC4xx はNC4xx JSONLから指定IP一致レコードを最大100件返す
func siScanNC4xx(filePath, ip string) []SearchIPEvent {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var results []SearchIPEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 512*1024), 512*1024)
	for scanner.Scan() && len(results) < 100 {
		line := scanner.Text()
		if !strings.Contains(line, ip) {
			continue
		}
		var rec NC4xxRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil || rec.IP != ip {
			continue
		}
		ts := ""
		if len(rec.Ts) >= 19 {
			ts = rec.Ts[:19]
		}
		method := rec.Method
		if method == "" {
			method = "GET"
		}
		detail := method + " " + rec.Path + " → " + rec.Status
		results = append(results, SearchIPEvent{
			Time:   ts,
			IP:     ip,
			Type:   "NC 4xx (" + rec.Status + ")",
			Detail: siTruncate(detail, 120),
		})
	}
	return results
}

// siTruncate は文字列をrune単位でmax文字に切り詰める
func siTruncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max])
}
