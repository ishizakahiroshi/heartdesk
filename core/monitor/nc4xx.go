package monitor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
)

func nc4xxLogDirPath() string { return sab.SabPath("data/json/nc4xx") }

// NC4xxRecord は NC 4xx アクセスログの1件
type NC4xxRecord struct {
	Ts     string `json:"ts"`
	IP     string `json:"ip"`
	Status string `json:"status"`
	Path   string `json:"path"`
	Query  string `json:"query"`
	Method string `json:"method"`
}

// NC4xxResponse は /nab/api/monitor/nc4xx_access のレスポンス
type NC4xxResponse struct {
	Records  []NC4xxRecord     `json:"records"`
	Total    int               `json:"total"`
	Flags    map[string]string `json:"flags"`
	DaysSpan int               `json:"days_span"`
}

// GetNC4xxAccess は nc4xx JSONL ログからアクセス一覧を返す
func GetNC4xxAccess(days, limit int, agentID ...string) NC4xxResponse {
	if days < 1 {
		days = 1
	}
	if days > 30 {
		days = 30
	}
	if limit < 100 {
		limit = 100
	}
	if limit > 3000 {
		limit = 3000
	}

	since := time.Now().In(sab.JST()).Add(-time.Duration(days) * 24 * time.Hour).Unix()
	id := normalizeAgentID(agentID)
	if id != "" {
		return getAgentNC4xxAccess(id, since, days, limit)
	}
	now := time.Now()

	// 今月 + 先月
	var files []string
	for i := 0; i <= 1; i++ {
		ym := now.AddDate(0, -i, 0).Format("200601")
		f := fmt.Sprintf("%s/nc4xx_%s.jsonl", nc4xxLogDirPath(), ym)
		if _, err := os.Stat(f); err == nil {
			files = append(files, f)
		}
	}

	records := make([]NC4xxRecord, 0)
	for _, file := range files {
		if len(records) >= limit {
			break
		}
		f, err := os.Open(file)
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
			var raw map[string]interface{}
			if err := json.Unmarshal([]byte(line), &raw); err != nil {
				continue
			}
			tsStr, _ := raw["ts"].(string)
			if tsStr == "" {
				continue
			}
			ts, err := sab.ParseTimestamp(tsStr)
			if err != nil || ts.Unix() < since {
				continue
			}
			ip, _ := raw["ip"].(string)
			// status は JSON 数値（404 等）なので float64 → string 変換
			var status string
			switch v := raw["status"].(type) {
			case float64:
				status = strconv.Itoa(int(v))
			case string:
				status = v
			}
			path, _ := raw["path"].(string)
			query, _ := raw["query"].(string)
			method, _ := raw["method"].(string)
			// タイムスタンプを JST 表示形式に変換
			tsDisplay := sab.FormatDatetime(ts.In(sab.JST()))
			records = append(records, NC4xxRecord{
				Ts:     tsDisplay,
				IP:     ip,
				Status: status,
				Path:   path,
				Query:  query,
				Method: method,
			})
			if len(records) >= limit {
				break
			}
		}
		f.Close()
	}

	// 新しい順にソート
	sort.Slice(records, func(i, j int) bool {
		return records[i].Ts > records[j].Ts
	})
	if len(records) > limit {
		records = records[:limit]
	}

	// days_span: 直近レコードと最古レコードのUNIX差（Tsは表示形式なので期間を days で近似）
	daysSpan := days

	// 国旗取得
	ipSet := make(map[string]bool)
	for _, r := range records {
		if r.IP != "" && r.IP != "127.0.0.1" {
			ipSet[r.IP] = true
		}
	}
	var uniqueIPs []string
	for ip := range ipSet {
		uniqueIPs = append(uniqueIPs, ip)
	}
	flags := GetCountryFlags(uniqueIPs)

	return NC4xxResponse{
		Records:  records,
		Total:    len(records),
		Flags:    flags,
		DaysSpan: daysSpan,
	}
}

func getAgentNC4xxAccess(agentID string, since int64, days, limit int) NC4xxResponse {
	events, _ := TailJSONL[NginxLogEvent](webAccessJSONLPath(agentID), limit*4)
	records := make([]NC4xxRecord, 0, limit)
	for i := len(events) - 1; i >= 0; i-- {
		ev := events[i]
		if ev.Status < 400 || ev.Status >= 500 {
			continue
		}
		pathOnly := ev.Path
		if idx := len(pathOnly); idx > 0 {
			parts := []rune(pathOnly)
			for j, c := range parts {
				if c == '?' {
					pathOnly = string(parts[:j])
					break
				}
			}
		}
		if pathOnly != nextcloudPath && !strings.HasPrefix(pathOnly, nextcloudPath+"/") {
			continue
		}
		ts, err := time.Parse(time.RFC3339, ev.TS)
		if err != nil || ts.Unix() < since {
			continue
		}
		query := ""
		if q := strings.SplitN(ev.Path, "?", 2); len(q) == 2 {
			query = q[1]
		}
		records = append(records, NC4xxRecord{
			Ts:     sab.FormatDatetime(ts.In(sab.JST())),
			IP:     ev.IP,
			Status: strconv.Itoa(ev.Status),
			Path:   pathOnly,
			Query:  query,
			Method: ev.Method,
		})
		if len(records) >= limit {
			break
		}
	}

	ipSet := make(map[string]bool)
	for _, r := range records {
		if r.IP != "" && r.IP != "127.0.0.1" {
			ipSet[r.IP] = true
		}
	}
	var uniqueIPs []string
	for ip := range ipSet {
		uniqueIPs = append(uniqueIPs, ip)
	}

	return NC4xxResponse{
		Records:  records,
		Total:    len(records),
		Flags:    GetCountryFlags(uniqueIPs),
		DaysSpan: days,
	}
}
