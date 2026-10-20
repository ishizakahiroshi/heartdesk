package monitor

import (
	"sort"
	"strings"
	"time"
)

// =============================================================================
// Nginx ヘルス（nginx_health カード）
// =============================================================================

// NginxStatusWindow は1ウィンドウのステータスコード集計
type NginxStatusWindow struct {
	Total   int            `json:"total"`
	ByClass map[string]int `json:"by_class"` // "2xx","3xx","4xx","5xx"
}

// NginxTop5xxEntry はTOP5xxエントリ
type NginxTop5xxEntry struct {
	URL    string `json:"url"`
	Count  int    `json:"count"`
	Status int    `json:"status"`
}

// NginxHealthResponse は /api/monitor/nginx_health のレスポンス
type NginxHealthResponse struct {
	Window1h  NginxStatusWindow  `json:"window_1h"`
	Window24h NginxStatusWindow  `json:"window_24h"`
	Top5xx    []NginxTop5xxEntry `json:"top_5xx"`
}

const nextcloudPath = "/nextcloud"

// GetNginxHealth は logs/nginx.jsonl を解析してヘルス情報を返す
func GetNginxHealth(agentID ...string) NginxHealthResponse {
	now := time.Now()
	cut1h := now.Add(-1 * time.Hour).Unix()
	cut24h := now.Add(-24 * time.Hour).Unix()

	w1h := NginxStatusWindow{ByClass: map[string]int{"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}}
	w24h := NginxStatusWindow{ByClass: map[string]int{"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}}
	top5xxMap := map[string]*NginxTop5xxEntry{}

	events, _ := TailJSONL[NginxLogEvent](webAccessJSONLPath(agentID...), 20000)
	if len(events) == 0 {
		return emptyNginxHealthResponse()
	}

	for _, ev := range events {
		// /nextcloud 配下のみ集計
		cleanPath := strings.SplitN(ev.Path, "?", 2)[0]
		if !strings.HasPrefix(cleanPath, nextcloudPath+"/") && cleanPath != nextcloudPath {
			continue
		}

		t, err := time.Parse(time.RFC3339, ev.TS)
		if err != nil || t.Unix() < cut24h {
			continue
		}

		cls := statusClass(ev.Status)
		if cls == "" {
			continue
		}

		w24h.Total++
		w24h.ByClass[cls]++
		if t.Unix() >= cut1h {
			w1h.Total++
			w1h.ByClass[cls]++
		}

		if cls == "5xx" {
			url := cleanPath
			if e, exists := top5xxMap[url]; exists {
				e.Count++
				e.Status = ev.Status
			} else {
				top5xxMap[url] = &NginxTop5xxEntry{URL: url, Count: 1, Status: ev.Status}
			}
		}
	}

	top5xx := make([]NginxTop5xxEntry, 0, len(top5xxMap))
	for _, e := range top5xxMap {
		top5xx = append(top5xx, *e)
	}
	sort.Slice(top5xx, func(i, j int) bool {
		return top5xx[i].Count > top5xx[j].Count
	})
	if len(top5xx) > 10 {
		top5xx = top5xx[:10]
	}
	if top5xx == nil {
		top5xx = []NginxTop5xxEntry{}
	}

	return NginxHealthResponse{
		Window1h:  w1h,
		Window24h: w24h,
		Top5xx:    top5xx,
	}
}

// statusClass は HTTP ステータスコードを "2xx"/"3xx"/"4xx"/"5xx"/"" に分類する
func statusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	default:
		return ""
	}
}

func emptyNginxHealthResponse() NginxHealthResponse {
	return NginxHealthResponse{
		Window1h:  NginxStatusWindow{ByClass: map[string]int{"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}},
		Window24h: NginxStatusWindow{ByClass: map[string]int{"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}},
		Top5xx:    []NginxTop5xxEntry{},
	}
}
