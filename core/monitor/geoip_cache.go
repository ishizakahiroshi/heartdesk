package monitor

import (
	"encoding/json"
	"os"
)

// =============================================================================
// GeoIP キャッシュ（geoip_cache カード）
// =============================================================================

// GeoIPCacheIP はGeoIPキャッシュの1エントリ
type GeoIPCacheIP struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	TS      *int64 `json:"ts"` // UnixTimestamp or nil
}

// GeoIPCacheResponse は /api/monitor/geoip_cache のレスポンス
type GeoIPCacheResponse struct {
	Count      int            `json:"count"`
	FileSize   int64          `json:"file_size"`
	Mtime      *int64         `json:"mtime"` // UnixTimestamp or nil
	XRL        interface{}    `json:"x_rl"`
	XTTL       interface{}    `json:"x_ttl"`
	LastCallTS interface{}    `json:"last_call_ts"`
	TotalCalls int            `json:"total_calls"`
	IPs        []GeoIPCacheIP `json:"ips"`
}

// GetGeoIPCache は GeoIP キャッシュファイルの内容を返す
func GetGeoIPCache() GeoIPCacheResponse {
	empty := GeoIPCacheResponse{IPs: []GeoIPCacheIP{}}

	cacheFile := geoCacheFilePath()
	if b, err2 := os.ReadFile(cacheFile); err2 != nil || len(b) == 0 {
		return empty
	}

	info, err := os.Stat(cacheFile)
	if err != nil {
		return empty
	}
	fileSize := info.Size()
	mtime := info.ModTime().Unix()

	b, err := os.ReadFile(cacheFile)
	if err != nil {
		return empty
	}
	raw := string(b)

	// JSON パース
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return empty
	}

	meta, _ := data["_meta"].(map[string]interface{})
	delete(data, "_meta")

	var ips []GeoIPCacheIP
	for ip, v := range data {
		entry := GeoIPCacheIP{IP: ip}
		switch val := v.(type) {
		case map[string]interface{}:
			entry.Country, _ = val["country"].(string)
			if ts, ok := val["ts"].(float64); ok {
				tsInt := int64(ts)
				entry.TS = &tsInt
			}
		case string:
			entry.Country = val
		}
		ips = append(ips, entry)
	}
	if ips == nil {
		ips = []GeoIPCacheIP{}
	}

	res := GeoIPCacheResponse{
		Count:    len(ips),
		FileSize: fileSize,
		Mtime:    &mtime,
		IPs:      ips,
	}
	if meta != nil {
		res.XRL = meta["x_rl"]
		res.XTTL = meta["x_ttl"]
		res.LastCallTS = meta["last_call_ts"]
		if tc, ok := meta["total_calls"].(float64); ok {
			res.TotalCalls = int(tc)
		}
	}
	return res
}
