package monitor

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// GetNcStorage は Nextcloud OCS API からユーザー/グループフォルダの容量情報を取得する
// ファイルキャッシュ ([nextcloud_cache]) を使用して API 呼び出しを削減する
func GetNcStorage(cfg *config.AppConfig) NcStorageData {
	cacheFile := ""
	if cfg != nil {
		cacheFile = strings.TrimSpace(cfg.NextcloudCache.StorageCacheFile)
	}
	if cacheFile == "" {
		cacheFile = "/var/lib/heartdesk/data/json/nc_storage_summary.json"
	}
	cacheTTL := 300
	if cfg != nil && cfg.NextcloudCache.StorageCacheTTL >= 0 {
		cacheTTL = cfg.NextcloudCache.StorageCacheTTL
	}

	// キャッシュヒット確認
	if cacheTTL > 0 {
		if fi, err := os.Stat(cacheFile); err == nil {
			if time.Since(fi.ModTime()) < time.Duration(cacheTTL)*time.Second {
				if raw, err := os.ReadFile(cacheFile); err == nil {
					var cached NcStorageData
					if json.Unmarshal(raw, &cached) == nil {
						cached.Cache = NcStorageCache{Hit: true, TTLSec: cacheTTL, File: cacheFile}
						return cached
					}
				}
			}
		}
	}

	// NC credentials
	ncURL := ""
	ncUser := ""
	ncPass := ""
	if cfg != nil {
		ncURL = strings.TrimRight(strings.TrimSpace(cfg.Nextcloud.URL), "/")
		ncUser = strings.TrimSpace(cfg.Nextcloud.AppUser)
		ncPass = cfg.Nextcloud.AppPass
	}
	if ncURL == "" || ncUser == "" {
		return NcStorageData{
			Errors:    map[string]string{"config": "nextcloud.url / nextcloud.app_user credentials not configured"},
			FetchedAt: time.Now().Format("2006-01-02 15:04:05"),
			Cache:     NcStorageCache{Hit: false, TTLSec: cacheTTL, File: cacheFile},
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	errors := map[string]string{}

	ncGet := func(url string) (map[string]interface{}, error) {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(ncUser, ncPass)
		req.Header.Set("OCS-APIRequest", "true")
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, err
		}
		return result, nil
	}

	parseQuota := func(v interface{}) *int64 {
		if v == nil {
			return nil
		}
		switch val := v.(type) {
		case string:
			s := strings.ToLower(strings.TrimSpace(val))
			if s == "none" || s == "default" || s == "unlimited" || s == "-3" {
				return nil
			}
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil || n <= 0 {
				return nil
			}
			return &n
		case float64:
			if val <= 0 {
				return nil
			}
			n := int64(val)
			return &n
		}
		return nil
	}
	parseInt64 := func(v interface{}) int64 {
		if v == nil {
			return 0
		}
		switch val := v.(type) {
		case float64:
			return int64(val)
		case string:
			n, _ := strconv.ParseInt(val, 10, 64)
			return n
		}
		return 0
	}

	// ---- ユーザー一覧 + 各ユーザー詳細 ----
	userTotals := NcUserSummary{}
	usersJSON, err := ncGet(ncURL + "/ocs/v1.php/cloud/users?format=json")
	if err != nil {
		errors["users"] = err.Error()
	} else {
		ocs, _ := usersJSON["ocs"].(map[string]interface{})
		data, _ := ocs["data"].(map[string]interface{})
		uids, _ := data["users"].([]interface{})
		for _, uid := range uids {
			uidStr, ok := uid.(string)
			if !ok {
				continue
			}
			userTotals.Users++
			uJSON, err := ncGet(ncURL + "/ocs/v1.php/cloud/users/" + url.PathEscape(uidStr) + "?format=json")
			if err != nil {
				errors["users"] = err.Error()
				continue
			}
			uOcs, _ := uJSON["ocs"].(map[string]interface{})
			uData, _ := uOcs["data"].(map[string]interface{})
			quota, _ := uData["quota"].(map[string]interface{})
			userTotals.Used += parseInt64(quota["used"])
			if q := parseQuota(quota["quota"]); q == nil {
				userTotals.Unlimited++
			} else {
				userTotals.Quota += *q
			}
		}
	}

	// ---- グループフォルダ ----
	var groupfolders []NcGroupFolder
	groupTotals := NcGroupFolderTotals{}
	gfJSON, err := ncGet(ncURL + "/index.php/apps/groupfolders/folders")
	if err != nil {
		errors["groupfolders"] = err.Error()
	} else {
		// レスポンスは {"ocs":{"data":{...}}} または {"data":{...}}
		var gfList map[string]interface{}
		if ocs, ok := gfJSON["ocs"].(map[string]interface{}); ok {
			gfList, _ = ocs["data"].(map[string]interface{})
		}
		if gfList == nil {
			gfList, _ = gfJSON["data"].(map[string]interface{})
		}
		for _, v := range gfList {
			f, ok := v.(map[string]interface{})
			if !ok {
				continue
			}
			size := parseInt64(f["size"])
			q := parseQuota(f["quota"])
			groupTotals.Size += size
			if q == nil {
				groupTotals.Unlimited++
			} else {
				groupTotals.Quota += *q
			}
			id := int(parseInt64(f["id"]))
			mp, _ := f["mount_point"].(string)
			groupfolders = append(groupfolders, NcGroupFolder{
				ID:         id,
				MountPoint: mp,
				Size:       size,
				Quota:      q,
			})
		}
	}

	result := NcStorageData{
		Users:             userTotals,
		Groupfolders:      groupfolders,
		GroupfolderTotals: groupTotals,
		Errors:            errors,
		FetchedAt:         time.Now().Format("2006-01-02 15:04:05"),
		Cache:             NcStorageCache{Hit: false, TTLSec: cacheTTL, File: cacheFile},
	}

	// キャッシュ書き込み: 部分失敗（errors 非空）はキャッシュしない。
	// 一時的な API 障害を TTL 分（既定 300s）ダッシュボードに固定してしまうため。
	if cacheTTL > 0 && len(errors) == 0 {
		if raw, err := json.Marshal(result); err == nil {
			_ = os.WriteFile(cacheFile, raw, 0600)
		}
	}

	return result
}
