package daemon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

const (
	defaultGeoIPDBURL             = "https://ipinfo.io/data/ipinfo_lite.mmdb"
	defaultGeoIPDBDownloadTimeout = 180 * time.Second
	// geoIPDBLogPathEnv はログ出力先の差し替え口。本番の systemd unit では設定しないので
	// defaultGeoIPDBLogPath（HEARTDESK_BASE_DIR 基準）が使われる。テストは本番パスへ書けないため必須。
	geoIPDBLogPathEnv         = "UPDATE_GEOIP_DB_LOG_PATH"
	minGeoIPDBSizeBytes int64 = 1024 * 1024
)

// defaultGeoIPDBLogPath は HEARTDESK_BASE_DIR 基準の既定のログ出力先。
func defaultGeoIPDBLogPath() string {
	return heartdesk.PathOrDefault("data/logs/update-geoip-db.log")
}

var geoIPDBHTTPClient = &http.Client{Timeout: defaultGeoIPDBDownloadTimeout}

// UpdateGeoIPDB は IPinfo Lite MMDB をダウンロードし、GeoIP DB をアトミック更新する。
func UpdateGeoIPDB(ctx context.Context, cfg *config.SchedulerConfig) error {
	dbPath := ""
	if cfg != nil {
		dbPath = strings.TrimSpace(cfg.GeoIPDBPath)
	}
	if dbPath == "" {
		return fmt.Errorf("GeoIP DB path not configured ([paths].geoip_db)")
	}

	token := ""
	if cfg != nil {
		token = strings.TrimSpace(cfg.GeoIPToken)
	}
	if token == "" {
		return fmt.Errorf("IPinfo token not configured ([geoip].token)")
	}

	downloadURL := ""
	if cfg != nil {
		downloadURL = strings.TrimSpace(cfg.GeoIPDBURL)
	}
	if downloadURL == "" {
		downloadURL = defaultGeoIPDBURL
	}

	logPath := defaultGeoIPDBLogPath()
	if v := strings.TrimSpace(os.Getenv(geoIPDBLogPathEnv)); v != "" {
		logPath = v
	}
	logLine, closeLog, err := openCollectLogger(logPath)
	if err != nil {
		return err
	}
	defer closeLog()

	timeout := defaultGeoIPDBDownloadTimeout
	if cfg != nil && cfg.GeoIPDownloadTimeoutSec > 0 {
		timeout = time.Duration(cfg.GeoIPDownloadTimeoutSec) * time.Second
	}

	client := *geoIPDBHTTPClient
	client.Timeout = timeout

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint, err := url.Parse(downloadURL)
	if err != nil {
		return fmt.Errorf("invalid download url: %w", err)
	}
	query := endpoint.Query()
	query.Set("token", token)
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return err
	}

	logLine("", "Downloading IPinfo Lite MMDB...")
	resp, err := client.Do(req)
	if err != nil {
		// client.Do が返す *url.Error は完全な URL（?token=<実値> を含む）を文字列化するため、
		// そのままログ・journald（daemon.go の run fail ログ）・scheduler 状態（LastError 永続化）へ
		// 流すと IPinfo トークンが平文流出する。返却エラー自体をマスクして全シンクを同時に塞ぐ。
		safeErr := err
		if token != "" {
			safeErr = fmt.Errorf("%s", strings.ReplaceAll(err.Error(), token, "***"))
		}
		logLine("ERROR", "download failed: "+safeErr.Error())
		return safeErr
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("download failed: http status %d", resp.StatusCode)
		logLine("ERROR", msg)
		return fmt.Errorf("%s", msg)
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return fmt.Errorf("db dir create failed: %w", err)
	}

	tmpPath := dbPath + ".tmp"
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open temp file failed: %w", err)
	}

	written, copyErr := io.Copy(tmpFile, resp.Body)
	closeErr := tmpFile.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("download write failed: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("download close failed: %w", closeErr)
	}
	if written < minGeoIPDBSizeBytes {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("downloaded file too small: %d bytes", written)
	}

	if err := os.Rename(tmpPath, dbPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace db failed: %w", err)
	}

	logLine("", fmt.Sprintf("SUCCESS: Updated GeoIP DB %s (%d bytes)", dbPath, written))
	return nil
}
