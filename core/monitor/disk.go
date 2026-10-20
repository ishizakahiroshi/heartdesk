package monitor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// GetDisk はディスク使用量・ログファイル・DB容量・Nginxトラフィックを返す。
// agentID が指定された場合は Unavailable を返す（disk は VPS 直実行専用のため、
// レポートあり・なしに関わらず Agent 経由では取得不可）。
func GetDisk(cfg *config.AppConfig, agentID ...string) DiskData {
	if len(agentID) > 0 && agentID[0] != "" {
		return DiskData{StatusCodes: map[string]int{}, CountryCounts: map[string]int{}, Unavailable: true}
	}
	ncDir := ""
	if cfg != nil {
		ncDir = strings.TrimSpace(cfg.Paths.NextcloudDir)
	}
	if ncDir == "" {
		ncDir = "/var/www/nextcloud"
	}
	d := DiskData{
		StatusCodes:   map[string]int{},
		CountryCounts: map[string]int{},
	}

	// ---- NC・ログ容量 (du -sh) ----
	d.NcDataSize = duSh(ncDir + "/data")
	d.NcAppSize = duSh(ncDir)
	d.LogSize = duSh("/var/log")
	d.NcLogSize = duSh(ncDir + "/data/nextcloud.log")

	// ---- NC ログファイル一覧 ----
	d.NcLogFiles = listNextcloudLogFiles(filepath.Join(ncDir, "data"), 7)

	// ---- DB 容量 (mysql CLI) ----
	dbSizeMB, rawList := getDBStats(cfg)
	if dbSizeMB != "?" {
		d.DBSize = dbSizeMB + " MB"
	} else {
		d.DBSize = "?"
	}
	for _, info := range rawList {
		d.DBList = append(d.DBList, DBInfo{Name: info.Name, Size: info.Size + " MB"})
	}

	// ---- Nginx アクセスログ解析（logs/nginx.jsonl から） ----
	todayStr := time.Now().Format("2006-01-02")
	ipCounts := map[string]int{}
	_ = ScanJSONL[NginxLogEvent](webAccessJSONLPath(), func(ev NginxLogEvent) bool {
		if len(ev.TS) < 10 || ev.TS[:10] != todayStr {
			return true
		}
		d.AccessToday++
		statusStr := fmt.Sprintf("%d", ev.Status)
		d.StatusCodes[statusStr]++
		if ev.IP != "" {
			ipCounts[ev.IP]++
		}
		return true
	})

	// 国別集計（geoiplookup または GeoLite2 mmdb）
	if len(ipCounts) > 0 {
		d.CountryCounts = geoipCountryCounts(ipCounts)
	}

	return d
}

// duSh は du -sh <path> の結果（サイズ部分のみ）を返す
func duSh(path string) string {
	out, err := exec.Command("du", "-sh", path).Output()
	if err != nil {
		return "?"
	}
	parts := strings.Fields(string(out))
	if len(parts) > 0 {
		return parts[0]
	}
	return "?"
}

// getDBStats は HEARTDESK_DB_DSN からDB容量をMB単位で取得して返す共通ヘルパー。
// dbSizeMB: MB数値文字列（例: "28.2"）、取得失敗時は "?"
// dbList:   DB別容量（Size は MB数値文字列のみ、単位なし）
// disk.go の GetDisk() と database.go の GetBackupAPIData() の両方から呼ばれる。
func getDBStats(cfg *config.AppConfig) (dbSizeMB string, dbList []DBInfo) {
	dsn := ""
	if cfg != nil {
		dsn = strings.TrimSpace(cfg.Database.DSN)
	}
	if dsn == "" {
		return "?", nil
	}
	dbUser, dbPass, dbSocket := parseMysqlDSN(dsn)
	if dbUser == "" {
		return "?", nil
	}
	baseArgs := []string{"-u", dbUser, "--batch", "--skip-column-names"}
	if dbSocket != "" {
		baseArgs = append(baseArgs, "-S", dbSocket)
	}
	env := append(os.Environ(), "MYSQL_PWD="+dbPass)

	sizeQuery := "SELECT ROUND(SUM(data_length+index_length)/1024/1024,1) FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','sys')"
	sizeCmd := exec.Command("mysql", append(append([]string{}, baseArgs...), "-e", sizeQuery)...)
	sizeCmd.Env = env
	if out, err := sizeCmd.Output(); err == nil {
		if v := strings.TrimSpace(string(out)); v != "" && !strings.Contains(strings.ToUpper(v), "ERROR") {
			dbSizeMB = v
		}
	}
	if dbSizeMB == "" {
		dbSizeMB = "?"
	}

	listQuery := "SELECT table_schema, ROUND(SUM(data_length+index_length)/1024/1024,1) FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','sys') GROUP BY table_schema ORDER BY SUM(data_length+index_length) DESC"
	listCmd := exec.Command("mysql", append(append([]string{}, baseArgs...), "-e", listQuery)...)
	listCmd.Env = env
	if out, err := listCmd.Output(); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if parts := strings.Split(line, "\t"); len(parts) == 2 {
				dbList = append(dbList, DBInfo{Name: parts[0], Size: parts[1]})
			}
		}
	}
	return
}

// parseMysqlDSN は go-sql-driver DSN から user / password / socket を取得する
// 形式: user:pass@unix(/run/mysqld/mysqld.sock)/dbname?options
// パスワードに @ が含まれる場合も正しく解析するため、最後の @unix( / @tcp( で分割する。
func parseMysqlDSN(dsn string) (user, pass, socket string) {
	parseUserPass := func(s string) (string, string) {
		idx := strings.Index(s, ":")
		if idx < 0 {
			return s, ""
		}
		return s[:idx], s[idx+1:]
	}

	if idx := strings.LastIndex(dsn, "@unix("); idx >= 0 {
		up := dsn[:idx]
		rest := dsn[idx+6:]
		if sockEnd := strings.Index(rest, ")"); sockEnd >= 0 {
			socket = rest[:sockEnd]
		}
		user, pass = parseUserPass(up)
		return
	}
	if idx := strings.LastIndex(dsn, "@tcp("); idx >= 0 {
		up := dsn[:idx]
		user, pass = parseUserPass(up)
		return
	}
	return
}

func listNextcloudLogFiles(dataDir string, limit int) []DiskLogFile {
	matches, err := filepath.Glob(filepath.Join(dataDir, "nextcloud.log.*.gz"))
	if err != nil || len(matches) == 0 || limit <= 0 {
		return nil
	}
	type logFile struct {
		path string
		info os.FileInfo
	}
	files := make([]logFile, 0, len(matches))
	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		files = append(files, logFile{path: path, info: info})
	}
	sort.Slice(files, func(i, j int) bool {
		mi := files[i].info.ModTime()
		mj := files[j].info.ModTime()
		if mi.Equal(mj) {
			return filepath.Base(files[i].path) < filepath.Base(files[j].path)
		}
		return mi.After(mj)
	})
	if len(files) > limit {
		files = files[:limit]
	}
	out := make([]DiskLogFile, 0, len(files))
	for _, file := range files {
		out = append(out, DiskLogFile{
			Name: filepath.Base(file.path),
			Size: duSh(file.path),
			Date: file.info.ModTime().Format("2006-01-02"),
		})
	}
	return out
}

// geoipCountryCounts は ユニークIP→件数マップから国別集計を返す
// HEARTDESK_GEOIP_DB が設定されていれば mmdb、なければ geoiplookup コマンドを使用する
func geoipCountryCounts(ipCounts map[string]int) map[string]int {
	countryCounts := map[string]int{}

	// GeoIP DB が設定されていれば GetCountryFlags を活用、なければ geoiplookup コマンドにフォールバック
	useMMDB := false
	if mmdbPath := strings.TrimSpace(os.Getenv("HEARTDESK_GEOIP_DB")); mmdbPath != "" {
		// main.go が TOML→env 橋渡し済みのため env 参照は意図的（geo.go 統一時に解消）
		if _, err := os.Stat(mmdbPath); err == nil {
			useMMDB = true
		}
	}

	// mmdb モードでは GetCountryFlags（geo.go）を使い国旗付き文字列から国名を取得する
	if useMMDB {
		ips := make([]string, 0, len(ipCounts))
		for ip := range ipCounts {
			ips = append(ips, ip)
		}
		flags := GetCountryFlags(ips)
		for ip, cnt := range ipCounts {
			country := "Unknown"
			if c, ok := flags[ip]; ok && c != "" {
				// "🇯🇵 日本" のような文字列から国名部分を取り出す
				parts := strings.SplitN(c, " ", 2)
				if len(parts) == 2 {
					country = strings.TrimSpace(parts[1])
				} else {
					country = c
				}
			}
			countryCounts[country] += cnt
		}
		return countryCounts
	}

	for ip, cnt := range ipCounts {
		country := geoipLookup(ip)
		if country == "" {
			country = "Unknown"
		}
		countryCounts[country] += cnt
	}
	return countryCounts
}

// geoipLookup は geoiplookup コマンドで国名を返す
func geoipLookup(ip string) string {
	out, err := exec.Command("geoiplookup", ip).Output()
	if err != nil || len(out) == 0 {
		return ""
	}
	line := strings.TrimSpace(string(out))
	// "GeoIP Country Edition: JP, Japan" → "Japan"
	if m := regexp.MustCompile(`:\s*[A-Z]{2},\s*(.+)`).FindStringSubmatch(line); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	// "GeoIP Country Edition: IP Address not found"
	if strings.Contains(strings.ToLower(line), "not found") {
		return "Unknown"
	}
	if m := regexp.MustCompile(`:\s*(.+)`).FindStringSubmatch(line); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// keepFmtImport は fmt パッケージの import を維持するためのダミー参照
var _ = fmt.Sprintf
