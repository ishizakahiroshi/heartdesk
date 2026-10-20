package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

const backupDir = "/var/backups/mariadb"
const ncBackupDir = "/var/backups/nextcloud-db"

// GetDatabaseData はバックアップカードの SSR 初期データを返す（JS が非同期で描画するため空）
func GetDatabaseData() DatabaseCardData {
	return DatabaseCardData{}
}

// GetBackupAPIData はバックアップ非同期 API 用データを返す（api/backups.php api_backups 相当）
func GetBackupAPIData(cfg *config.AppConfig, agentID ...string) BackupAPIData {
	id := ""
	if len(agentID) > 0 {
		id = strings.TrimSpace(agentID[0])
	}
	if id != "" {
		if data, ok := backupAPIDataFromReport(id); ok {
			data.R2BackupFiles, data.R2ConfigFiles = loadR2BackupFileLists(cfg)
			return data
		}
		return BackupAPIData{}
	}

	// ---- ローカルバックアップ一覧（ls -lt で新しい順） ----
	backupFiles := loadLocalBackupFiles(backupDir, "*.sql.zst")

	// ---- Nextcloud DBダンプ一覧（nc-db-backup.sh の出力先。無ければ空） ----
	ncBackupFiles := loadLocalBackupFiles(ncBackupDir, "*.sql.gz")

	// ---- R2 バックアップ一覧（r2.go の R2ListFiles() で取得、30秒タイムアウト） ----
	r2BackupFiles, r2ConfigFiles := loadR2BackupFileLists(cfg)

	// ---- DB 容量一覧（バックアップ対象DB表示用） ----
	dbSizeMB, dbList := getDBStats(cfg)

	return BackupAPIData{
		BackupFiles:   backupFiles,
		NCBackupFiles: ncBackupFiles,
		R2BackupFiles: r2BackupFiles,
		R2ConfigFiles: r2ConfigFiles,
		DBSize:        dbSizeMB,
		DBList:        dbList,
	}
}

func loadLocalBackupFiles(dir, pattern string) []BackupFile {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil || len(matches) == 0 {
		return nil
	}
	type localBackup struct {
		path string
		info os.FileInfo
	}
	files := make([]localBackup, 0, len(matches))
	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		files = append(files, localBackup{path: path, info: info})
	}
	sort.Slice(files, func(i, j int) bool {
		mi := files[i].info.ModTime()
		mj := files[j].info.ModTime()
		if mi.Equal(mj) {
			return filepath.Base(files[i].path) < filepath.Base(files[j].path)
		}
		return mi.After(mj)
	})
	out := make([]BackupFile, 0, len(files))
	for _, file := range files {
		out = append(out, BackupFile{
			Name: filepath.Base(file.path),
			Size: fmt.Sprintf("%d", file.info.Size()),
			Date: heartdesk.FormatDatetime(file.info.ModTime().In(heartdesk.JST())),
		})
	}
	return out
}

func loadR2BackupFileLists(cfg *config.AppConfig) ([]BackupFile, []BackupFile) {
	var r2BackupFiles []BackupFile
	var r2ConfigFiles []BackupFile
	reR2 := regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\d+)\s+(.+)$`)
	for _, line := range R2ListFiles(cfg, "nextcloud-backups", "backups/db/") {
		if m := reR2.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			var size int64
			fmt.Sscanf(m[2], "%d", &size)
			r2BackupFiles = append(r2BackupFiles, BackupFile{Name: m[3], Size: fmt.Sprintf("%.1f MB", float64(size)/1024/1024), Date: m[1]})
		}
	}
	for _, line := range R2ListFiles(cfg, "nextcloud-backups", "backups/config/") {
		if m := reR2.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			var size int64
			fmt.Sscanf(m[2], "%d", &size)
			r2ConfigFiles = append(r2ConfigFiles, BackupFile{Name: m[3], Size: fmt.Sprintf("%.1f KB", float64(size)/1024), Date: m[1]})
		}
	}
	return r2BackupFiles, r2ConfigFiles
}
