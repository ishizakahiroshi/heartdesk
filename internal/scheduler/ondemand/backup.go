package ondemand

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/r2"
)

const (
	defaultBackupDir         = "/var/backups/mariadb"
	defaultLocalRetentionDay = 7
	defaultR2RetentionDay    = 30
	defaultMaxRetries        = 2
	defaultOCCPHP            = "/usr/bin/php"
	defaultOCCPath           = "/var/www/nextcloud/occ"
	defaultConfigPHP         = "/var/www/nextcloud/config/config.php"
	defaultR2Profile         = "r2"
	defaultR2Bucket          = "nextcloud-backups"
	defaultR2Prefix          = "backups"
	defaultAWSCmd            = "/usr/local/bin/aws"
	defaultHeartbeatPath     = "data/csv/mariadb_backup_last.csv"
)

// BackupMariaDB は backup_mariadb.sh 相当の処理を Go で実行する。
func BackupMariaDB(ctx context.Context, cfg *config.SchedulerConfig) error {
	now := time.Now()
	stamp := now.Format("20060102_1504")
	backupDir := defaultBackupDir
	logPath := "/var/log/mariadb-backup.log"
	heartbeatPath := heartdesk.Path(defaultHeartbeatPath)
	if cfg != nil && strings.TrimSpace(cfg.BackupOutputDir) != "" {
		backupDir = strings.TrimSpace(cfg.BackupOutputDir)
	}
	if cfg != nil && strings.TrimSpace(cfg.BackupLogPath) != "" {
		logPath = strings.TrimSpace(cfg.BackupLogPath)
	}
	if cfg != nil && strings.TrimSpace(cfg.BackupHeartbeatPath) != "" {
		heartbeatPath = strings.TrimSpace(cfg.BackupHeartbeatPath)
	}

	logf, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o660)
	if err != nil {
		return fmt.Errorf("open backup log failed: %w", err)
	}
	defer logf.Close()

	logLine := func(level, msg string) {
		ts := time.Now().Format("2006-01-02 15:04:05")
		prefix := ""
		switch level {
		case "ERROR":
			prefix = "[ERROR] "
		case "WARN":
			prefix = "[WARN] "
		}
		_, _ = io.WriteString(logf, fmt.Sprintf("[%s] %s%s\n", ts, prefix, msg))
	}

	start := time.Now()
	logLine("", "=== MariaDB バックアップ開始 ===")

	if err := os.MkdirAll(backupDir, 0o770); err != nil {
		logLine("ERROR", "バックアップディレクトリ作成失敗: "+err.Error())
		writeBackupHeartbeat(logLine, heartbeatPath, "fail", "", 0, time.Since(start), "mkdir failed")
		return err
	}

	if _, err := exec.LookPath("zstd"); err != nil {
		logLine("ERROR", "zstd コマンドが見つかりません")
		writeBackupHeartbeat(logLine, heartbeatPath, "fail", "", 0, time.Since(start), "zstd not found")
		return fmt.Errorf("zstd not found: %w", err)
	}

	backupFile := filepath.Join(backupDir, "mariadb_full_"+stamp+".sql.zst")
	configBackup := filepath.Join(backupDir, "config_"+stamp+".php")

	maintenanceOn := false
	defer func() {
		if maintenanceOn {
			logLine("", "Nextcloud メンテナンスモードを解除します...")
			if err := runToLog(ctx, logf, "sudo", "-n", "-u", "www-data", defaultOCCPHP, defaultOCCPath, "maintenance:mode", "--off"); err != nil {
				logLine("ERROR", "Nextcloud メンテナンスモード OFF に失敗しました: "+err.Error())
			} else {
				logLine("", "Nextcloud メンテナンスモード OFF 完了")
			}
		}
	}()

	logLine("", "Nextcloud メンテナンスモードを有効化します...")
	if err := runToLog(ctx, logf, "sudo", "-n", "-u", "www-data", defaultOCCPHP, defaultOCCPath, "maintenance:mode", "--on"); err != nil {
		logLine("WARN", "メンテナンスモード ON に失敗しました。継続します: "+err.Error())
	} else {
		maintenanceOn = true
		logLine("", "Nextcloud メンテナンスモード ON 完了")
	}

	maxRetries := intEnv("SCHED_BACKUP_MAX_RETRIES", defaultMaxRetries)
	var fileSize int64
	ok := false
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			logLine("WARN", fmt.Sprintf("バックアップ失敗のためリトライします（%d/%d）", attempt, maxRetries))
		}
		if err := runDumpZstd(ctx, logf, backupFile); err != nil {
			logLine("ERROR", "mariadb-dump または zstd の実行に失敗しました: "+err.Error())
			_ = os.Remove(backupFile)
			continue
		}
		fi, err := os.Stat(backupFile)
		if err != nil || fi.Size() <= 0 {
			logLine("ERROR", "バックアップファイルが0バイトです。失敗とみなします。")
			_ = os.Remove(backupFile)
			continue
		}
		fileSize = fi.Size()
		logLine("", fmt.Sprintf("データベースダンプ完了: %s (%s)", backupFile, humanBytes(fileSize)))
		ok = true
		break
	}
	if !ok {
		logLine("ERROR", "バックアップに失敗しました。リトライ上限を超えました。")
		writeBackupHeartbeat(logLine, heartbeatPath, "fail", filepath.Base(backupFile), fileSize, time.Since(start), "dump failed")
		return fmt.Errorf("backup dump failed after retries")
	}

	configPath := stringEnv("SCHED_BACKUP_CONFIG_PATH", defaultConfigPHP)
	if fi, err := os.Stat(configPath); err == nil && !fi.IsDir() {
		if err := runToLog(ctx, logf, "sudo", "-n", "cp", configPath, configBackup); err != nil {
			logLine("ERROR", "config.php バックアップに失敗しました: "+err.Error())
		} else {
			if user := strings.TrimSpace(os.Getenv("USER")); user != "" {
				_ = runToLog(ctx, logf, "sudo", "-n", "chown", user+":"+user, configBackup)
			}
			logLine("", "config.php バックアップ完了: "+configBackup)
		}
	} else {
		logLine("WARN", "config.php が見つかりません: "+configPath)
	}

	uploadToR2(ctx, logf, backupFile, configBackup, logLine, cfg)
	cleanupLocalBackups(backupDir, logLine)
	cleanupR2Backups(ctx, logf, logLine, cfg)

	elapsed := time.Since(start)
	logLine("", fmt.Sprintf("バックアップ完了: %s (%s, %d秒)", backupFile, humanBytes(fileSize), int(elapsed.Seconds())))
	logLine("", "=== MariaDB バックアップ正常終了 ===")
	writeBackupHeartbeat(logLine, heartbeatPath, "success", filepath.Base(backupFile), fileSize, elapsed, "")
	return nil
}

func runDumpZstd(ctx context.Context, logw io.Writer, outPath string) error {
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	dumpCmd := exec.CommandContext(ctx, "sudo", "-n", "/usr/bin/mariadb-dump",
		"--all-databases", "--single-transaction", "--routines", "--triggers", "--events")
	zstdCmd := exec.CommandContext(ctx, "zstd", "-T0")

	pipe, err := dumpCmd.StdoutPipe()
	if err != nil {
		return err
	}
	dumpCmd.Stderr = logw
	zstdCmd.Stdin = pipe
	zstdCmd.Stdout = out
	zstdCmd.Stderr = logw

	if err := zstdCmd.Start(); err != nil {
		return err
	}
	if err := dumpCmd.Start(); err != nil {
		_ = zstdCmd.Wait()
		return err
	}
	if err := dumpCmd.Wait(); err != nil {
		_ = zstdCmd.Wait()
		return err
	}
	return zstdCmd.Wait()
}

func runToLog(ctx context.Context, logw io.Writer, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = logw
	cmd.Stderr = logw
	return cmd.Run()
}

func uploadToR2(ctx context.Context, logw io.Writer, backupFile, configBackup string, logLine func(string, string), cfg *config.SchedulerConfig) {
	awsCmd := stringEnv("SCHED_R2_AWS_CMD", defaultAWSCmd)
	if _, err := os.Stat(awsCmd); err != nil {
		if p, lpErr := exec.LookPath("aws"); lpErr == nil {
			awsCmd = p
		} else {
			logLine("WARN", "AWS CLI が見つからないため R2 アップロードをスキップします")
			return
		}
	}

	profile := stringEnv("SCHED_R2_PROFILE", defaultR2Profile)
	endpoint := stringEnv("SCHED_R2_ENDPOINT", "")
	if endpoint == "" && cfg != nil {
		endpoint = r2.EndpointURL(cfg.R2AccountID)
	}
	if endpoint == "" {
		logLine("WARN", "R2 endpoint 未設定のためアップロードをスキップします")
		return
	}

	bucket := stringEnv("SCHED_R2_BUCKET", defaultR2Bucket)
	prefix := strings.Trim(strings.TrimSpace(stringEnv("SCHED_R2_PREFIX", defaultR2Prefix)), "/")
	base := "s3://" + bucket + "/" + prefix
	common := []string{"--profile", profile, "--endpoint-url", endpoint}

	logLine("", "R2へDBダンプをアップロード中...")
	argsDB := append([]string{"s3", "cp", backupFile, base + "/db/" + filepath.Base(backupFile)}, common...)
	if err := runToLog(ctx, logw, awsCmd, argsDB...); err != nil {
		logLine("ERROR", "R2へのDBアップロードに失敗しました: "+err.Error())
	} else {
		logLine("", "R2アップロード完了（DB）")
	}

	if fi, err := os.Stat(configBackup); err == nil && !fi.IsDir() {
		logLine("", "R2へconfig.phpをアップロード中...")
		argsCfg := append([]string{"s3", "cp", configBackup, base + "/config/" + filepath.Base(configBackup)}, common...)
		if err := runToLog(ctx, logw, awsCmd, argsCfg...); err != nil {
			logLine("ERROR", "R2へのconfigアップロードに失敗しました: "+err.Error())
		} else {
			logLine("", "R2アップロード完了（config）")
		}
	}
}

func cleanupLocalBackups(backupDir string, logLine func(string, string)) {
	retention := intEnv("SCHED_BACKUP_LOCAL_RETENTION_DAYS", defaultLocalRetentionDay)
	threshold := time.Now().AddDate(0, 0, -retention)
	patterns := []string{"*.sql.zst", "config_*.php"}
	deleted := 0
	for _, p := range patterns {
		files, _ := filepath.Glob(filepath.Join(backupDir, p))
		for _, f := range files {
			fi, err := os.Stat(f)
			if err != nil || fi.ModTime().After(threshold) {
				continue
			}
			if os.Remove(f) == nil {
				deleted++
			}
		}
	}
	if deleted > 0 {
		logLine("", fmt.Sprintf("ローカル: %d 件の古いバックアップを削除しました（%d日以上前）", deleted, retention))
	}
}

func cleanupR2Backups(ctx context.Context, logw io.Writer, logLine func(string, string), cfg *config.SchedulerConfig) {
	awsCmd := stringEnv("SCHED_R2_AWS_CMD", defaultAWSCmd)
	if _, err := os.Stat(awsCmd); err != nil {
		if p, lpErr := exec.LookPath("aws"); lpErr == nil {
			awsCmd = p
		} else {
			return
		}
	}
	profile := stringEnv("SCHED_R2_PROFILE", defaultR2Profile)
	endpoint := stringEnv("SCHED_R2_ENDPOINT", "")
	if endpoint == "" && cfg != nil {
		endpoint = r2.EndpointURL(cfg.R2AccountID)
	}
	if endpoint == "" {
		return
	}
	bucket := stringEnv("SCHED_R2_BUCKET", defaultR2Bucket)
	prefix := strings.Trim(strings.TrimSpace(stringEnv("SCHED_R2_PREFIX", defaultR2Prefix)), "/")
	base := "s3://" + bucket + "/" + prefix
	retention := intEnv("SCHED_BACKUP_R2_RETENTION_DAYS", defaultR2RetentionDay)
	threshold := time.Now().AddDate(0, 0, -retention).Format("20060102")
	common := []string{"--profile", profile, "--endpoint-url", endpoint}

	deleteInPath := func(path string) int {
		listArgs := append([]string{"s3", "ls", path}, common...)
		cmd := exec.CommandContext(ctx, awsCmd, listArgs...)
		out, err := cmd.Output()
		if err != nil {
			return 0
		}
		deleted := 0
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			filename := fields[len(fields)-1]
			dateToken := regexp.MustCompile(`\d{8}`).FindString(filename)
			if dateToken == "" || dateToken >= threshold {
				continue
			}
			rmArgs := append([]string{"s3", "rm", path + filename}, common...)
			if runToLog(ctx, logw, awsCmd, rmArgs...) == nil {
				deleted++
			}
		}
		return deleted
	}

	dbDeleted := deleteInPath(base + "/db/")
	cfgDeleted := deleteInPath(base + "/config/")
	total := dbDeleted + cfgDeleted
	if total > 0 {
		logLine("", fmt.Sprintf("R2: %d 件の古いバックアップを削除しました（%d日以上前）", total, retention))
	}
}

func writeBackupHeartbeat(logLine func(string, string), path, status, file string, size int64, elapsed time.Duration, msg string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o770); err != nil {
		logLine("WARN", "heartbeat ディレクトリ作成失敗: "+err.Error())
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o660)
	if err != nil {
		logLine("WARN", "heartbeat 書き込み失敗: "+err.Error())
		return
	}
	defer f.Close()

	info, _ := f.Stat()
	w := csv.NewWriter(f)
	if info == nil || info.Size() == 0 {
		_ = w.Write([]string{"timestamp", "status", "file", "size_bytes", "elapsed_sec", "message"})
	}
	_ = w.Write([]string{
		time.Now().Format(time.RFC3339),
		status,
		file,
		strconv.FormatInt(size, 10),
		strconv.Itoa(int(elapsed.Seconds())),
		msg,
	})
	w.Flush()
}

func intEnv(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

func stringEnv(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func humanBytes(n int64) string {
	if n <= 0 {
		return "0 B"
	}
	unit := []string{"B", "KB", "MB", "GB", "TB"}
	size := float64(n)
	idx := 0
	for size >= 1024 && idx < len(unit)-1 {
		size /= 1024
		idx++
	}
	return fmt.Sprintf("%.1f %s", size, unit[idx])
}
