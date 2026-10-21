package ondemand

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/filelock"
)

const (
	defaultAptLockPath = "/var/lock/heartdesk-apt-update.lock"
	defaultOCCBin      = "/usr/bin/php"
	defaultOCCScript   = "/var/www/nextcloud/occ"
	aptLogKeep         = 10
)

type aptState struct {
	Status          string  `json:"status"`
	Mode            string  `json:"mode"`
	StartedAt       string  `json:"started_at"`
	CompletedAt     *string `json:"completed_at"`
	ExitCode        *int    `json:"exit_code"`
	LogPath         string  `json:"log_path"`
	Summary         string  `json:"summary"`
	MaintenanceLeft bool    `json:"maintenance_left_on"`
}

// apt 管理ジョブの状態ファイル・ログの置き場所。HEARTDESK_BASE_DIR 基準（未設定なら /var/lib/heartdesk 配下）。
func defaultAptStateDir() string  { return heartdesk.PathOrDefault("data/json") }
func defaultAptStatePath() string { return heartdesk.PathOrDefault("data/json/apt_update_state.json") }
func defaultAptLogDir() string    { return heartdesk.PathOrDefault("data/log") }

// RunAptUpgradeManaged は apt_update_runner.sh 相当の処理を Go で実行する。
// mode は "upgrade" または "full-upgrade"。
func RunAptUpgradeManaged(ctx context.Context, _ *config.SchedulerConfig, mode string) error {
	if mode != "upgrade" && mode != "full-upgrade" {
		return fmt.Errorf("invalid apt mode: %s", mode)
	}

	statePath := defaultAptStatePath()
	logDir := defaultAptLogDir()
	lockPath := defaultAptLockPath

	if err := os.MkdirAll(filepath.Dir(statePath), 0o770); err != nil {
		return fmt.Errorf("apt state dir create failed: %w", err)
	}
	if err := os.MkdirAll(logDir, 0o770); err != nil {
		return fmt.Errorf("apt log dir create failed: %w", err)
	}

	// Unix 系では flock で多重起動防止。非 Unix 環境では no-op。
	unlock, err := filelock.Acquire(lockPath)
	if err != nil {
		if errors.Is(err, filelock.ErrLocked) {
			now := time.Now().Format(time.RFC3339)
			writeState(statePath, aptState{
				Status:    "already_running",
				Mode:      mode,
				StartedAt: now,
				LogPath:   "",
				Summary:   "apt managed job is already running",
			})
			return nil
		}
		return fmt.Errorf("apt lock acquire failed: %w", err)
	}
	defer unlock()

	now := time.Now()
	logPath := filepath.Join(logDir, "apt_update_"+now.Format("20060102_150405")+".log")
	startedAt := now.Format(time.RFC3339)

	writeState(statePath, aptState{
		Status:          "running",
		Mode:            mode,
		StartedAt:       startedAt,
		LogPath:         logPath,
		MaintenanceLeft: true,
	})

	logF, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("apt log open failed: %w", err)
	}
	defer logF.Close()

	logLine := func(s string) {
		_, _ = fmt.Fprintln(logF, s)
	}
	logLine(fmt.Sprintf("=== started: %s (mode=%s) ===", startedAt, mode))

	rc := runAptSteps(ctx, logF, mode)
	finishedAt := time.Now().Format(time.RFC3339)

	summary := extractAptSummary(logPath)
	exitCode := rc

	if rc == 0 {
		_ = occRun(logF, "maintenance:mode", "--off")
		writeState(statePath, aptState{
			Status:          "success",
			Mode:            mode,
			StartedAt:       startedAt,
			CompletedAt:     &finishedAt,
			ExitCode:        &exitCode,
			LogPath:         logPath,
			Summary:         summary,
			MaintenanceLeft: false,
		})
	} else {
		writeState(statePath, aptState{
			Status:          "failed",
			Mode:            mode,
			StartedAt:       startedAt,
			CompletedAt:     &finishedAt,
			ExitCode:        &exitCode,
			LogPath:         logPath,
			Summary:         summary,
			MaintenanceLeft: true,
		})
	}
	logLine(fmt.Sprintf("=== finished: %s (rc=%d) ===", finishedAt, rc))

	trimAptLogs(logDir)

	if rc != 0 {
		return fmt.Errorf("apt %s failed with exit code %d", mode, rc)
	}
	return nil
}

func runAptSteps(ctx context.Context, logF *os.File, mode string) int {
	if err := occRun(logF, "maintenance:mode", "--on"); err != nil {
		return 1
	}
	if rc := runCmd(ctx, logF, "/usr/bin/apt-get", "update"); rc != 0 {
		return rc
	}
	return runCmd(ctx, logF,
		"/usr/bin/apt-get",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "Dpkg::Options::=--force-confdef",
		"-y", mode,
	)
}

func occRun(logF *os.File, args ...string) error {
	cmdArgs := append([]string{defaultOCCScript}, args...)
	cmd := exec.Command(defaultOCCBin, cmdArgs...)
	cmd.Stdout = logF
	cmd.Stderr = logF
	return cmd.Run()
}

func runCmd(ctx context.Context, logF *os.File, name string, args ...string) int {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = logF
	cmd.Stderr = logF
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		return 1
	}
	return 0
}

func extractAptSummary(logPath string) string {
	raw, err := os.ReadFile(logPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "0 upgraded") ||
			(len(line) > 0 && line[0] >= '0' && line[0] <= '9' && strings.Contains(line, "upgraded")) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func writeState(path string, s aptState) {
	buf, err := json.Marshal(s)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

func trimAptLogs(logDir string) {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return
	}
	var logs []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "apt_update_") && strings.HasSuffix(e.Name(), ".log") {
			logs = append(logs, filepath.Join(logDir, e.Name()))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(logs)))
	for _, p := range logs[min(aptLogKeep, len(logs)):] {
		_ = os.Remove(p)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
