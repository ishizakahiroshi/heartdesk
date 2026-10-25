package ondemand

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	defaultAptGetBin   = "/usr/bin/apt-get"
	occRunAsUser       = "www-data"
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
	lockPath := heartdesk.OperationalIdentity().AptUpdateLockPath

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

	// Nextcloud の occ があるホストだけ maintenance:mode の手順を行う。
	hasOCC := occAvailable()

	now := time.Now()
	logPath := filepath.Join(logDir, "apt_update_"+now.Format("20060102_150405")+".log")
	startedAt := now.Format(time.RFC3339)

	writeState(statePath, aptState{
		Status:          "running",
		Mode:            mode,
		StartedAt:       startedAt,
		LogPath:         logPath,
		MaintenanceLeft: hasOCC,
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

	rc, failure := runAptSteps(ctx, logF, mode, hasOCC)
	finishedAt := time.Now().Format(time.RFC3339)

	summary := extractAptSummary(logPath)
	exitCode := rc

	if rc == 0 {
		if hasOCC {
			// 失敗の内容は occRun が logF に残す。状態ファイルの扱いは従来どおり。
			_ = occRun(logF, "maintenance:mode", "--off")
		}
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
			MaintenanceLeft: hasOCC,
		})
	}
	logLine(fmt.Sprintf("=== finished: %s (rc=%d) ===", finishedAt, rc))

	trimAptLogs(logDir)

	if rc != 0 {
		if failure != nil {
			return fmt.Errorf("apt %s failed with exit code %d (%s)", mode, rc, failure.String())
		}
		return fmt.Errorf("apt %s failed with exit code %d", mode, rc)
	}
	return nil
}

// aptStepFailure は apt 管理ジョブの失敗した手順と、その出力の末尾を表す（ログ・返却エラー用）。
type aptStepFailure struct {
	Step string
	Tail string
}

func (f aptStepFailure) String() string {
	if f.Tail == "" {
		return f.Step
	}
	return f.Step + ": " + f.Tail
}

// aptSteps が実行する外部コマンドの実行器（テストで差し替える）。出力は w へ書き、終了コードを返す。
var aptExec = execStep

// occScriptPath は Nextcloud の occ のパス（テストで差し替える）。
var occScriptPath = defaultOCCScript

// occAvailable は Nextcloud の occ が存在するかを返す。無いホスト（Nextcloud なし）では
// maintenance:mode の手順を飛ばす。
func occAvailable() bool {
	info, err := os.Stat(occScriptPath)
	return err == nil && !info.IsDir()
}

// occCommand は occ を www-data で実行するコマンド行を返す。heartdesk は root でも www-data でもない
// ユーザーで動くので、services.go / backup.go と同じく sudo -n -u www-data 経由にする。
func occCommand(args ...string) (string, []string) {
	argv := append([]string{"-n", "-u", occRunAsUser, defaultOCCBin, occScriptPath}, args...)
	return "sudo", argv
}

// aptGetCommand は apt-get を sudo -n 経由で実行するコマンド行を返す。
func aptGetCommand(args ...string) (string, []string) {
	argv := append([]string{"-n", defaultAptGetBin}, args...)
	return "sudo", argv
}

// runAptSteps は maintenance:mode（occ がある場合のみ）→ apt-get update → apt-get <mode> を実行する。
// 失敗したときは終了コードと、どの手順がなぜ失敗したか（出力の末尾つき）を返す。
func runAptSteps(ctx context.Context, logF io.Writer, mode string, withOCC bool) (int, *aptStepFailure) {
	logLine := func(s string) { _, _ = fmt.Fprintln(logF, s) }
	if withOCC {
		if rc, f := runStep(ctx, logF, "occ maintenance:mode --on", occCommand, "maintenance:mode", "--on"); rc != 0 {
			return 1, f
		}
	} else {
		logLine(fmt.Sprintf("occ not found at %s: skip maintenance:mode (Nextcloud なし)", occScriptPath))
	}
	if rc, f := runStep(ctx, logF, "apt-get update", aptGetCommand, "update"); rc != 0 {
		return rc, f
	}
	rc, f := runStep(ctx, logF, "apt-get "+mode, aptGetCommand,
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "Dpkg::Options::=--force-confdef",
		"-y", mode,
	)
	return rc, f
}

// runStep は 1 手順を実行する。失敗したときは、出力の末尾を logF とエラー用の戻り値に残す。
func runStep(ctx context.Context, logF io.Writer, label string, build func(args ...string) (string, []string), args ...string) (int, *aptStepFailure) {
	name, argv := build(args...)
	tail := &tailBuffer{max: aptFailureTailBytes}
	rc := aptExec(ctx, io.MultiWriter(logF, tail), name, argv...)
	if rc == 0 {
		return 0, nil
	}
	f := &aptStepFailure{Step: fmt.Sprintf("%s failed (rc=%d)", label, rc), Tail: tail.String()}
	_, _ = fmt.Fprintln(logF, "ERROR: "+f.String())
	return rc, f
}

// occRun は occ を実行し、出力を logF へ書く。失敗したときはエラーと出力の末尾を logF に残す。
func occRun(logF io.Writer, args ...string) error {
	rc, _ := runStep(context.Background(), logF, "occ "+strings.Join(args, " "), occCommand, args...)
	if rc != 0 {
		return fmt.Errorf("occ %s failed (rc=%d)", strings.Join(args, " "), rc)
	}
	return nil
}

// execStep は外部コマンドを実行し、終了コードを返す（起動できなかった場合は 1 と理由を w へ書く）。
func execStep(ctx context.Context, w io.Writer, name string, args ...string) int {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = w
	cmd.Stderr = w
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		_, _ = fmt.Fprintf(w, "%s: %v\n", name, err)
		return 1
	}
	return 0
}

// aptFailureTailBytes は失敗時にログ・エラーへ残す出力末尾の最大バイト数。
const aptFailureTailBytes = 400

// tailBuffer は書き込まれた内容の末尾 max バイトだけを保持する io.Writer。
type tailBuffer struct {
	max int
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

// String は末尾の内容を、改行・連続空白を 1 つの空白にまとめて返す。
func (t *tailBuffer) String() string {
	return strings.Join(strings.Fields(strings.ToValidUTF8(string(t.buf), "")), " ")
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
