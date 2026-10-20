package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/scheduler/ondemand"
)

// GetUpdatesData はシステムアップデート情報を取得する（api_legacy.php handle_updates 相当）。
// agentID が指定された場合は、該当 Agent の最新レポートに含まれる updates collector を返す。
// レポート未受信 / FreeBSD（updates 非対応）の場合は Unavailable=true を返す。
func GetUpdatesData(agentID ...string) UpdatesData {
	if len(agentID) > 0 && agentID[0] != "" {
		return updatesDataFromAgentReport(agentID[0])
	}
	// unattended-upgrades サービス状態
	updateSvc := sab.Run("systemctl is-active unattended-upgrades 2>/dev/null")

	// auto update設定値
	updateAuto := sab.Run("apt-config dump APT::Periodic::Unattended-Upgrade 2>/dev/null")
	if updateAuto == "" {
		updateAuto = `APT::Periodic::Unattended-Upgrade "0";`
	}

	// アップグレード可能パッケージ一覧（ヘッダ行を除く）
	listRaw := sab.Run("apt list --upgradable 2>/dev/null | tail -n +2")
	var updateList []string
	if listRaw != "" {
		for _, line := range strings.Split(listRaw, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				updateList = append(updateList, line)
			}
		}
	}

	// unattended-upgrades ログ末尾 30行
	updateLog := sab.Run("tail -30 /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null")

	// 最終インストール時刻（history.log の mtime — install/upgrade 実行時のみ更新）
	updateLast := formatStatMtime(sab.Run("stat -c '%y' /var/log/apt/history.log 2>/dev/null"))
	// 最終リスト更新時刻（apt-get update が成功するたびに touch される stamp ファイル）
	updateListLast := formatStatMtime(sab.Run("stat -c '%y' /var/lib/apt/periodic/update-success-stamp 2>/dev/null"))

	// Ubuntu バージョン
	ubuntuVer := sab.Run("lsb_release -ds 2>/dev/null")
	if ubuntuVer == "" {
		ubuntuVer = readOSPrettyName()
	}

	// 自動更新が有効か（サービスactive かつ設定値 "1"）
	autoEnabled := strings.TrimSpace(updateSvc) == "active" && strings.Contains(updateAuto, `"1"`)

	// カーネル情報
	k := GetKernel()

	// apt-mark hold で明示的に保留されたパッケージ一覧
	heldRaw := sab.Run("apt-mark showhold 2>/dev/null")
	var heldPackages []string
	if heldRaw != "" {
		for _, line := range strings.Split(heldRaw, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				heldPackages = append(heldPackages, line)
			}
		}
	}

	return UpdatesData{
		UpdateSvc:      updateSvc,
		UpdateAuto:     updateAuto,
		AutoEnabled:    autoEnabled,
		UpdateCount:    len(updateList),
		UpdateList:     updateList,
		UpdateLog:      updateLog,
		UpdateLast:     updateLast,
		UpdateListLast: updateListLast,
		UbuntuVer:      ubuntuVer,
		KernelCurrent:  k.Current,
		KernelLatest:   k.Latest,
		KernelOutdated: k.Outdated,
		HeldCount:      len(heldPackages),
		HeldPackages:   heldPackages,
		IsLocal:        true,
	}
}

// updatesDataFromAgentReport は agentID の最新レポートから updates collector を取り出して
// UpdatesData に詰め直す。受信なし / FreeBSD等で updates が含まれない場合は Unavailable=true。
func updatesDataFromAgentReport(agentID string) UpdatesData {
	raw, ok := GetAgentLatestCollector(agentID, "updates")
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return UpdatesData{Unavailable: true}
	}
	var d UpdatesData
	if err := json.Unmarshal(raw, &d); err != nil {
		return UpdatesData{Unavailable: true}
	}
	// IsLocal は明示的に false（リモート Agent）にする
	d.IsLocal = false
	return d
}

// formatStatMtime は `stat -c '%y'` の出力（例: "2026-04-15 12:34:56.123456789 +0900"）から
// "YYYY-MM-DD HH:MM:SS" を抽出する。空入力は空文字を返す。
func formatStatMtime(statOut string) string {
	if statOut == "" {
		return ""
	}
	parts := strings.Fields(statOut)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + " " + strings.SplitN(parts[1], ".", 2)[0]
}

func humanGiB(bytes int64) string {
	if bytes <= 0 {
		return ""
	}
	return fmt.Sprintf("%.2f GiB", float64(bytes)/(1024*1024*1024))
}

func readCPUModel() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "model name") {
			continue
		}
		if idx := strings.Index(line, ":"); idx >= 0 {
			return strings.TrimSpace(line[idx+1:])
		}
	}
	return ""
}

func readCPUCores() int {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 0
	}
	cores := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "processor") {
			cores++
		}
	}
	return cores
}

func readOSPrettyName() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "PRETTY_NAME=") {
			continue
		}
		return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
	}
	return ""
}

// RunAptUpdate は apt-get update（パッケージリスト更新）をバックグラウンドで開始する
func RunAptUpdate() {
	go func() {
		cmd := exec.Command("sudo", "/usr/bin/apt-get", "update")
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil {
			log.Printf("ERROR: monitor: apt-get update failed: %v", err)
		}
	}()
}

// RunAptUpgrade は apt-get upgrade を managed モードでバックグラウンド実行する
func RunAptUpgrade() {
	go func() {
		if err := ondemand.RunAptUpgradeManaged(context.Background(), nil, "upgrade"); err != nil {
			log.Printf("ERROR: monitor: apt upgrade managed failed: %v", err)
		}
	}()
}

// RunAptFullUpgrade は apt-get full-upgrade を managed モードでバックグラウンド実行する
func RunAptFullUpgrade() {
	go func() {
		if err := ondemand.RunAptUpgradeManaged(context.Background(), nil, "full-upgrade"); err != nil {
			log.Printf("ERROR: monitor: apt full-upgrade managed failed: %v", err)
		}
	}()
}

// ToggleAutoUpdate は unattended-upgrades を有効/無効にする
func ToggleAutoUpdate(enable bool) error {
	val := "0"
	if enable {
		val = "1"
	}
	content := fmt.Sprintf(
		"APT::Periodic::Update-Package-Lists \"%s\";\nAPT::Periodic::Unattended-Upgrade \"%s\";\n",
		val, val,
	)
	// 設定ファイル書き込み（stdin 経由で tee に渡し、改行を正しく保つ）
	cmd := exec.Command("sudo", "/usr/bin/tee", "/etc/apt/apt.conf.d/20auto-upgrades")
	cmd.Stdin = strings.NewReader(content)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return err
	}
	// サービス制御（ベストエフォート: 権限不足でも設定変更は反映済みなので無視）
	if enable {
		_ = exec.Command("sudo", "/usr/bin/systemctl", "enable", "unattended-upgrades").Run()
		_ = exec.Command("sudo", "/usr/bin/systemctl", "start", "unattended-upgrades").Run()
	} else {
		_ = exec.Command("sudo", "/usr/bin/systemctl", "stop", "unattended-upgrades").Run()
		_ = exec.Command("sudo", "/usr/bin/systemctl", "disable", "unattended-upgrades").Run()
	}
	return nil
}
