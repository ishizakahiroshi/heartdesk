package daemon

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

const (
	defaultResourceLogPath  = "data/csv/resource_log.csv"
	defaultCollectLogPath   = "/var/log/collect_resources.log"
	defaultCollectHeartbeat = "data/csv/resource_check_last.csv"
	defaultMaxLines         = 2016
)

// CollectResources は collect_resources.sh 相当のリソース監視CSV追記を実行する。
func CollectResources(ctx context.Context, cfg *config.SchedulerConfig) error {
	resourceLogPath := sab.SabPath(defaultResourceLogPath)
	collectLogPath := defaultCollectLogPath
	heartbeatPath := sab.SabPath(defaultCollectHeartbeat)
	if cfg != nil && strings.TrimSpace(cfg.ResourceLogPath) != "" {
		resourceLogPath = strings.TrimSpace(cfg.ResourceLogPath)
	}
	if cfg != nil && strings.TrimSpace(cfg.CollectLogPath) != "" {
		collectLogPath = strings.TrimSpace(cfg.CollectLogPath)
	}
	if cfg != nil && strings.TrimSpace(cfg.CollectHeartbeatPath) != "" {
		heartbeatPath = strings.TrimSpace(cfg.CollectHeartbeatPath)
	}

	logLine, closeLog, err := openCollectLogger(collectLogPath)
	if err != nil {
		return err
	}
	defer closeLog()

	cpu, err := cpuUsagePercent(ctx)
	if err != nil {
		writeCollectHeartbeat(logLine, heartbeatPath, "fail", 0, 0, 0, "cpu read failed: "+err.Error())
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	mem, err := memoryUsagePercent()
	if err != nil {
		writeCollectHeartbeat(logLine, heartbeatPath, "fail", cpu, 0, 0, "memory read failed: "+err.Error())
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	disk, err := rootDiskUsagePercent()
	if err != nil {
		writeCollectHeartbeat(logLine, heartbeatPath, "fail", cpu, mem, 0, "disk read failed: "+err.Error())
		return err
	}

	timestamp := time.Now().Format(time.RFC3339)
	line := fmt.Sprintf("%s,%.1f,%.1f,%d", timestamp, cpu, mem, disk)
	if err := appendCSVLine(resourceLogPath, line); err != nil {
		writeCollectHeartbeat(logLine, heartbeatPath, "fail", cpu, mem, disk, "csv append failed: "+err.Error())
		return err
	}
	if err := trimCSVMaxLines(resourceLogPath, defaultMaxLines); err != nil {
		writeCollectHeartbeat(logLine, heartbeatPath, "fail", cpu, mem, disk, "csv trim failed: "+err.Error())
		return err
	}

	logLine("", fmt.Sprintf("resource sample recorded: ts=%s cpu=%.1f mem=%.1f disk=%d", timestamp, cpu, mem, disk))
	writeCollectHeartbeat(logLine, heartbeatPath, "success", cpu, mem, disk, "")
	return nil
}

func openCollectLogger(path string) (func(level, msg string), func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o770); err != nil {
		return nil, nil, fmt.Errorf("collect log dir create failed: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o660)
	if err != nil {
		return nil, nil, fmt.Errorf("open collect log failed: %w", err)
	}
	logLine := func(level, msg string) {
		ts := time.Now().Format("2006-01-02 15:04:05")
		prefix := ""
		switch level {
		case "ERROR":
			prefix = "[ERROR] "
		case "WARN":
			prefix = "[WARN] "
		}
		_, _ = io.WriteString(f, fmt.Sprintf("[%s] %s%s\n", ts, prefix, msg))
	}
	return logLine, func() { _ = f.Close() }, nil
}

func appendCSVLine(path, line string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o770); err != nil {
		return fmt.Errorf("resource log dir create failed: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o660)
	if err != nil {
		return fmt.Errorf("resource log open failed: %w", err)
	}
	defer f.Close()
	if _, err := io.WriteString(f, line+"\n"); err != nil {
		return fmt.Errorf("resource log write failed: %w", err)
	}
	return nil
}

func trimCSVMaxLines(path string, maxLines int) error {
	if maxLines <= 0 {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("resource log read failed: %w", err)
	}
	text := strings.TrimRight(string(raw), "\n")
	if text == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	if len(lines) <= maxLines {
		return nil
	}
	lines = lines[len(lines)-maxLines:]
	rebuilt := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(rebuilt), 0o660); err != nil {
		return fmt.Errorf("resource log rewrite failed: %w", err)
	}
	return nil
}

func cpuUsagePercent(ctx context.Context) (float64, error) {
	idle1, total1, err := readCPUStat()
	if err != nil {
		return 0, err
	}
	// 2 スナップショット間の待機。daemon シャットダウン時に即座に抜けられるよう
	// time.Sleep ではなく ctx キャンセルを監視する。
	select {
	case <-time.After(250 * time.Millisecond):
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	idle2, total2, err := readCPUStat()
	if err != nil {
		return 0, err
	}
	totalDelta := total2 - total1
	idleDelta := idle2 - idle1
	if totalDelta <= 0 {
		return 0, fmt.Errorf("invalid cpu stat delta")
	}
	pct := (1.0 - float64(idleDelta)/float64(totalDelta)) * 100.0
	return round1(pct), nil
}

func readCPUStat() (idle, total uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, fmt.Errorf("open /proc/stat failed: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			return 0, 0, fmt.Errorf("unexpected cpu stat format")
		}
		var vals []uint64
		for _, v := range fields[1:] {
			n, convErr := strconv.ParseUint(v, 10, 64)
			if convErr != nil {
				return 0, 0, fmt.Errorf("parse cpu stat failed: %w", convErr)
			}
			vals = append(vals, n)
			total += n
		}
		idle = vals[3]
		if len(vals) > 4 {
			idle += vals[4]
		}
		return idle, total, nil
	}
	if err := sc.Err(); err != nil {
		return 0, 0, fmt.Errorf("scan /proc/stat failed: %w", err)
	}
	return 0, 0, fmt.Errorf("cpu aggregate line not found")
}

func memoryUsagePercent() (float64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, fmt.Errorf("open /proc/meminfo failed: %w", err)
	}
	defer f.Close()

	var totalKB, availKB float64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			totalKB = parseMemInfoKB(line)
		}
		if strings.HasPrefix(line, "MemAvailable:") {
			availKB = parseMemInfoKB(line)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("scan /proc/meminfo failed: %w", err)
	}
	if totalKB <= 0 {
		return 0, fmt.Errorf("MemTotal missing")
	}
	if availKB < 0 {
		availKB = 0
	}
	usedPct := (totalKB - availKB) / totalKB * 100.0
	return round1(usedPct), nil
}

func parseMemInfoKB(line string) float64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return 0
	}
	return v
}

func rootDiskUsagePercent() (int, error) {
	// collect_resources.sh と同様に df / の Use% を参照する。
	out, err := exec.Command("df", "/").Output()
	if err != nil {
		return 0, fmt.Errorf("df command failed: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("unexpected df output")
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 5 {
		return 0, fmt.Errorf("unexpected df columns")
	}
	pctStr := strings.TrimSuffix(fields[4], "%")
	pct, convErr := strconv.Atoi(pctStr)
	if convErr != nil {
		return 0, fmt.Errorf("parse disk percent failed: %w", convErr)
	}
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct, nil
}

func writeCollectHeartbeat(logLine func(level, msg string), path, status string, cpu, mem float64, disk int, msg string) {
	if err := os.MkdirAll(filepath.Dir(path), 0o770); err != nil {
		logLine("WARN", "collect heartbeat dir create failed: "+err.Error())
		return
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o660)
	if err != nil {
		logLine("WARN", "collect heartbeat open failed: "+err.Error())
		return
	}
	defer f.Close()

	info, _ := f.Stat()
	w := csv.NewWriter(f)
	if info == nil || info.Size() == 0 {
		_ = w.Write([]string{"timestamp", "status", "cpu_pct", "memory_pct", "disk_pct", "message"})
	}
	_ = w.Write([]string{
		time.Now().Format(time.RFC3339),
		status,
		fmt.Sprintf("%.1f", cpu),
		fmt.Sprintf("%.1f", mem),
		strconv.Itoa(disk),
		msg,
	})
	w.Flush()
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}
