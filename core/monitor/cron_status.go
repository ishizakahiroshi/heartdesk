package monitor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/scheduler"
)

const cronCsvDelayMultiplier = 3
const cronCsvDelayFallbackSec = 600

type cronJobSpec struct {
	key     string
	label   string
	summary string
	script  string
	kind    string // "log" / "csv"
	logFile string
	csvFile string
}

func cronJobSpecsList() []cronJobSpec {
	return []cronJobSpec{
		{
			key: "check_alerts", label: heartdesk.OperationalIdentity().AlertScriptName,
			summary: "アラート判定・メール通知",
			script:  scriptCheckAlerts(),
			kind:    "csv", csvFile: heartdesk.Path("data/json/alert_check_last.csv"),
		},
	}
}

type cronEntry struct {
	schedule string
	command  string
	source   string
	label    string // HEARTDESK_LABEL メタデータ
	summary  string // HEARTDESK_SUMMARY メタデータ
}

var reCronWhitespace = regexp.MustCompile(`\s+`)
var reCronRedirect = regexp.MustCompile(`\s+>>?\s+\S+(\s+2>&1)?$`)

func extractScriptMeta(lines []string) map[string]string {
	reScriptMeta := regexp.MustCompile(`^\s*#\s*` + regexp.QuoteMeta(heartdesk.OperationalIdentity().ScriptMetadataPrefix) + `_(\w+)=(.+)$`)
	meta := make(map[string]string)
	for _, line := range lines {
		if m := reScriptMeta.FindStringSubmatch(line); m != nil {
			meta[m[1]] = strings.TrimSpace(m[2])
		}
	}
	return meta
}

func parseCronLines(raw, source string) []cronEntry {
	var entries []cronEntry
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := reCronWhitespace.Split(line, 6)
		if len(parts) < 6 {
			continue
		}
		schedule := strings.Join(parts[:5], " ")
		command := reCronRedirect.ReplaceAllString(parts[5], "")
		entries = append(entries, cronEntry{schedule: schedule, command: command, source: source})
	}
	return entries
}

func parseCrontabEntries() []cronEntry {
	raw := heartdesk.Run("crontab -l 2>/dev/null")
	if raw == "" {
		return nil
	}
	return parseCronLines(raw, "crontab")
}

func parseSystemCronEntries() []cronEntry {
	var entries []cronEntry
	paths := []string{"/etc/crontab"}
	if files, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, f := range files {
			if !f.IsDir() {
				paths = append(paths, filepath.Join("/etc/cron.d", f.Name()))
			}
		}
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		// メタデータを抽出（コメント行から）
		metadata := extractScriptMeta(lines)
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// /etc/crontab と cron.d はユーザーフィールドが6番目
			parts := reCronWhitespace.Split(line, 7)
			if len(parts) < 6 {
				continue
			}
			schedule := strings.Join(parts[:5], " ")
			cmd := ""
			if len(parts) >= 7 {
				cmd = parts[6]
			} else {
				cmd = parts[5]
			}
			cmd = reCronRedirect.ReplaceAllString(cmd, "")
			entries = append(entries, cronEntry{
				schedule: schedule,
				command:  cmd,
				source:   path,
				label:    metadata["LABEL"],
				summary:  metadata["SUMMARY"],
			})
		}
	}
	return entries
}

func detectBackupLogStatus(logFile string) (status, lastTime string) {
	raw, err := os.ReadFile(logFile)
	if err != nil {
		return "unknown", "未取得"
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	reTime := regexp.MustCompile(`^\[([0-9:\- ]+)\]`)
	extractTime := func(line string) string {
		if m := reTime.FindStringSubmatch(line); m != nil {
			return m[1]
		}
		return ""
	}
	startIdx := -1
	startTime := ""
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], "=== MariaDB バックアップ開始 ===") {
			startIdx = i
			startTime = extractTime(lines[i])
			break
		}
	}
	if startIdx == -1 {
		if len(lines) > 0 {
			startTime = extractTime(lines[len(lines)-1])
		}
		return "unknown", startTime
	}
	for i := startIdx; i < len(lines); i++ {
		if strings.Contains(lines[i], "[ERROR]") {
			return "fail", startTime
		}
	}
	return "success", startTime
}

func detectAppendLogStatus(logFile string) (status, lastTime string) {
	raw, err := os.ReadFile(logFile)
	if err != nil {
		return "unknown", "未取得"
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 {
		return "unknown", "取得失敗"
	}
	// 最終行にタイムスタンプが含まれていれば取得
	lastLine := lines[len(lines)-1]
	reTime := regexp.MustCompile(`\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}`)
	lastTime = ""
	if m := reTime.FindString(lastLine); m != "" {
		lastTime = m
	}
	// エラー行があれば fail
	for _, line := range lines {
		if strings.Contains(line, "[ERROR]") || strings.Contains(line, "Error") {
			return "fail", lastTime
		}
	}
	return "success", lastTime
}

func detectLogStatus(logFile string) (status, lastTime string) {
	raw, err := os.ReadFile(logFile)
	if err != nil {
		return "unknown", "未取得"
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 {
		return "unknown", "取得失敗"
	}
	// 最終行からタイムスタンプを抽出
	lastLine := lines[len(lines)-1]
	reTime := regexp.MustCompile(`\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}`)
	lastTime = ""
	if m := reTime.FindString(lastLine); m != "" {
		lastTime = m
	}
	// エラー行があれば fail
	for _, line := range lines {
		if strings.Contains(line, "[ERROR]") || strings.Contains(line, "error") || strings.Contains(line, "Error") {
			return "fail", lastTime
		}
	}
	return "success", lastTime
}

func lastCSVTimestamp(csvPath string) (ts int64, label string) {
	raw, err := os.ReadFile(csvPath)
	if err != nil {
		return 0, "未取得"
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		if len(parts) == 0 || parts[0] == "timestamp" {
			continue
		}
		tsStr := strings.Trim(parts[0], `"`)
		// "2006-01-02 15:04:05" / "2006-01-02T15:04:05" / RFC3339(タイムゾーン付き) を試みる
		var t time.Time
		var err error
		for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
			t, err = time.Parse(layout, tsStr)
			if err == nil {
				break
			}
		}
		if err == nil && !t.IsZero() {
			return t.Unix(), heartdesk.FormatRawDatetime(t.Local().Format("2006-01-02 15:04:05"))
		}
	}
	return 0, "取得失敗"
}

func cronIntervalSeconds(schedule string) int {
	if m := regexp.MustCompile(`^\*\/(\d+)\s`).FindStringSubmatch(schedule); m != nil {
		n, _ := strconv.Atoi(m[1])
		if n < 1 {
			n = 1
		}
		return n * 60
	}
	return 0
}

func cronScheduleHuman(schedule string) string {
	schedule = strings.TrimSpace(schedule)
	switch schedule {
	case "* * * * *":
		return "毎分"
	case "0 1 * * *":
		return "毎日 1:00"
	}
	if m := regexp.MustCompile(`^\*\/(\d+)\s\*\s\*\s\*\s\*$`).FindStringSubmatch(schedule); m != nil {
		min, _ := strconv.Atoi(m[1])
		if min == 1 {
			return "1分毎"
		}
		return fmt.Sprintf("%d分毎", min)
	}
	if m := regexp.MustCompile(`^0\s(\d{1,2})\s\*\s\*\s\*$`).FindStringSubmatch(schedule); m != nil {
		h, _ := strconv.Atoi(m[1])
		return fmt.Sprintf("毎日 %d:00", h)
	}
	if m := regexp.MustCompile(`^(\d{1,2})\s(\d{1,2})\s\*\s\*\s\*$`).FindStringSubmatch(schedule); m != nil {
		min, _ := strconv.Atoi(m[1])
		h, _ := strconv.Atoi(m[2])
		return fmt.Sprintf("毎日 %d:%02d", h, min)
	}
	return ""
}

// GetCronStatus はcronジョブの実行状況一覧を返す（PHP fetch_card_cron_status_data 相当）
func GetCronStatus(agentID ...string) CronStatusData {
	id := ""
	if len(agentID) > 0 {
		id = strings.TrimSpace(agentID[0])
	}
	if id != "" {
		return getCronStatusFromReport(id)
	}

	entries := append(parseCrontabEntries(), parseSystemCronEntries()...)
	now := time.Now().Unix()

	var jobs []CronJob
	seenLabels := make(map[string]struct{})

	// entries から直接ジョブを生成（メタデータがあれば優先）
	for _, e := range entries {
		// cronファイルにメタデータがない場合、cronJobSpecs からマッチを探す
		label := e.label
		summary := e.summary
		logFileOrCSV := ""
		kind := "unknown"

		if label == "" || summary == "" {
			// フォールバック：cronJobSpecs からマッチを探す
			for _, spec := range cronJobSpecsList() {
				scriptBase := filepath.Base(spec.script)
				if strings.Contains(e.command, spec.script) ||
					(scriptBase != "" && strings.Contains(e.command, scriptBase)) {
					if label == "" {
						label = spec.label
					}
					if summary == "" {
						summary = spec.summary
					}
					logFileOrCSV = spec.logFile
					if logFileOrCSV == "" {
						logFileOrCSV = spec.csvFile
					}
					kind = spec.kind
					break
				}
			}
		}

		if label == "" {
			continue // メタデータもマッチもない場合はスキップ
		}
		seenLabels[label] = struct{}{}

		job := CronJob{
			Label:         label,
			Summary:       summary,
			Schedule:      e.schedule,
			Command:       e.command,
			Registered:    true,
			ScheduleHuman: cronScheduleHuman(e.schedule),
		}

		// 最終実行時刻と結果
		if kind == "log" && logFileOrCSV != "" {
			var status, lastTime string
			if strings.Contains(logFileOrCSV, "mariadb-backup") {
				status, lastTime = detectBackupLogStatus(logFileOrCSV)
			} else if strings.Contains(logFileOrCSV, heartdesk.OperationalIdentity().SchedulerLockPrefix+"-") {
				status, lastTime = detectLogStatus(logFileOrCSV)
			} else {
				status, lastTime = detectAppendLogStatus(logFileOrCSV)
			}
			job.LastTime = heartdesk.FormatRawDatetime(lastTime)
			job.Result = status
		} else if kind == "csv" && logFileOrCSV != "" {
			ts, label := lastCSVTimestamp(logFileOrCSV)
			job.LastTime = label
			if ts > 0 {
				interval := cronIntervalSeconds(job.Schedule)
				threshold := int64(cronCsvDelayFallbackSec)
				if interval > 0 {
					threshold = int64(interval * cronCsvDelayMultiplier)
				}
				if now-ts <= threshold {
					job.Result = "success"
				} else {
					job.Result = "fail"
				}
			} else {
				job.Result = "unknown"
			}
		} else {
			job.Result = "unknown"
			job.LastTime = "データなし"
		}

		jobs = append(jobs, job)
	}

	// Daemon Scheduler 利用時は、cron エントリが無くても
	// scheduler registry からジョブ定義を表示できるようにする。
	states := scheduler.SnapshotStates()
	for _, def := range scheduler.ListJobs() {
		if _, exists := seenLabels[def.Label]; exists {
			continue
		}
		result := "unknown"
		lastTime := "未実行"
		if st, ok := states[def.ID]; ok {
			if st.Running {
				result = "running"
				lastTime = "実行中"
			} else if !st.LastFinished.IsZero() {
				lastTime = heartdesk.FormatDatetime(st.LastFinished)
				if st.LastError == "" {
					result = "success"
				} else {
					result = "fail"
				}
			}
		}
		jobs = append(jobs, CronJob{
			Label:         def.Label,
			Summary:       def.Summary,
			Schedule:      def.DefaultCronSchedule,
			ScheduleHuman: cronScheduleHuman(def.DefaultCronSchedule),
			Command:       "managed by " + heartdesk.OperationalIdentity().SchedulerLockPrefix + "-scheduler",
			Registered:    true,
			LastTime:      lastTime,
			Result:        result,
		})
	}

	return CronStatusData{Jobs: jobs}
}

type rentalCronCollectorResult struct {
	Lines []string `json:"lines"`
}

func getCronStatusFromReport(agentID string) CronStatusData {
	lines, ok := loadCronLinesFromReport(agentID)
	if !ok {
		return CronStatusData{}
	}

	raw := strings.Join(lines, "\n")
	entries := parseCronLines(raw, "agent_crontab")
	seen := make(map[string]int)
	jobs := make([]CronJob, 0, len(entries))
	lastAt := reportReceivedAt(agentID)
	if lastAt == "" {
		lastAt = "未取得"
	}

	for _, e := range entries {
		label, summary := matchCronSpec(e.command)
		if label == "" {
			label = commandLabel(e.command)
		}
		seen[label]++
		if seen[label] > 1 {
			label = fmt.Sprintf("%s#%d", label, seen[label])
		}
		jobs = append(jobs, CronJob{
			Label:         label,
			Summary:       summary,
			Schedule:      e.schedule,
			ScheduleHuman: cronScheduleHuman(e.schedule),
			Command:       e.command,
			Registered:    true,
			LastTime:      lastAt,
			Result:        "unknown",
		})
	}

	return CronStatusData{Jobs: jobs}
}

func loadCronLinesFromReport(agentID string) ([]string, bool) {
	raw := loadCollectorRaw(agentID, "cron")
	if raw == nil {
		return nil, false
	}

	var payload rentalCronCollectorResult
	if err := json.Unmarshal(raw, &payload); err == nil {
		return payload.Lines, true
	}

	// 旧/簡易形式の後方互換: ["* * * * * ...", ...]
	var lines []string
	if err := json.Unmarshal(raw, &lines); err == nil {
		return lines, true
	}
	return nil, false
}

func matchCronSpec(command string) (label string, summary string) {
	for _, spec := range cronJobSpecsList() {
		scriptBase := filepath.Base(spec.script)
		if strings.Contains(command, spec.script) ||
			(scriptBase != "" && strings.Contains(command, scriptBase)) {
			return spec.label, spec.summary
		}
	}
	return "", ""
}

func commandLabel(command string) string {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return "cron-job"
	}
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return "cron-job"
	}
	base := filepath.Base(parts[0])
	if base == "" || base == "." || base == "/" {
		return "cron-job"
	}
	return base
}
