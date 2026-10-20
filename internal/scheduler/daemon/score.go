package daemon

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

const (
	defaultScoreConfigPath    = "data/json/score_config.json"
	defaultScoreOutputPath    = "data/csv/threat_score.csv"
	defaultScoreHistoryPath   = "data/csv/threat_score_history.csv"
	defaultAutobanLogPath     = "data/csv/autoban_log.csv"
	defaultBanHistoryPath     = "data/csv/ban_history.csv"
	defaultHoneypotDir        = "data/json/honeypot"
	defaultNC4xxDir           = "data/json/nc4xx"
	defaultSSHIPListPath      = "config/managed_ips.toml"
	defaultLoginEventsPath    = "/var/lib/heartdesk/data/nc_extract/login_events.jsonl"
	defaultNextcloudLogPath   = "/var/www/nextcloud/data/nextcloud.log"
	defaultNginxAccessLogPath = "/var/log/nginx/access.log"
	defaultScoreLogPath       = "data/logs/score_engine.log"
	defaultStaticWhitelist    = "127.0.0.1 ::1"
)

type scoreWeights struct {
	ScanHit       int
	ScanCritical  int
	AuthFail      int
	NCFail        int
	NC4xx         int
	AlreadyBanned int
	ForeignIP     int
}

type scoreConfigValues struct {
	Weights         scoreWeights
	TimeWindowHours int
}

type scoreIPEntry struct {
	IP            string
	Score         int
	ScanHits      int
	ScanCriticals int
	AuthFails     int
	NCFails       int
	NC4xx         int
	IsBanned      int
	IsForeign     int
}

type sshAllowedIPEntry struct {
	IP   string `toml:"ip" json:"ip"`
	Type string `toml:"type" json:"type"`
}

type sshAllowedIPFile struct {
	IPs []sshAllowedIPEntry `toml:"ips"`
}

type hpLine struct {
	TS      string `json:"ts"`
	IP      string `json:"ip"`
	Trigger string `json:"trigger"`
}

type nc4xxLine struct {
	TS string `json:"ts"`
	IP string `json:"ip"`
}

type webAccessLine struct {
	TS     string `json:"ts"`
	IP     string `json:"ip"`
	Path   string `json:"path"`
	Status int    `json:"status"`
}

type nextcloudEventLine struct {
	TS  string `json:"ts"`
	IP  string `json:"ip"`
	Msg string `json:"msg"`
}

type fail2banEventLine struct {
	TS    string `json:"ts"`
	Event string `json:"event"`
	IP    string `json:"ip"`
}

var (
	reIPv4           = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	reNginxAccess    = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"[^"]*"\s+(\d{3})\s`)
	reJSONTime       = regexp.MustCompile(`"time":"([^"]+)"`)
	reJSONRemoteAddr = regexp.MustCompile(`"remoteAddr":"(\d+\.\d+\.\d+\.\d+)"`)
	reBanHistoryTS   = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`)
	reBanHistoryIP   = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$`)
	reBanHistoryJail = regexp.MustCompile(`\[(.+?)\] Ban `)
)

// ScoreEngine は score_engine.sh 相当の脅威スコア計算を実行する。
func ScoreEngine(ctx context.Context, cfg *config.SchedulerConfig) error {
	paths := resolveScorePaths(cfg)
	logLine, closeLog, err := openScoreLogger(paths.ScoreLogPath)
	if err != nil {
		return err
	}
	defer closeLog()

	cfgValues := loadScoreConfig(paths.ScoreConfigPath)
	cutoff := time.Now().Add(-time.Duration(cfgValues.TimeWindowHours) * time.Hour)
	nowTS := time.Now().Format("2006-01-02T15:04:05")

	wlm, noBan, ncFailSkip := loadWhitelistSets(paths.SSHIPListPath)
	var scoreStaticWhitelist string
	if cfg != nil {
		scoreStaticWhitelist = cfg.ScoreStaticWhitelist
	}
	staticWL := strings.Fields(strings.TrimSpace(scoreStaticWhitelist))
	if len(staticWL) == 0 {
		staticWL = strings.Fields(defaultStaticWhitelist)
	}
	skipScore := make(map[string]struct{}, len(staticWL)+len(wlm))
	for _, ip := range staticWL {
		skipScore[ip] = struct{}{}
	}
	for ip := range wlm {
		skipScore[ip] = struct{}{}
	}

	scanHits, scanCriticals := collectHoneypotCounts(ctx, paths.HoneypotDir, cutoff, logLine)
	authFails := collectAuth401Counts(ctx, paths.NginxAccessLogPath, cutoff, logLine)
	ncFails := collectNCFailCounts(ctx, paths.LoginEventsPath, paths.NextcloudLogPath, cutoff, ncFailSkip, logLine)
	nc4xxHits := collectNC4xxCounts(ctx, paths.NC4xxDir, cutoff, logLine)
	banned := collectBannedIPs(ctx, logLine)
	autobanEnabled := true
	if paths.AgentEventDir != "" {
		scanHits, scanCriticals = collectHoneypotEventCounts(ctx, filepath.Join(paths.AgentEventDir, "honeypot.jsonl"), cutoff, logLine)
		authFails = collectAuth401EventCounts(ctx, filepath.Join(paths.AgentEventDir, "web_access.jsonl"), cutoff, logLine)
		ncFails = collectNCFailEventCounts(ctx, filepath.Join(paths.AgentEventDir, "nextcloud_login.jsonl"), cutoff, ncFailSkip, logLine)
		nc4xxHits = collectNC4xxEventCounts(ctx, filepath.Join(paths.AgentEventDir, "web_access.jsonl"), cutoff, logLine)
		banned = collectBannedIPsFromEvents(ctx, filepath.Join(paths.AgentEventDir, "fail2ban.jsonl"), cutoff, logLine)
		autobanEnabled = false
		logLine("", "agent event score input enabled; monitor-side autoban disabled")
	}

	allIPs := make(map[string]struct{})
	mergeKeySet(allIPs, scanHits)
	mergeKeySet(allIPs, scanCriticals)
	mergeKeySet(allIPs, authFails)
	mergeKeySet(allIPs, ncFails)
	mergeKeySet(allIPs, nc4xxHits)
	for ip := range banned {
		allIPs[ip] = struct{}{}
	}

	_ = ensureCSVHeader(paths.AutobanLogPath, []string{"timestamp", "ip", "action", "detail"})

	// japan_ips セットを 1 回だけ読み込む（IP ごとに sudo ipset test を起動しない）。
	japanSet := loadJapanIPMatcher(ctx)
	if !japanSet.loaded {
		logLine("", "japan_ips unavailable; foreign_ip score component disabled")
	}

	rows := make([]scoreIPEntry, 0, len(allIPs))
	for ip := range allIPs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !isIPv4(ip) {
			continue
		}
		if _, ok := skipScore[ip]; ok {
			continue
		}

		scan := scanHits[ip]
		scanCrit := scanCriticals[ip]
		auth := authFails[ip]
		nc := ncFails[ip]
		nc4xx := nc4xxHits[ip]
		isBanned := 0
		if _, ok := banned[ip]; ok {
			isBanned = 1
		}
		isForeign := 0
		if japanSet.loaded && !japanSet.contains(ip) {
			isForeign = 1
		}

		score := scan*cfgValues.Weights.ScanHit +
			scanCrit*cfgValues.Weights.ScanCritical +
			auth*cfgValues.Weights.AuthFail +
			nc*cfgValues.Weights.NCFail +
			nc4xx*cfgValues.Weights.NC4xx +
			isBanned*cfgValues.Weights.AlreadyBanned +
			isForeign*cfgValues.Weights.ForeignIP
		if score == 0 {
			continue
		}

		if autobanEnabled && scanCrit > 0 && isBanned == 0 {
			if _, protected := noBan[ip]; !protected {
				_, _ = runCombined(8*time.Second, "sudo", "/usr/bin/fail2ban-client", "set", "recidive", "banip", ip)
				_ = appendCSVRow(paths.AutobanLogPath, []string{
					time.Now().Format("2006-01-02T15:04:05"), ip, "autoban", fmt.Sprintf("scan_critical=%d", scanCrit),
				})
				isBanned = 1
			}
		}

		rows = append(rows, scoreIPEntry{
			IP:            ip,
			Score:         score,
			ScanHits:      scan,
			ScanCriticals: scanCrit,
			AuthFails:     auth,
			NCFails:       nc,
			NC4xx:         nc4xx,
			IsBanned:      isBanned,
			IsForeign:     isForeign,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Score == rows[j].Score {
			return rows[i].IP < rows[j].IP
		}
		return rows[i].Score > rows[j].Score
	})

	if err := writeThreatScoreCSV(paths.ScoreOutputPath, nowTS, rows); err != nil {
		logLine("ERROR", "threat score csv write failed: "+err.Error())
		return err
	}
	if err := appendThreatScoreHistory(paths.ScoreHistoryPath, nowTS, rows); err != nil {
		logLine("WARN", "threat score history update failed: "+err.Error())
	}
	if err := updateBanHistory(paths.BanHistoryPath); err != nil {
		logLine("WARN", "ban history update failed: "+err.Error())
	}

	logLine("", fmt.Sprintf("score completed: rows=%d", len(rows)))
	return nil
}

type scorePaths struct {
	ScoreConfigPath    string
	ScoreOutputPath    string
	ScoreHistoryPath   string
	AutobanLogPath     string
	BanHistoryPath     string
	HoneypotDir        string
	NC4xxDir           string
	SSHIPListPath      string
	LoginEventsPath    string
	NextcloudLogPath   string
	NginxAccessLogPath string
	ScoreLogPath       string
	AgentEventDir      string
}

func resolveScorePaths(cfg *config.SchedulerConfig) scorePaths {
	p := scorePaths{
		ScoreConfigPath:    heartdesk.Path(defaultScoreConfigPath),
		ScoreOutputPath:    heartdesk.Path(defaultScoreOutputPath),
		ScoreHistoryPath:   heartdesk.Path(defaultScoreHistoryPath),
		AutobanLogPath:     heartdesk.Path(defaultAutobanLogPath),
		BanHistoryPath:     heartdesk.Path(defaultBanHistoryPath),
		HoneypotDir:        heartdesk.Path(defaultHoneypotDir),
		NC4xxDir:           heartdesk.Path(defaultNC4xxDir),
		SSHIPListPath:      heartdesk.Path(defaultSSHIPListPath),
		LoginEventsPath:    defaultLoginEventsPath,
		NextcloudLogPath:   defaultNextcloudLogPath,
		NginxAccessLogPath: defaultNginxAccessLogPath,
		ScoreLogPath:       heartdesk.Path(defaultScoreLogPath),
	}
	if cfg == nil {
		return p
	}
	if s := strings.TrimSpace(cfg.ScoreCSVPath); s != "" {
		p.ScoreOutputPath = s
	}
	if s := strings.TrimSpace(cfg.ScoreLogPath); s != "" {
		p.ScoreLogPath = s
	}
	if s := strings.TrimSpace(cfg.SSHIPListPath); s != "" {
		p.SSHIPListPath = s
	}
	if s := strings.TrimSpace(cfg.NC4xxDir); s != "" {
		p.NC4xxDir = s
	}
	if s := strings.TrimSpace(cfg.NCEventBaseDir); s != "" {
		p.LoginEventsPath = filepath.Join(s, "login_events.jsonl")
	}
	if s := strings.TrimSpace(cfg.ScoreConfigPath); s != "" {
		p.ScoreConfigPath = s
	}
	if s := strings.TrimSpace(cfg.ScoreHistoryPath); s != "" {
		p.ScoreHistoryPath = s
	}
	if s := strings.TrimSpace(cfg.AutobanLogPath); s != "" {
		p.AutobanLogPath = s
	}
	if s := strings.TrimSpace(cfg.BanHistoryPath); s != "" {
		p.BanHistoryPath = s
	}
	if s := strings.TrimSpace(cfg.HoneypotDir); s != "" {
		p.HoneypotDir = s
	}
	if s := strings.TrimSpace(cfg.NginxAccessLog); s != "" {
		p.NginxAccessLogPath = s
	}
	if s := strings.TrimSpace(cfg.NextcloudLog); s != "" {
		p.NextcloudLogPath = s
	}
	if s := strings.TrimSpace(cfg.LoginEventsPath); s != "" {
		p.LoginEventsPath = s
	}
	if cfg.AgentEventDir != "" {
		p.AgentEventDir = cfg.AgentEventDir
	} else if cfg.AgentID != "" {
		p.AgentEventDir = heartdesk.Path(filepath.Join("data/logs/agents", cfg.AgentID))
	}
	return p
}

func loadScoreConfig(path string) scoreConfigValues {
	cfg := scoreConfigValues{
		Weights: scoreWeights{
			ScanHit:       5,
			ScanCritical:  15,
			AuthFail:      50,
			NCFail:        20,
			NC4xx:         10,
			AlreadyBanned: 50,
			ForeignIP:     10,
		},
		TimeWindowHours: 24,
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return cfg
	}
	if v, ok := toIntFromAny(obj["time_window_hours"]); ok && v > 0 {
		cfg.TimeWindowHours = v
	}
	weights, _ := obj["weights"].(map[string]interface{})
	cfg.Weights.ScanHit = firstPositiveInt(cfg.Weights.ScanHit, toIntAny(weights, "scan_hit"))
	cfg.Weights.ScanCritical = firstPositiveInt(cfg.Weights.ScanCritical, toIntAny(weights, "scan_critical"))
	cfg.Weights.AuthFail = firstPositiveInt(cfg.Weights.AuthFail, toIntAny(weights, "auth_fail"))
	cfg.Weights.NCFail = firstPositiveInt(cfg.Weights.NCFail, toIntAny(weights, "nc_fail"))
	cfg.Weights.NC4xx = firstPositiveInt(cfg.Weights.NC4xx, toIntAny(weights, "nc_4xx"))
	cfg.Weights.AlreadyBanned = firstPositiveInt(cfg.Weights.AlreadyBanned, toIntAny(weights, "already_banned"))
	cfg.Weights.ForeignIP = firstPositiveInt(cfg.Weights.ForeignIP, toIntAny(weights, "foreign_ip"))
	return cfg
}

func firstPositiveInt(def, v int) int {
	if v > 0 {
		return v
	}
	return def
}

func toIntAny(m map[string]interface{}, key string) int {
	if m == nil {
		return 0
	}
	v, ok := toIntFromAny(m[key])
	if !ok {
		return 0
	}
	return v
}

func toIntFromAny(v interface{}) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), true
	case int:
		return x, true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		return n, err == nil
	default:
		return 0, false
	}
}

func loadWhitelistSets(path string) (map[string]struct{}, map[string]struct{}, map[string]struct{}) {
	wlm := map[string]struct{}{}
	noBan := map[string]struct{}{}
	ncFailSkip := map[string]struct{}{}
	entries, err := loadManagedIPEntries(path)
	if err != nil {
		return wlm, noBan, ncFailSkip
	}
	for _, e := range entries {
		ip := strings.TrimSpace(e.IP)
		if !isIPv4(ip) {
			continue
		}
		t := strings.TrimSpace(e.Type)
		if t == "" {
			t = "wlm"
		}
		if t == "wlm" {
			wlm[ip] = struct{}{}
		}
		if t == "wlm" || t == "wla" || t == "wl" {
			noBan[ip] = struct{}{}
		}
		if t == "wlm" || t == "wla" || t == "known" || t == "wl" {
			ncFailSkip[ip] = struct{}{}
		}
	}
	return wlm, noBan, ncFailSkip
}

func loadManagedIPEntries(path string) ([]sshAllowedIPEntry, error) {
	if strings.HasSuffix(strings.ToLower(path), ".toml") {
		var file sshAllowedIPFile
		if _, err := toml.DecodeFile(path, &file); err == nil {
			return file.IPs, nil
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}

	legacyPaths := []string{path}
	if strings.HasSuffix(strings.ToLower(path), ".toml") {
		legacyPaths = append(legacyPaths, strings.TrimSuffix(path, ".toml")+".json")
	}
	for _, candidate := range legacyPaths {
		raw, err := os.ReadFile(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		var entries []sshAllowedIPEntry
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, err
		}
		return entries, nil
	}
	return nil, os.ErrNotExist
}

func collectHoneypotCounts(ctx context.Context, dir string, cutoff time.Time, logLine func(string, string)) (map[string]int, map[string]int) {
	hits := make(map[string]int)
	crit := make(map[string]int)
	for _, path := range listLatestMonthJSONL(dir, "honeypot_", 2) {
		_ = readJSONL(path, func(line []byte) {
			if ctx.Err() != nil {
				return
			}
			var rec hpLine
			if err := json.Unmarshal(line, &rec); err != nil {
				return
			}
			if !isIPv4(rec.IP) {
				return
			}
			t, err := parseFlexTimestamp(rec.TS)
			if err != nil || t.Before(cutoff) {
				return
			}
			hits[rec.IP]++
			if rec.Trigger == "backdoor" || rec.Trigger == "query_string" {
				crit[rec.IP]++
			}
		})
	}
	logLine("", fmt.Sprintf("honeypot parsed: hits_ip=%d crit_ip=%d", len(hits), len(crit)))
	return hits, crit
}

func collectHoneypotEventCounts(ctx context.Context, path string, cutoff time.Time, logLine func(string, string)) (map[string]int, map[string]int) {
	hits := make(map[string]int)
	crit := make(map[string]int)
	_ = readJSONL(path, func(line []byte) {
		if ctx.Err() != nil {
			return
		}
		var rec hpLine
		if err := json.Unmarshal(line, &rec); err != nil || !isIPv4(rec.IP) {
			return
		}
		t, err := parseFlexTimestamp(rec.TS)
		if err != nil || t.Before(cutoff) {
			return
		}
		hits[rec.IP]++
		if rec.Trigger == "backdoor" || rec.Trigger == "query_string" {
			crit[rec.IP]++
		}
	})
	logLine("", fmt.Sprintf("agent honeypot parsed: hits_ip=%d crit_ip=%d", len(hits), len(crit)))
	return hits, crit
}

func collectAuth401Counts(ctx context.Context, path string, cutoff time.Time, logLine func(string, string)) map[string]int {
	out := make(map[string]int)
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 512*1024)
	for sc.Scan() {
		if ctx.Err() != nil {
			return out
		}
		m := reNginxAccess.FindStringSubmatch(sc.Text())
		if m == nil || m[3] != "401" {
			continue
		}
		ip := m[1]
		if !isIPv4(ip) {
			continue
		}
		t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
		if err != nil || t.Before(cutoff) {
			continue
		}
		out[ip]++
	}
	logLine("", fmt.Sprintf("nginx401 parsed: ip=%d", len(out)))
	return out
}

func collectAuth401EventCounts(ctx context.Context, path string, cutoff time.Time, logLine func(string, string)) map[string]int {
	out := make(map[string]int)
	_ = readJSONL(path, func(line []byte) {
		if ctx.Err() != nil {
			return
		}
		var rec webAccessLine
		if err := json.Unmarshal(line, &rec); err != nil || rec.Status != 401 || !isIPv4(rec.IP) {
			return
		}
		t, err := parseFlexTimestamp(rec.TS)
		if err != nil || t.Before(cutoff) {
			return
		}
		out[rec.IP]++
	})
	logLine("", fmt.Sprintf("agent web401 parsed: ip=%d", len(out)))
	return out
}

func collectNCFailCounts(ctx context.Context, loginEventsPath, nextcloudLogPath string, cutoff time.Time, skip map[string]struct{}, logLine func(string, string)) map[string]int {
	out := make(map[string]int)
	lines, exitCode := grepOutputLines(`"Login fail`, loginEventsPath)
	if exitCode > 1 {
		lines, _ = grepOutputLines(`"Login failed"`, nextcloudLogPath)
	}
	for _, line := range lines {
		if ctx.Err() != nil {
			return out
		}
		tsMatch := reJSONTime.FindStringSubmatch(line)
		ipMatch := reJSONRemoteAddr.FindStringSubmatch(line)
		if len(tsMatch) < 2 || len(ipMatch) < 2 {
			continue
		}
		ip := ipMatch[1]
		if !isIPv4(ip) {
			continue
		}
		if _, excluded := skip[ip]; excluded {
			continue
		}
		t, err := parseFlexTimestamp(tsMatch[1])
		if err != nil || t.Before(cutoff) {
			continue
		}
		out[ip]++
	}
	logLine("", fmt.Sprintf("nc_fail parsed: ip=%d", len(out)))
	return out
}

func collectNCFailEventCounts(ctx context.Context, path string, cutoff time.Time, skip map[string]struct{}, logLine func(string, string)) map[string]int {
	out := make(map[string]int)
	_ = readJSONL(path, func(line []byte) {
		if ctx.Err() != nil {
			return
		}
		var rec nextcloudEventLine
		if err := json.Unmarshal(line, &rec); err != nil || !isIPv4(rec.IP) {
			return
		}
		if _, excluded := skip[rec.IP]; excluded {
			return
		}
		if !strings.Contains(strings.ToLower(rec.Msg), "login failed") && !strings.Contains(strings.ToLower(rec.Msg), "failed login") {
			return
		}
		t, err := parseFlexTimestamp(rec.TS)
		if err != nil || t.Before(cutoff) {
			return
		}
		out[rec.IP]++
	})
	logLine("", fmt.Sprintf("agent nc_fail parsed: ip=%d", len(out)))
	return out
}

func collectNC4xxCounts(ctx context.Context, dir string, cutoff time.Time, logLine func(string, string)) map[string]int {
	out := make(map[string]int)
	for _, path := range listLatestMonthJSONL(dir, "nc4xx_", 2) {
		_ = readJSONL(path, func(line []byte) {
			if ctx.Err() != nil {
				return
			}
			var rec nc4xxLine
			if err := json.Unmarshal(line, &rec); err != nil {
				return
			}
			if !isIPv4(rec.IP) {
				return
			}
			t, err := parseFlexTimestamp(rec.TS)
			if err != nil || t.Before(cutoff) {
				return
			}
			out[rec.IP]++
		})
	}
	logLine("", fmt.Sprintf("nc4xx parsed: ip=%d", len(out)))
	return out
}

func collectNC4xxEventCounts(ctx context.Context, path string, cutoff time.Time, logLine func(string, string)) map[string]int {
	out := make(map[string]int)
	_ = readJSONL(path, func(line []byte) {
		if ctx.Err() != nil {
			return
		}
		var rec webAccessLine
		if err := json.Unmarshal(line, &rec); err != nil || !isIPv4(rec.IP) || rec.Status < 400 || rec.Status >= 500 {
			return
		}
		pathOnly := strings.SplitN(rec.Path, "?", 2)[0]
		if pathOnly != "/nextcloud" && !strings.HasPrefix(pathOnly, "/nextcloud/") {
			return
		}
		t, err := parseFlexTimestamp(rec.TS)
		if err != nil || t.Before(cutoff) {
			return
		}
		out[rec.IP]++
	})
	logLine("", fmt.Sprintf("agent nc4xx parsed: ip=%d", len(out)))
	return out
}

func collectBannedIPs(ctx context.Context, logLine func(string, string)) map[string]struct{} {
	jails := []string{"sshd", "nginx-basic-auth", "recidive"}
	out := make(map[string]struct{})
	for _, jail := range jails {
		if ctx.Err() != nil {
			return out
		}
		raw, _ := runCombined(6*time.Second, "sudo", "/usr/bin/fail2ban-client", "status", jail)
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, "Banned IP list:") {
				continue
			}
			ips := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "|- Banned IP list:")))
			for _, ip := range ips {
				if isIPv4(ip) {
					out[ip] = struct{}{}
				}
			}
		}
	}
	logLine("", fmt.Sprintf("fail2ban parsed: ip=%d", len(out)))
	return out
}

func collectBannedIPsFromEvents(ctx context.Context, path string, cutoff time.Time, logLine func(string, string)) map[string]struct{} {
	out := make(map[string]struct{})
	_ = readJSONL(path, func(line []byte) {
		if ctx.Err() != nil {
			return
		}
		var rec fail2banEventLine
		if err := json.Unmarshal(line, &rec); err != nil || !isIPv4(rec.IP) {
			return
		}
		t, err := parseFlexTimestamp(rec.TS)
		if err != nil || t.Before(cutoff) {
			return
		}
		switch rec.Event {
		case "ban", "restore":
			out[rec.IP] = struct{}{}
		case "unban":
			delete(out, rec.IP)
		}
	})
	logLine("", fmt.Sprintf("agent fail2ban parsed: ip=%d", len(out)))
	return out
}

// ipsetPathOnce は ipset バイナリのパス探索を 1 回だけ行う。
var (
	ipsetPathOnce  sync.Once
	ipsetPathValue string
)

func ipsetPath() string {
	ipsetPathOnce.Do(func() {
		for _, p := range []string{"/sbin/ipset", "/usr/sbin/ipset"} {
			if _, err := os.Stat(p); err == nil {
				ipsetPathValue = p
				return
			}
		}
		ipsetPathValue = "ipset" // PATH 解決にフォールバック
	})
	return ipsetPathValue
}

// japanIPMatcher は japan_ips セットのメンバー（単一 IP / CIDR の両方）を保持し、
// インメモリで国内判定する。score 1 回につき 1 度だけ ipset を読み込み、IP ごとの
// sudo 起動（最大 2 プロセス × IP 数）を排除する。
type japanIPMatcher struct {
	loaded bool
	ips    map[string]struct{}
	nets   []*net.IPNet
}

// loadJapanIPMatcher は `ipset list japan_ips` を 1 回実行してメンバーを解析する。
// 取得失敗時は loaded=false の matcher を返す。geofilter 移行後は ipset が無い環境が
// 正常なので、呼び出し側で foreign_ip 加点を無効化する。
func loadJapanIPMatcher(ctx context.Context) *japanIPMatcher {
	m := &japanIPMatcher{ips: map[string]struct{}{}}
	if ctx.Err() != nil {
		return m
	}
	out, err := runCombined(10*time.Second, "sudo", ipsetPath(), "list", "japan_ips")
	if err != nil {
		return m
	}
	inMembers := false
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 256*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !inMembers {
			if strings.HasPrefix(line, "Members:") {
				inMembers = true
			}
			continue
		}
		// メンバー行。"1.2.3.4" or "1.0.16.0/20"（末尾に "timeout ..." 等が付く場合は先頭トークン）
		token := strings.Fields(line)[0]
		if strings.Contains(token, "/") {
			if _, ipNet, perr := net.ParseCIDR(token); perr == nil {
				m.nets = append(m.nets, ipNet)
			}
			continue
		}
		if net.ParseIP(token) != nil {
			m.ips[token] = struct{}{}
		}
	}
	m.loaded = true
	return m
}

// contains は ip が japan_ips に含まれるか（単一 IP 完全一致 or CIDR レンジ）を返す。
func (m *japanIPMatcher) contains(ip string) bool {
	if m == nil || !m.loaded {
		return false
	}
	if _, ok := m.ips[ip]; ok {
		return true
	}
	if len(m.nets) > 0 {
		parsed := net.ParseIP(ip)
		if parsed != nil {
			for _, n := range m.nets {
				if n.Contains(parsed) {
					return true
				}
			}
		}
	}
	return false
}

func writeThreatScoreCSV(path, ts string, rows []scoreIPEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o770); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o660)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	_ = w.Write([]string{"timestamp", "ip", "score", "scan_hits", "scan_criticals", "auth_fails", "nc_fails", "nc_4xx", "is_banned", "is_foreign"})
	for _, row := range rows {
		_ = w.Write([]string{
			ts,
			row.IP,
			strconv.Itoa(row.Score),
			strconv.Itoa(row.ScanHits),
			strconv.Itoa(row.ScanCriticals),
			strconv.Itoa(row.AuthFails),
			strconv.Itoa(row.NCFails),
			strconv.Itoa(row.NC4xx),
			strconv.Itoa(row.IsBanned),
			strconv.Itoa(row.IsForeign),
		})
	}
	w.Flush()
	return w.Error()
}

func appendThreatScoreHistory(path, ts string, rows []scoreIPEntry) error {
	if err := ensureCSVHeader(path, []string{"timestamp", "ip", "score", "scan_hits", "scan_criticals", "auth_fails", "nc_fails", "nc_4xx", "is_banned", "is_foreign"}); err != nil {
		return err
	}
	for _, row := range rows {
		if err := appendCSVRow(path, []string{
			ts,
			row.IP,
			strconv.Itoa(row.Score),
			strconv.Itoa(row.ScanHits),
			strconv.Itoa(row.ScanCriticals),
			strconv.Itoa(row.AuthFails),
			strconv.Itoa(row.NCFails),
			strconv.Itoa(row.NC4xx),
			strconv.Itoa(row.IsBanned),
			strconv.Itoa(row.IsForeign),
		}); err != nil {
			return err
		}
	}
	cutoff := time.Now().AddDate(0, 0, -7)
	return trimHistoryCSV(path, cutoff)
}

func trimHistoryCSV(path string, cutoff time.Time) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(f)
	rows, err := r.ReadAll()
	if err != nil || len(rows) == 0 {
		return err
	}
	kept := [][]string{rows[0]}
	for _, row := range rows[1:] {
		if len(row) == 0 {
			continue
		}
		t, err := parseFlexTimestamp(row[0])
		if err != nil {
			continue
		}
		if !t.Before(cutoff) {
			kept = append(kept, row)
		}
	}
	tmp := path + ".tmp"
	wf, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o660)
	if err != nil {
		return err
	}
	// 書込失敗や Rename 失敗で壊れた .tmp が残らないよう、成功時以外は必ず削除する。
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmp)
		}
	}()
	w := csv.NewWriter(wf)
	_ = w.WriteAll(kept)
	w.Flush()
	_ = wf.Close()
	if w.Error() != nil {
		return w.Error()
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	renamed = true
	return nil
}

func updateBanHistory(path string) error {
	if err := ensureCSVHeader(path, []string{"timestamp", "ip", "jail"}); err != nil {
		return err
	}
	lastTS := lastBanHistoryTS(path)
	lines, err := readFail2banLogLines()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o660)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	for _, line := range lines {
		if !strings.Contains(line, "] Ban ") || strings.Contains(line, "Restore Ban") {
			continue
		}
		ts := firstSubmatch(reBanHistoryTS, line)
		if ts == "" || (lastTS != "" && ts <= lastTS) {
			continue
		}
		ip := firstSubmatch(reBanHistoryIP, line)
		jail := firstSubmatch(reBanHistoryJail, line)
		if ts == "" || ip == "" || jail == "" {
			continue
		}
		_ = w.Write([]string{ts, ip, jail})
	}
	w.Flush()
	return w.Error()
}

func lastBanHistoryTS(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "timestamp,") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	return ""
}

func readFail2banLogLines() ([]string, error) {
	paths := make([]string, 0)
	gz, _ := filepath.Glob("/var/log/fail2ban.log.*.gz")
	sort.Strings(gz)
	paths = append(paths, gz...)

	plain, _ := filepath.Glob("/var/log/fail2ban.log.[0-9]*")
	filtered := make([]string, 0, len(plain))
	for _, p := range plain {
		if !strings.HasSuffix(p, ".gz") {
			filtered = append(filtered, p)
		}
	}
	sort.Strings(filtered)
	paths = append(paths, filtered...)
	paths = append(paths, "/var/log/fail2ban.log")

	var lines []string
	for _, p := range paths {
		if strings.HasSuffix(p, ".gz") {
			f, err := os.Open(p)
			if err != nil {
				continue
			}
			gr, err := gzip.NewReader(f)
			if err != nil {
				_ = f.Close()
				continue
			}
			sc := bufio.NewScanner(gr)
			sc.Buffer(make([]byte, 0, 64*1024), 512*1024)
			for sc.Scan() {
				lines = append(lines, sc.Text())
			}
			_ = gr.Close()
			_ = f.Close()
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimRight(line, "\r")
			if line != "" {
				lines = append(lines, line)
			}
		}
	}
	return lines, nil
}

func listLatestMonthJSONL(dir, prefix string, n int) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	matches := make([]string, 0, len(ents))
	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".jsonl") {
			matches = append(matches, filepath.Join(dir, name))
		}
	}
	sort.Strings(matches)
	if len(matches) <= n {
		return matches
	}
	return matches[len(matches)-n:]
}

func readJSONL(path string, fn func([]byte)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 512*1024)
	for sc.Scan() {
		line := bytesTrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		fn(cp)
	}
	return sc.Err()
}

func bytesTrimSpace(b []byte) []byte {
	return bytes.TrimSpace(b)
}

func parseFlexTimestamp(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty")
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid ts")
}

// grepOutputLines は root/www-data 所有のログ（nextcloud.log 等）を heartdesk ユーザーから読むため
// sudo grep を使う。直読み（bufio.Scanner）化は権限の都合で本番のスコアリングを壊しうるため
// 採用しない。pattern は呼び出し元でハードコードされており注入余地はないが、将来の動的化に備え
// "--" でオプションとパターンを分離する。
func grepOutputLines(pattern, path string) ([]string, int) {
	cmd := exec.Command("sudo", "/usr/bin/grep", "-i", "--", pattern, path)
	out, err := cmd.CombinedOutput()
	raw := strings.TrimSpace(string(out))
	if err == nil {
		if raw == "" {
			return nil, 0
		}
		return strings.Split(raw, "\n"), 0
	}
	var exitErr *exec.ExitError
	if !errorAs(err, &exitErr) {
		return nil, 2
	}
	code := exitErr.ExitCode()
	if code == 1 {
		return nil, 1
	}
	return nil, code
}

func errorAs(err error, target interface{}) bool {
	switch t := target.(type) {
	case **exec.ExitError:
		e, ok := err.(*exec.ExitError)
		if ok {
			*t = e
			return true
		}
	}
	return false
}

func mergeKeySet(dst map[string]struct{}, src map[string]int) {
	for ip := range src {
		dst[ip] = struct{}{}
	}
}

func isIPv4(ip string) bool {
	return reIPv4.MatchString(strings.TrimSpace(ip))
}

func runCombined(timeout time.Duration, cmd string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, cmd, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func openScoreLogger(path string) (func(level, msg string), func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o770); err != nil {
		return nil, nil, fmt.Errorf("score log dir create failed: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o660)
	if err != nil {
		return nil, nil, fmt.Errorf("score log open failed: %w", err)
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

func ensureCSVHeader(path string, header []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o770); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err == nil && info.Size() > 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o660)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write(header)
	w.Flush()
	return w.Error()
}

func appendCSVRow(path string, row []string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o660)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write(row)
	w.Flush()
	return w.Error()
}

func firstSubmatch(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}
