// Package alertscli exposes the standalone compatibility alert evaluator.
// Its historical state and best-effort behavior are separate from scheduler alerts.
package alertscli

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type AlertRules struct {
	Rules      map[string]AlertRule `json:"rules"`
	Recipients []Recipient          `json:"recipients"`
	SMTP       map[string]string    `json:"smtp"`
}

type AlertRule struct {
	Enabled        bool    `json:"enabled"`
	Threshold      float64 `json:"threshold"`
	Recovery       float64 `json:"recovery"`
	SustainSec     int     `json:"sustain_sec"`
	CooldownSec    int     `json:"cooldown_sec"`
	NotifyRecovery bool    `json:"notify_recovery"`
}

type Recipient struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type AlertState map[string]map[string]interface{}

type SSHEntry struct {
	IP   string `toml:"ip" json:"ip"`
	Name string `toml:"name" json:"name"`
	Type string `toml:"type" json:"type"`
}

type sshEntryFile struct {
	IPs []SSHEntry `toml:"ips"`
}

type LockoutEvent struct {
	Timestamp string `json:"timestamp"`
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	IP        string `json:"ip"`
}

// Run evaluates the existing resource/service/score/lockout rules, writes the
// check stamp, optionally sends test mail, then saves the historical nested
// state. It deliberately retains the standalone CLI's best-effort errors and
// recipient semantics; it does not invoke the scheduler's richer evaluator.
func (r *Runner) Run(testMail bool) {
	rules := r.loadAlertRules()
	state := r.loadAlertState()

	// 1. メモリ / ディスク
	if mem, disk := r.readResourceLog(); mem > 0 || disk > 0 {
		r.checkMemoryAlert(rules, state, mem)
		r.checkDiskAlert(rules, state, disk)
	}

	// 2. サービス停止
	r.checkServiceAlert(rules, state, "nginx")
	r.checkServiceAlert(rules, state, "mariadb")

	// 3. 脅威スコア
	if maxScore, topIP := r.readThreatScore(); maxScore > 0 {
		ipNames := r.loadSSHIPNames()
		topIPLabel := ipNames[topIP]
		r.checkThreatScoreAlert(rules, state, maxScore, topIP, topIPLabel)
	}

	// 4. アカウントロックアウト
	r.checkAccountLockoutAlert(rules, state, r.paths.Lockout)

	// 5. 実行スタンプ
	r.deps.MkdirAll(filepath.Dir(r.paths.LastCheck), 0770)
	r.deps.WriteFile(r.paths.LastCheck, []byte(r.deps.Now().Format("2006-01-02T15:04:05-07:00")+"\n"), 0644)

	// 6. テストメール
	if testMail {
		r.sendTestMail(rules)
	}

	// 状態ファイルに保存
	r.saveAlertState(state)
}

func (r *Runner) loadAlertRules() AlertRules {
	data, err := r.deps.ReadFile(r.paths.Rules)
	if err != nil {
		return AlertRules{Rules: map[string]AlertRule{}, Recipients: []Recipient{}}
	}
	var rules AlertRules
	json.Unmarshal(data, &rules)
	if rules.Rules == nil {
		rules.Rules = map[string]AlertRule{}
	}
	if rules.Recipients == nil {
		rules.Recipients = []Recipient{}
	}
	if rules.SMTP == nil {
		rules.SMTP = map[string]string{}
	}
	return rules
}

func (r *Runner) loadAlertState() AlertState {
	data, err := r.deps.ReadFile(r.paths.State)
	if err != nil {
		return AlertState{}
	}
	var state AlertState
	json.Unmarshal(data, &state)
	if state == nil {
		state = AlertState{}
	}
	return state
}

func (r *Runner) saveAlertState(state AlertState) {
	r.deps.MkdirAll(filepath.Dir(r.paths.State), 0770)
	data, _ := json.MarshalIndent(state, "", "  ")
	r.deps.WriteFile(r.paths.State, data, 0644)
}

func (r *Runner) readResourceLog() (float64, float64) {
	file, err := r.deps.Open(r.paths.ResourceLog)
	if err != nil {
		return 0, 0
	}
	defer file.Close()

	reader := csv.NewReader(file)
	var mem, disk float64
	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		if len(record) >= 4 {
			if m, err := strconv.ParseFloat(record[2], 64); err == nil {
				mem = m
			}
			if d, err := strconv.ParseFloat(record[3], 64); err == nil {
				disk = d
			}
		}
	}
	return mem, disk
}

func (r *Runner) readThreatScore() (int, string) {
	file, err := r.deps.Open(r.paths.ScoreLog)
	if err != nil {
		return 0, ""
	}
	defer file.Close()

	reader := csv.NewReader(file)
	var maxScore int
	var maxIP string
	lineNum := 0
	excludedIPs := r.loadExcludedIPs()

	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		lineNum++
		if lineNum == 1 {
			continue // Skip header
		}

		if len(record) >= 10 {
			ip := strings.TrimSpace(record[1])
			score, _ := strconv.Atoi(strings.TrimSpace(record[2]))

			// Skip excluded IPs
			if excludedIPs[ip] {
				continue
			}
			if score > maxScore {
				maxScore = score
				maxIP = ip
			}
		}
	}

	return maxScore, maxIP
}

func (r *Runner) loadSSHIPNames() map[string]string {
	names := make(map[string]string)
	entries, err := r.loadSSHIPEntries()
	if err != nil {
		return names
	}
	for _, e := range entries {
		if e.Type == "known" {
			names[e.IP] = e.Name
		}
	}
	return names
}

func (r *Runner) loadExcludedIPs() map[string]bool {
	excluded := make(map[string]bool)
	entries, err := r.loadSSHIPEntries()
	if err != nil {
		return excluded
	}
	for _, e := range entries {
		if e.Type == "wlm" || e.Type == "wla" {
			excluded[e.IP] = true
		}
	}
	return excluded
}

func (r *Runner) loadSSHIPEntries() ([]SSHEntry, error) {
	var file sshEntryFile
	data, err := r.deps.ReadFile(r.paths.ManagedIPs)
	if err == nil {
		if _, err := toml.Decode(string(data), &file); err != nil {
			return nil, err
		}
		return file.IPs, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	legacyPath := strings.TrimSuffix(r.paths.ManagedIPs, ".toml") + ".json"
	data, err = r.deps.ReadFile(legacyPath)
	if err != nil {
		return nil, err
	}
	var entries []SSHEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func getBool(m map[string]interface{}, key string, def bool) bool {
	v, ok := m[key]
	if !ok {
		return def
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}

func getFloat(m map[string]interface{}, key string, def float64) float64 {
	v, ok := m[key]
	if !ok {
		return def
	}
	if f, ok := v.(float64); ok {
		return f
	}
	return def
}

func (r *Runner) checkMemoryAlert(rules AlertRules, state AlertState, memPct float64) {
	ruleID := "memory_high"
	rule := rules.Rules[ruleID]
	if !rule.Enabled {
		return
	}

	if state[ruleID] == nil {
		state[ruleID] = map[string]interface{}{}
	}

	th := rule.Threshold
	if th == 0 {
		th = 90.0
	}

	active := memPct >= th
	lastActive := getBool(state[ruleID], "active", false)
	lastTime := getFloat(state[ruleID], "last_alert_time", 0)

	if active && !lastActive && r.shouldAlert(lastTime, rule.SustainSec, rule.CooldownSec) {
		r.sendAlert(rules, ruleID, fmt.Sprintf("メモリ使用率が高騰しています: %.1f%%", memPct))
		state[ruleID]["active"] = true
		state[ruleID]["last_alert_time"] = float64(r.deps.Now().Unix())
	} else if !active && lastActive && rule.NotifyRecovery {
		r.sendAlert(rules, ruleID, "メモリ使用率が正常に戻りました")
		state[ruleID]["active"] = false
	}
	state[ruleID]["last_value"] = memPct
}

func (r *Runner) checkDiskAlert(rules AlertRules, state AlertState, diskPct float64) {
	ruleID := "disk_high"
	rule := rules.Rules[ruleID]
	if !rule.Enabled {
		return
	}

	if state[ruleID] == nil {
		state[ruleID] = map[string]interface{}{}
	}

	th := rule.Threshold
	if th == 0 {
		th = 92.0
	}

	active := diskPct >= th
	lastActive := getBool(state[ruleID], "active", false)
	lastTime := getFloat(state[ruleID], "last_alert_time", 0)

	if active && !lastActive && r.shouldAlert(lastTime, rule.SustainSec, rule.CooldownSec) {
		r.sendAlert(rules, ruleID, fmt.Sprintf("ディスク使用率が高騰しています: %d%%", int(diskPct)))
		state[ruleID]["active"] = true
		state[ruleID]["last_alert_time"] = float64(r.deps.Now().Unix())
	} else if !active && lastActive && rule.NotifyRecovery {
		r.sendAlert(rules, ruleID, "ディスク使用率が正常に戻りました")
		state[ruleID]["active"] = false
	}
	state[ruleID]["last_value"] = diskPct
}

func (r *Runner) checkServiceAlert(rules AlertRules, state AlertState, service string) {
	ruleID := "service_down_" + service
	rule := rules.Rules[ruleID]
	if !rule.Enabled {
		return
	}

	if state[ruleID] == nil {
		state[ruleID] = map[string]interface{}{}
	}

	// systemctl is-active を実行
	status := r.deps.Command("systemctl", "is-active", service)
	isDown := status != "active"

	lastActive := getBool(state[ruleID], "active", false)
	lastTime := getFloat(state[ruleID], "last_alert_time", 0)

	if isDown && !lastActive && r.shouldAlert(lastTime, rule.SustainSec, rule.CooldownSec) {
		r.sendAlert(rules, ruleID, fmt.Sprintf("%s がダウンしています", service))
		state[ruleID]["active"] = true
		state[ruleID]["last_alert_time"] = float64(r.deps.Now().Unix())
	} else if !isDown && lastActive && rule.NotifyRecovery {
		r.sendAlert(rules, ruleID, fmt.Sprintf("%s が復帰しました", service))
		state[ruleID]["active"] = false
	}
	state[ruleID]["last_value"] = status
}

func (r *Runner) checkThreatScoreAlert(rules AlertRules, state AlertState, maxScore int, topIP, topIPLabel string) {
	ruleID := "threat_score_critical"
	rule := rules.Rules[ruleID]
	if !rule.Enabled {
		return
	}

	if state[ruleID] == nil {
		state[ruleID] = map[string]interface{}{}
	}

	th := rule.Threshold
	if th == 0 {
		th = 100.0
	}

	active := float64(maxScore) >= th
	lastActive := getBool(state[ruleID], "active", false)
	lastTime := getFloat(state[ruleID], "last_alert_time", 0)

	if active && !lastActive && r.shouldAlert(lastTime, rule.SustainSec, rule.CooldownSec) {
		msg := fmt.Sprintf("脅威スコアが %d に達しました (IP: %s)", maxScore, topIP)
		if topIPLabel != "" {
			msg += fmt.Sprintf(" (%s)", topIPLabel)
		}
		r.sendAlert(rules, ruleID, msg)
		state[ruleID]["active"] = true
		state[ruleID]["last_alert_time"] = float64(r.deps.Now().Unix())
	} else if !active && lastActive && rule.NotifyRecovery {
		r.sendAlert(rules, ruleID, "脅威スコアが低下しました")
		state[ruleID]["active"] = false
	}
	state[ruleID]["last_value"] = maxScore
}

func (r *Runner) checkAccountLockoutAlert(rules AlertRules, state AlertState, lockoutFile string) {
	ruleID := "account_lockout"
	rule := rules.Rules[ruleID]
	if !rule.Enabled {
		return
	}

	file, err := r.deps.Open(lockoutFile)
	if err != nil {
		return
	}
	defer file.Close()

	if state[ruleID] == nil {
		state[ruleID] = map[string]interface{}{}
	}

	lastTime := getFloat(state[ruleID], "last_check_time", 0)

	// 全行を毎回 unmarshal するのを避け、末尾 N 行のみをリングバッファで保持して処理する
	// （tail 化）。lockout イベントは追記順＝時刻順のため、last_check_time より新しい
	// イベントは必ず末尾側に存在する。N は 2 回のチェック間に起こり得る件数に対し十分大きく取る。
	const tailMax = 2000
	ring := make([]string, tailMax)
	n := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ring[n%tailMax] = scanner.Text()
		n++
	}

	start, count := 0, n
	if n > tailMax {
		start = n % tailMax
		count = tailMax
	}
	for i := 0; i < count; i++ {
		line := ring[(start+i)%tailMax]
		var event LockoutEvent
		if json.Unmarshal([]byte(line), &event) != nil {
			continue
		}
		t, _ := time.Parse(time.RFC3339, event.Timestamp)
		if t.Unix() > int64(lastTime) {
			r.sendAlert(rules, ruleID, fmt.Sprintf("アカウントロックアウト: %s (IP: %s)", event.Username, event.IP))
		}
	}

	state[ruleID]["last_check_time"] = float64(r.deps.Now().Unix())
}

func (r *Runner) shouldAlert(lastTime float64, sustainSec, cooldownSec int) bool {
	now := float64(r.deps.Now().Unix())
	// クールダウン中はアラート不可
	if now-lastTime < float64(cooldownSec) {
		return false
	}
	return true
}

func (r *Runner) sendAlert(rules AlertRules, ruleID, message string) {
	// TODO: 通知ルールから該当ルールの受信者を取得
	// 簡易版: alert_rules.json の recipients に全て送信
	for _, recipient := range rules.Recipients {
		r.deps.SendMail(rules.SMTP, recipient.Email, "【アラート】"+ruleID, message)
	}
}

func sendMail(smtpConf map[string]string, to, subject, body string) error {
	if len(smtpConf) == 0 {
		return fmt.Errorf("SMTP config not found")
	}

	host := smtpConf["smtp_host"]
	port := smtpConf["smtp_port"]
	user := smtpConf["smtp_user"]
	pass := smtpConf["smtp_pass"]
	from := smtpConf["smtp_from"]

	if host == "" || user == "" || pass == "" || to == "" || from == "" {
		return fmt.Errorf("incomplete SMTP config")
	}
	if port == "" {
		port = "587"
	}
	addr := net.JoinHostPort(host, port)

	// TLS 検証は有効（InsecureSkipVerify=false）。ServerName を正しく設定する。
	tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	auth := smtp.PlainAuth("", user, pass, host)

	// 件名は非 ASCII（日本語）を含むため MIME ヘッダエンコードする。
	msg := []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s\r\n",
		from, to, mime.QEncoding.Encode("utf-8", subject), body))

	var client *smtp.Client
	var err error
	if port == "465" {
		// implicit TLS（SMTPS）
		conn, derr := tls.Dial("tcp", addr, tlsConfig)
		if derr != nil {
			return fmt.Errorf("SMTP tls dial: %w", derr)
		}
		client, err = smtp.NewClient(conn, host)
		if err != nil {
			// defer client.Close() に到達する前なので、生きている TLS conn を明示的に閉じる。
			conn.Close()
			return fmt.Errorf("SMTP new client: %w", err)
		}
	} else {
		client, err = smtp.Dial(addr)
	}
	if err != nil {
		return fmt.Errorf("SMTP dial: %w", err)
	}
	defer client.Close()

	if err := client.Hello("localhost"); err != nil {
		return fmt.Errorf("SMTP hello: %w", err)
	}

	// 587/25 は STARTTLS で TLS を張る。サーバーが STARTTLS 非対応なら平文送信を避けて中止する
	// （旧実装は TLS 失敗時に平文フォールバックして認証情報を平文送信していた → 廃止）。
	if port != "465" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("SMTP server does not support STARTTLS; refusing to send credentials in cleartext")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("SMTP starttls: %w", err)
		}
	}

	if ok, _ := client.Extension("AUTH"); ok {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("SMTP mail from: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP rcpt to: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("SMTP write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("SMTP data close: %w", err)
	}
	return client.Quit()
}

func (r *Runner) sendTestMail(rules AlertRules) {
	if len(rules.SMTP) == 0 {
		fmt.Fprintln(r.deps.Stdout, "SMTP config not configured")
		return
	}
	for _, recipient := range rules.Recipients {
		err := r.deps.SendMail(rules.SMTP, recipient.Email, r.testSubject, r.testBody)
		if err != nil {
			fmt.Fprintf(r.deps.Stderr, "Failed to send test mail to %s: %v\n", recipient.Email, err)
		} else {
			fmt.Fprintf(r.deps.Stdout, "Test mail sent to %s\n", recipient.Email)
		}
	}
}

func defaultCommand(args ...string) string {
	if len(args) == 0 {
		return ""
	}
	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}
