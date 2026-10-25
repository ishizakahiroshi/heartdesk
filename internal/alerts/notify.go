package alerts

import (
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"mime"
	"net"
	"net/smtp"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// serviceCheckTimeout は systemctl is-active の最大待ち時間。
const serviceCheckTimeout = 5 * time.Second

// SSHEntry は managed_ips.toml の 1 エントリ。
type SSHEntry struct {
	IP   string `toml:"ip" json:"ip"`
	Name string `toml:"name" json:"name"`
	Type string `toml:"type" json:"type"`
}

type sshEntryFile struct {
	IPs []SSHEntry `toml:"ips"`
}

// DeliveryResult describes one notification path. A path that was not tried
// returns its zero value. Delivered is considered only when Attempted is true.
type DeliveryResult struct {
	Attempted bool
	Delivered bool
}

// Notifier はメール以外の追加の通知経路（チャット・ウェブフック等）。
// RegisterNotifier で登録すると、Run の評価サイクルごとに Prepare、発報ごとに Notify が呼ばれる。
// Notify の結果は全経路の配信結果へ集約し、全経路で失敗した場合は次の評価で再試行する。
type Notifier interface {
	// Prepare は評価サイクルの開始時に 1 回呼ばれる。送信先の設定を cfg から取り出す。
	Prepare(cfg *config.AppConfig)
	// Notify は 1 件の発報を送る。
	Notify(ruleID, message string) DeliveryResult
}

var (
	notifiersMu sync.RWMutex
	notifiers   []Notifier
)

// RegisterNotifier は追加の通知経路を登録する。起動時（Run を呼ぶ前）に呼ぶ。
func RegisterNotifier(n Notifier) {
	if n == nil {
		return
	}
	notifiersMu.Lock()
	defer notifiersMu.Unlock()
	notifiers = append(notifiers, n)
}

func registeredNotifiers() []Notifier {
	notifiersMu.RLock()
	defer notifiersMu.RUnlock()
	return append([]Notifier(nil), notifiers...)
}

// prepareNotifiers は登録済みの通知経路へ今回の設定を渡す。
func prepareNotifiers(cfg *config.AppConfig) {
	for _, n := range registeredNotifiers() {
		n.Prepare(cfg)
	}
}

// sendAlert はルールに紐づく受信者全員へ通知する。メールと追加の通知経路は互いに独立して
// 試みる。片方の設定が無い／失敗しても、もう片方の送信を妨げない
// （メールの SMTP 未設定環境でも追加の通知経路は届く必要がある）。
//
// 何も試みなかった場合、または試みた経路のどれか一つでも届いた場合は true。
// 一つ以上を試み、すべて失敗した場合だけ false を返して再試行する。
func sendAlert(rules AlertRules, ruleID, message string) bool {
	result := sendAlertMailResult(rules, ruleID, message)
	for _, n := range registeredNotifiers() {
		next := n.Notify(ruleID, message)
		result.Attempted = result.Attempted || next.Attempted
		result.Delivered = result.Delivered || (next.Attempted && next.Delivered)
	}
	return !result.Attempted || result.Delivered
}

// mailSendFn は 1 通送る処理（テストで差し替え可能）。
var mailSendFn = sendMail

// mailRecipients は ruleID のメールを受け取る宛先を返す。無効にした宛先、受け取るルールを
// 指定していてその中に ruleID が無い宛先、メールアドレスが空の宛先は含めない。
func mailRecipients(rules AlertRules, ruleID string) []Recipient {
	var out []Recipient
	for _, r := range rules.Recipients {
		if strings.TrimSpace(r.Email) == "" || !r.wants(ruleID) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// sendAlertMail retains the mail-only delivery decision used by existing callers.
func sendAlertMail(rules AlertRules, ruleID, message string) bool {
	result := sendAlertMailResult(rules, ruleID, message)
	return !result.Attempted || result.Delivered
}

// sendAlertMailResult separates an unconfigured path from an attempted failure.
// A partial recipient success counts as delivered to avoid retrying that path
// indefinitely. Rule and recipient filtering is shared with the mail-only path.
func sendAlertMailResult(rules AlertRules, ruleID, message string) DeliveryResult {
	if len(rules.SMTP) == 0 {
		log.Printf("alerts: SMTP not configured, skip mail for %s: %s", ruleID, message)
		return DeliveryResult{}
	}
	if len(rules.Recipients) == 0 {
		log.Printf("alerts: no recipients configured, skip mail for %s: %s", ruleID, message)
		return DeliveryResult{}
	}
	subject := "【アラート】" + ruleID
	result := DeliveryResult{}
	for _, r := range mailRecipients(rules, ruleID) {
		result.Attempted = true
		if err := mailSendFn(rules.SMTP, r.Email, subject, message); err != nil {
			log.Printf("alerts: send mail to %s failed: %v", r.Email, err)
			continue
		}
		result.Delivered = true
	}
	return result
}

// sendMail は net/smtp で 1 通送信する。
// 587/25 は STARTTLS、465 は implicit TLS。STARTTLS 非対応サーバーには
// 認証情報を平文送信せず中止する（旧実装の平文フォールバックは廃止）。
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
			// defer client.Close() に到達する前なので、生きている TLS conn を明示的に閉じる
			// （閉じないと port=465 で NewClient 失敗が続くたびに FD/ソケットがリークする）。
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

	// 587/25 は STARTTLS で TLS を張る。STARTTLS 非対応なら平文送信を避けて中止する。
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

// serviceStatusFn は systemctl is-active 相当（テストで差し替え可能）。
var serviceStatusFn = systemctlIsActive

// systemctlIsActive は `systemctl is-active <service>` をタイムアウト付きで実行し、
// 標準出力（"active" / "inactive" / "failed" など）を返す。失敗時は空文字。
func systemctlIsActive(service string) string {
	ctx, cancel := context.WithTimeout(context.Background(), serviceCheckTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", service).Output()
	status := strings.TrimSpace(string(out))
	if err != nil && status == "" {
		// is-active は inactive のとき exit code 非ゼロ + stdout に状態を返す。
		// stdout が空（コマンド実行自体に失敗）の場合のみ空を返す。
		return ""
	}
	return status
}

// evaluateServiceAlerts は nginx / mariadb の停止を評価する。
// service_down_<svc> ルールが Enabled のときのみチェックする。
func evaluateServiceAlerts(rules AlertRules, state *AlertState) []string {
	now := nowFn()
	var out []string
	for _, svc := range []string{"nginx", "mariadb"} {
		ruleID := "service_down_" + svc
		rule, defined := rules.Rules[ruleID]
		if !defined || !rule.Enabled {
			continue
		}
		status := serviceStatusFn(svc)
		// status が空（コマンド失敗）の場合は判定不能としてスキップ（誤発報防止）。
		if status == "" {
			continue
		}
		key := ruleID
		isDown := status != "active"
		if isDown {
			snap := snapshotAlertKey(key, state)
			if !state.Active[key] && shouldAlert(key, rule.SustainSec, rule.CooldownSec, state, now) {
				if msg, ok := fireTracked(rules, ruleID, key, state, snap, fmt.Sprintf("%s がダウンしています", svc)); ok {
					out = append(out, msg)
					state.Active[key] = true
				}
			}
		} else {
			clearBreach(key, state)
			if state.Active[key] && rule.NotifyRecovery {
				msg, ok := fireDelivered(rules, ruleID, fmt.Sprintf("%s が復帰しました", svc))
				if !ok {
					// 復旧通知が届かなかったので Active を残し、次の評価で再試行する。
					log.Printf("alerts: recovery delivery failed for %s; will retry on next evaluation", ruleID)
					continue
				}
				out = append(out, msg)
			}
			state.Active[key] = false
		}
	}
	return out
}

// evaluateThreatScore は脅威スコア CSV から除外 IP を除いた最大スコアを評価する。
// threat_score_critical ルールが Enabled のときのみチェックする。
func evaluateThreatScore(scoreCSV, ipListPath string, rules AlertRules, state *AlertState) []string {
	const ruleID = "threat_score_critical"
	rule, defined := rules.Rules[ruleID]
	if !defined || !rule.Enabled {
		return nil
	}

	excluded, knownNames := loadIPMaps(ipListPath)
	maxScore, topIP := readThreatScore(scoreCSV, excluded)
	if maxScore <= 0 {
		// スコアが取れなければ評価対象外（復帰扱いはしない）。
		return nil
	}

	th := rule.Threshold
	if th == 0 {
		th = 100
	}
	now := nowFn()
	key := ruleID
	var out []string
	active := float64(maxScore) >= th
	if active {
		snap := snapshotAlertKey(key, state)
		if !state.Active[key] && shouldAlert(key, rule.SustainSec, rule.CooldownSec, state, now) {
			msg := fmt.Sprintf("脅威スコアが %d に達しました (IP: %s)", maxScore, topIP)
			if label := knownNames[topIP]; label != "" {
				msg += fmt.Sprintf(" (%s)", label)
			}
			if sent, ok := fireTracked(rules, ruleID, key, state, snap, msg); ok {
				out = append(out, sent)
				state.Active[key] = true
			}
		}
	} else {
		clearBreach(key, state)
		recovered := true
		if state.Active[key] && rule.NotifyRecovery {
			msg, ok := fireDelivered(rules, ruleID, "脅威スコアが低下しました")
			if ok {
				out = append(out, msg)
			} else {
				// 復旧通知が届かなかったので Active を残し、次の評価で再試行する。
				log.Printf("alerts: recovery delivery failed for %s; will retry on next evaluation", ruleID)
				recovered = false
			}
		}
		if recovered {
			state.Active[key] = false
		}
	}
	return out
}

// readThreatScore は threat_score.csv を読み、除外 IP を除いた最大スコアとその IP を返す。
// CSV は score_engine が出力する `..,ip,score,..`（>=10 列、1 行目はヘッダ）形式。
func readThreatScore(path string, excluded map[string]bool) (int, string) {
	f, err := os.Open(path)
	if err != nil {
		return 0, ""
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	var maxScore int
	var maxIP string
	lineNum := 0
	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		lineNum++
		if lineNum == 1 {
			continue // ヘッダ
		}
		if len(record) < 10 {
			continue
		}
		ip := strings.TrimSpace(record[1])
		score, _ := strconv.Atoi(strings.TrimSpace(record[2]))
		if excluded[ip] {
			continue
		}
		if score > maxScore {
			maxScore = score
			maxIP = ip
		}
	}
	return maxScore, maxIP
}

// loadIPMaps は managed_ips.toml（または legacy .json）から
// 除外 IP（type=wlm/wla）と既知 IP ラベル（type=known）のマップを返す。
func loadIPMaps(path string) (excluded map[string]bool, knownNames map[string]string) {
	excluded = map[string]bool{}
	knownNames = map[string]string{}
	entries := loadSSHIPEntries(path)
	for _, e := range entries {
		switch e.Type {
		case "wlm", "wla":
			excluded[e.IP] = true
		case "known":
			knownNames[e.IP] = e.Name
		}
	}
	return excluded, knownNames
}

// loadSSHIPEntries は managed_ips.toml を読む。なければ legacy .json を試す。
// いずれも無い／壊れている場合は空スライス（評価は除外なしで継続する）。
func loadSSHIPEntries(path string) []SSHEntry {
	var file sshEntryFile
	if _, err := toml.DecodeFile(path, &file); err == nil {
		return file.IPs
	} else if !os.IsNotExist(err) {
		log.Printf("alerts: decode ssh ip list %s: %v", path, err)
	}

	legacyPath := strings.TrimSuffix(path, ".toml") + ".json"
	data, err := os.ReadFile(legacyPath)
	if err != nil {
		return nil
	}
	var entries []SSHEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		log.Printf("alerts: unmarshal legacy ssh ip list %s: %v", legacyPath, err)
		return nil
	}
	return entries
}
