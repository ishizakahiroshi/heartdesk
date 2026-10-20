package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

func ncCronWarnSec(cfg *config.AppConfig) int {
	if cfg != nil && cfg.NextcloudCron.WarnSec > 0 {
		return cfg.NextcloudCron.WarnSec
	}
	return 300
}

func ncCronDangerSec(cfg *config.AppConfig) int {
	if cfg != nil && cfg.NextcloudCron.DangerSec > 0 {
		return cfg.NextcloudCron.DangerSec
	}
	return 900
}

var serviceNames = []string{"nginx", "php8.3-fpm", "mariadb", "redis-server", "fail2ban", "sab"}

var procNames = map[string]string{
	"nginx":        "nginx",
	"php8.3-fpm":   "php-fpm",
	"mariadb":      "mariadb",
	"redis-server": "redis-server",
	"fail2ban":     "fail2ban",
	"sab":          "bin/sab",
}

var markerRe = regexp.MustCompile(`^##(.+)##$`)
var versionRe = regexp.MustCompile(`\d+(?:\.\d+)+`)

// getVersions は全サービスのバージョンを 1 コマンドで一括取得する
func getVersions() map[string]string {
	script := `echo '##nginx##'; nginx -v 2>&1; ` +
		`echo '##php8.3-fpm##'; php -v 2>/dev/null | head -1; ` +
		`echo '##mariadb##'; mariadb --version 2>/dev/null; ` +
		`echo '##redis-server##'; redis-server --version 2>/dev/null; ` +
		`echo '##fail2ban##'; fail2ban-client --version 2>/dev/null; ` +
		`echo '##sab##'; go version ` + sab.SabPath("bin/sab") + ` 2>/dev/null`

	result := make(map[string]string)
	curKey := ""
	for _, line := range strings.Split(sab.Run(script), "\n") {
		line = strings.TrimSpace(line)
		if m := markerRe.FindStringSubmatch(line); m != nil {
			curKey = m[1]
			result[curKey] = ""
			continue
		}
		if curKey != "" && result[curKey] == "" && line != "" {
			if m := versionRe.FindString(line); m != "" {
				result[curKey] = m
			}
		}
	}
	return result
}

// GetNextcloudCron は Nextcloud Cron の最終実行時刻を取得し状態を返す
func GetNextcloudCron(cfg *config.AppConfig) CronInfo {
	raw := sab.Run("sudo -n -u www-data /usr/bin/php /var/www/nextcloud/occ config:app:get core lastcron 2>/dev/null")
	ts, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || ts == 0 {
		return CronInfo{Class: "danger", Label: "取得失敗", Time: "-"}
	}

	t := time.Unix(ts, 0).In(sab.JST())
	ago := time.Now().Unix() - ts
	agoMin := ago / 60

	switch {
	case ago >= int64(ncCronDangerSec(cfg)):
		return CronInfo{Class: "danger", Label: fmt.Sprintf("%d分前（異常）", agoMin), Time: sab.FormatDatetime(t)}
	case ago >= int64(ncCronWarnSec(cfg)):
		return CronInfo{Class: "warning", Label: fmt.Sprintf("%d分前（遅延）", agoMin), Time: sab.FormatDatetime(t)}
	default:
		return CronInfo{Class: "ok", Label: fmt.Sprintf("%d分前", agoMin), Time: sab.FormatDatetime(t)}
	}
}

// GetMaintenanceMode は Nextcloud のメンテナンスモードが有効かどうかを返す
func GetMaintenanceMode() bool {
	out := sab.Run(`grep "'maintenance'" /var/www/nextcloud/config/config.php 2>/dev/null`)
	return strings.Contains(out, "true")
}

func getNextcloudVersion() string {
	type occStatus struct {
		VersionString string `json:"versionstring"`
		Version       string `json:"version"`
	}

	raw := sab.Run("sudo -n -u www-data /usr/bin/php /var/www/nextcloud/occ status --output=json 2>/dev/null")
	if raw != "" {
		var st occStatus
		if err := json.Unmarshal([]byte(raw), &st); err == nil {
			if st.VersionString != "" {
				return st.VersionString
			}
			if st.Version != "" {
				return st.Version
			}
		}
		if m := versionRe.FindString(raw); m != "" {
			return m
		}
	}
	return "-"
}

func getNextcloudCapacity() string {
	raw := sab.Run("df -B1 /var/www/nextcloud/data 2>/dev/null | tail -n 1 | awk '{print $3\" \"$2}'")
	parts := strings.Fields(raw)
	if len(parts) < 2 {
		return "-"
	}
	used, errUsed := strconv.ParseInt(parts[0], 10, 64)
	total, errTotal := strconv.ParseInt(parts[1], 10, 64)
	if errUsed != nil || errTotal != nil || total <= 0 {
		return "-"
	}
	return humanBytes(used) + " / " + humanBytes(total)
}

func getNextcloudInfo(isMaint bool) NextcloudInfo {
	label := "通常"
	class := "ok"
	if isMaint {
		label = "メンテ中"
		class = "warning"
	}
	return NextcloudInfo{
		Class:    class,
		Label:    label,
		Version:  getNextcloudVersion(),
		Capacity: getNextcloudCapacity(),
	}
}

// servicesCollectorResult は services collector の JSON 構造
type servicesCollectorResult struct {
	Services map[string]struct {
		Status  string  `json:"status"`
		Mem     float64 `json:"mem"`
		Version string  `json:"version"`
	} `json:"services"`
	Order    []string `json:"order"`
	Features struct {
		Nextcloud bool `json:"nextcloud"`
	} `json:"features"`
}

// servicesFromReport は agentID の最新 services collector から ServicesResponse を生成する。
// コレクターが存在しない場合は false を返す。
func servicesFromReport(agentID string) (ServicesResponse, bool) {
	raw := loadCollectorRaw(agentID, "services")
	if raw == nil {
		return ServicesResponse{}, false
	}
	var result servicesCollectorResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return ServicesResponse{}, false
	}
	resp := ServicesResponse{
		Services: make(map[string]ServiceInfo, len(result.Services)),
		Order:    result.Order,
		Actions:  buildActions(result.Features.Nextcloud, false),
	}
	for name, entry := range result.Services {
		resp.Services[name] = ServiceInfo{
			Status:  entry.Status,
			Mem:     entry.Mem,
			Version: entry.Version,
		}
	}
	return resp, true
}

// buildActions は features フラグに基づいて表示するアクションキー一覧を返す。
// isLocal は Monitor と同居のサーバー（sakura）かどうか（再起動系ボタンの制御）。
func buildActions(nextcloud bool, isLocal bool) []string {
	var actions []string
	if nextcloud {
		actions = append(actions, "maintenance_toggle", "nc_repair")
	}
	if isLocal {
		actions = append(actions, "restart_sab", "reboot")
	}
	return actions
}

// GetServices は全サービスのステータス・メモリ・バージョンと Nextcloud Cron を返す。
// agentID が指定された場合はレポートから読む（services collector がなければ Unavailable を返す）。
func GetServices(cfg *config.AppConfig, agentID ...string) ServicesResponse {
	if len(agentID) > 0 && agentID[0] != "" {
		if resp, ok := servicesFromReport(agentID[0]); ok {
			return resp
		}
		return ServicesResponse{Services: map[string]ServiceInfo{}, Unavailable: true}
	}
	isMaint := GetMaintenanceMode()
	resp := ServicesResponse{
		Services: make(map[string]ServiceInfo),
		Order:    serviceNames,
		IsMaint:  isMaint,
		Actions:  buildActions(true, true),
	}

	// systemctl is-active で全サービスのステータスを 1 コマンドで取得
	statusRaw := sab.Run("systemctl is-active " + strings.Join(serviceNames, " "))
	statuses := strings.Split(statusRaw, "\n")

	versions := getVersions()

	for i, name := range serviceNames {
		status := "unknown"
		if i < len(statuses) {
			status = strings.TrimSpace(statuses[i])
		}

		// メモリ: ps aux の RSS(KB) 合計 → MB
		proc := procNames[name]
		memRaw := sab.Run(fmt.Sprintf(
			"ps aux | grep -F '%s' | grep -v grep | awk '{sum+=$6} END {print sum+0}'",
			proc,
		))
		memKB, _ := strconv.ParseFloat(memRaw, 64)
		memMB := math.Round(memKB/1024*10) / 10

		resp.Services[name] = ServiceInfo{
			Status:  status,
			Mem:     memMB,
			Version: versions[name],
		}
	}

	nc := getNextcloudInfo(isMaint)
	resp.Nextcloud = &nc
	resp.NcCron = GetNextcloudCron(cfg)
	return resp
}

// SetMaintenanceMode は Nextcloud のメンテナンスモードを on/off する
func SetMaintenanceMode(on bool) (string, error) {
	mode := "--off"
	if on {
		mode = "--on"
	}
	return runNextcloudOCC("maintenance:mode", mode)
}

// RunNCRepair は Nextcloud の修復を実行する
func RunNCRepair() (string, error) {
	return runNextcloudOCC("maintenance:repair")
}

func runNextcloudOCC(args ...string) (string, error) {
	out, err := exec.Command("sudo", nextcloudOCCArgs(args...)...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func nextcloudOCCArgs(args ...string) []string {
	return append([]string{"-n", "-u", "www-data", "/usr/bin/php", "/var/www/nextcloud/occ"}, args...)
}

// GetSSL はSSL証明書の有効期限と Let's Encrypt 自動更新の状態を返す。
// agentID が指定された場合は Agent が収集した ssl collector データを返す。
// Agent 側で ssl collector が未有効・未受信の場合は Unavailable=true。
func GetSSL(cfg *config.AppConfig, agentID ...string) SSLData {
	if len(agentID) > 0 && agentID[0] != "" {
		raw, ok := GetAgentLatestCollector(agentID[0], "ssl")
		if !ok || len(raw) == 0 || string(raw) == "null" {
			return SSLData{Unavailable: true}
		}
		var d SSLData
		if err := json.Unmarshal(raw, &d); err != nil {
			return SSLData{Unavailable: true}
		}
		return d
	}
	sniDomain := ""
	connectHost := "127.0.0.1"
	connectPort := "443"
	if cfg != nil {
		if v := strings.TrimSpace(cfg.SSL.SNIDomain); v != "" {
			sniDomain = v
		}
		if v := strings.TrimSpace(cfg.SSL.ConnectHost); v != "" {
			connectHost = v
		}
		if cfg.SSL.ConnectPort > 0 {
			connectPort = strconv.Itoa(cfg.SSL.ConnectPort)
		}
	}

	d := SSLData{
		RenewAllowed:  true,
		LeStatus:      "不明",
		LeStatusClass: "warning",
	}

	// SSL証明書の有効期限を openssl s_client で取得
	raw := opensslCertEndDate(sniDomain, connectHost, connectPort)
	if idx := strings.Index(raw, "="); idx >= 0 {
		dateStr := strings.TrimSpace(raw[idx+1:])
		wdays := []string{"日", "月", "火", "水", "木", "金", "土"}
		for _, layout := range []string{"Jan  2 15:04:05 2006 MST", "Jan 2 15:04:05 2006 MST"} {
			if t, err := time.Parse(layout, dateStr); err == nil {
				jst := sab.JST()
				tjst := t.In(jst)
				d.SSLExpiry = sab.FormatDatetime(tjst)
				d.SSLDays = int(time.Until(t).Hours() / 24)
				renewal := t.AddDate(0, 0, -30).In(jst)
				d.SSLRenewalDate = renewal.Format("2006-01-02") + "(" + wdays[renewal.Weekday()] + ")"
				break
			}
		}
	}

	// certbot.timer の状態を確認
	timerRaw := sab.Run("systemctl status certbot.timer 2>/dev/null")
	if strings.Contains(timerRaw, "Active: active") {
		d.LeStatus = "タイマー稼働中"
		d.LeStatusClass = "ok"
	}
	// 次回トリガー時刻
	if idx := strings.Index(timerRaw, "Trigger:"); idx >= 0 {
		rest := timerRaw[idx+8:]
		if end := strings.Index(rest, ";"); end >= 0 {
			trigStr := strings.TrimSpace(rest[:end])
			// "Thu 2026-04-17 15:06:03 JST" → FormatRawDatetime は "YYYY-MM-DD HH:MM:SS" 形式を期待するため
			// スペース区切りで日時部分を抽出して変換を試みる
			parts := strings.Fields(trigStr)
			for i, p := range parts {
				if len(p) == 10 && strings.Count(p, "-") == 2 && i+1 < len(parts) {
					formatted := sab.FormatRawDatetime(p + " " + parts[i+1])
					d.LeLastDate = "次回: " + formatted
					break
				}
			}
			if d.LeLastDate == "" {
				d.LeLastDate = "次回: " + trigStr
			}
		}
	}

	// Let's Encrypt ログを確認
	leLog := sab.Run("tail -50 /var/log/letsencrypt/letsencrypt.log 2>/dev/null")
	hasFailure := false
	for _, line := range strings.Split(leLog, "\n") {
		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, "no renewal failures"),
			strings.Contains(lower, "not yet due"),
			strings.Contains(lower, "certificate not yet due"):
			d.LeStatus = "正常（更新不要）"
			d.LeStatusClass = "ok"
		case strings.Contains(lower, "success"),
			strings.Contains(lower, "renewed"),
			strings.Contains(lower, "congratulations"):
			d.LeStatus = "更新成功"
			d.LeStatusClass = "ok"
		case strings.Contains(lower, "renewal fail"),
			strings.Contains(lower, "error") && !strings.Contains(lower, "no renewal"):
			hasFailure = true
		}
	}
	if hasFailure && d.LeStatusClass != "ok" {
		d.LeStatus = "失敗"
		d.LeStatusClass = "danger"
	}

	if d.LeLastDate == "" && d.SSLExpiry != "" {
		d.LeLastDate = d.SSLExpiry
	}

	return d
}

func opensslCertEndDate(sniDomain, connectHost, connectPort string) string {
	args := []string{"s_client", "-connect", sslConnectAddress(connectHost, connectPort)}
	if sniDomain != "" {
		args = append(args, "-servername", sniDomain)
	}
	sclient := exec.Command("openssl", args...)
	sclient.Stdin = strings.NewReader("")
	sclient.Stderr = io.Discard
	certPEM, err := sclient.Output()
	if err != nil && len(certPEM) == 0 {
		return ""
	}

	x509 := exec.Command("openssl", "x509", "-noout", "-enddate")
	x509.Stdin = bytes.NewReader(certPEM)
	x509.Stderr = io.Discard
	out, err := x509.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func sslConnectAddress(host, port string) string {
	return net.JoinHostPort(host, port)
}

// Reboot はサーバーを再起動する（バックグラウンド実行）
func Reboot() {
	_ = exec.Command("bash", "-c", "sudo /usr/sbin/reboot 2>&1 &").Start()
}

// RestartSab は sab サービスを再起動する（バックグラウンド実行）
func RestartSab() {
	// 実行中プロセス自身を再起動対象に含むため、応答返却後に再起動されるよう遅延実行する。
	_ = exec.Command("bash", "-c", "( sleep 1; sudo /usr/bin/systemctl restart sab ) >/dev/null 2>&1 &").Start()
}
