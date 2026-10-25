package monitor

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
)

// exportFilename は出力ファイル名を生成する（YmdHis 形式タイムスタンプ付き）
func exportFilename(prefix, ext string) string {
	ts := time.Now().In(heartdesk.JST()).Format("20060102150405")
	return prefix + "_" + ts + "." + ext
}

// setDownloadHeader は Content-Disposition / Content-Type をセットする。
// RFC 5987 の filename*=UTF-8” と ASCII フォールバック filename= を併記し、
// 非 ASCII ファイル名でもヘッダが壊れないようにする。
func setDownloadHeader(w http.ResponseWriter, filename, contentType string) {
	w.Header().Set("Content-Type", contentType)
	ascii := asciiFilenameFallback(filename)
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q; filename*=UTF-8''%s", ascii, url.PathEscape(filename)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// asciiFilenameFallback は filename= 用に非 ASCII 文字とダブルクオートを '_' へ置換する。
func asciiFilenameFallback(filename string) string {
	var b strings.Builder
	for _, r := range filename {
		if r < 0x20 || r > 0x7E || r == '"' || r == '\\' {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	if b.Len() == 0 {
		return "download"
	}
	return b.String()
}

// csvBOM は UTF-8 BOM (Excel 互換)
var csvBOM = []byte{0xEF, 0xBB, 0xBF}

const (
	exportKeyHoneypot     = "honeypot"
	exportKeyNextcloud    = "nextcloud"
	exportKeyAuditAnomaly = "audit_anomaly"
	exportKeyBan          = "ban"
	exportKeyLoginHistory = "login_history"
	exportKeyPhpMyAdmin   = "phpmyadmin_login"
	exportKeyNginx        = "nginx"
	exportKeySSHLogin     = "ssh_login"
	exportKeyGeoIPCache   = "geoip_cache"
	exportKeyThreatScore  = "threat_score"
	exportKeyNCHighScore  = "nc_high_score"
	exportKeySSHIP        = "sship"
	exportKeyAll          = "all"
)

var exportHandlers = map[string]func(http.ResponseWriter){
	exportKeyHoneypot:     exportHoneypot,
	exportKeyNextcloud:    exportNextcloud,
	exportKeyAuditAnomaly: exportAuditAnomaly,
	exportKeyBan:          exportBan,
	exportKeyLoginHistory: exportLoginHistory,
	exportKeyPhpMyAdmin:   exportPhpMyAdminLogin,
	exportKeyNginx:        exportNginx,
	exportKeySSHLogin:     exportSSHLogin,
	exportKeyGeoIPCache:   exportGeoIPCache,
	exportKeyThreatScore:  exportThreatScore,
	exportKeyNCHighScore:  exportNCHighScore,
	exportKeySSHIP:        exportSSHIP,
	exportKeyAll:          exportAll,
}

func hasExportHandler(exportType string) bool {
	if _, ok := endpointByName(extensionRegistry.Exports, exportType); ok {
		return true
	}
	_, ok := exportHandlers[exportType]
	return ok
}

func listExportKeys() []string {
	keys := make([]string, 0, len(exportHandlers))
	for key := range exportHandlers {
		keys = append(keys, key)
	}
	for _, endpoint := range extensionRegistry.Exports {
		keys = append(keys, endpoint.Name)
	}
	sort.Strings(keys)
	return keys
}

// csvSafe は CSV インジェクション対策（= + - @ 先頭に ' を前置）
func csvSafe(s string) string {
	if len(s) == 0 {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@':
		return "'" + s
	}
	return s
}

// exportCardIDByKey は export キー → カード ID の対応。
// 空文字は vendor_staff 必須（all / 一括持ち出し系）。
var exportCardIDByKey = map[string]string{
	exportKeyHoneypot:     navmeta.CardSecHoneypotAccess,
	exportKeyNextcloud:    navmeta.CardSecNcLogin,
	exportKeyAuditAnomaly: navmeta.CardSecAuditAnomaly,
	exportKeyBan:          navmeta.CardSecFail2ban,
	exportKeyLoginHistory: navmeta.CardSecLoginHistory,
	exportKeyPhpMyAdmin:   navmeta.CardSecPhpmyadminLogin,
	exportKeyNginx:        navmeta.CardSecNginxLog,
	exportKeySSHLogin:     navmeta.CardSecSSHLoginHistory,
	exportKeyGeoIPCache:   navmeta.CardSecGeoipCache,
	exportKeyThreatScore:  navmeta.CardSecThreatScore,
	exportKeyNCHighScore:  navmeta.CardSecNcHighScore,
	exportKeySSHIP:        navmeta.CardSecIPMgmt,
	exportKeyAll:          "", // vendor only
}

// dispatchExport は ?export=xxx に応じたファイルダウンロードを返す
func dispatchExport(w http.ResponseWriter, r *http.Request, exportType string) {
	if r.Method != http.MethodGet {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// カード hidden / vendor 限定を GET API と同水準で適用。
	if !allowExport(r, exportType) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// ---- パラメータ駆動の特殊エクスポート ----
	exporter, ok := exportHandlers[exportType]
	if !ok {
		http.Error(w, "unknown export type", http.StatusNotFound)
		return
	}
	exporter(w)
}

// allowExport は export キーがセッションのカード表示・role で許可されるかを返す。
func allowExport(r *http.Request, exportType string) bool {
	sess, ok := auth.DefaultSessionManager().SessionFromRequest(r)
	if !ok {
		return false
	}
	cardID, known := exportCardIDByKey[exportType]
	if !known {
		// 未マップ export は vendor のみ（fail-closed）。
		return auth.Role(auth.NormalizeRole(sess.Role)) == auth.RoleVendorStaff
	}
	if cardID == "" {
		return auth.Role(auth.NormalizeRole(sess.Role)) == auth.RoleVendorStaff
	}
	if normalizeCardModes(sess.CardModes)[cardID] == "hidden" {
		return false
	}
	return true
}

// ---- ハニーポット CSV ----

func exportHoneypot(w http.ResponseWriter) {
	// 当月 + 前月の JSONL ファイルを読み込む
	now := time.Now().In(heartdesk.JST())
	prevMonth := now.AddDate(0, -1, 0)
	patterns := []string{
		filepath.Join(hpLogDirPath(), fmt.Sprintf("honeypot_%s.jsonl", now.Format("200601"))),
		filepath.Join(hpLogDirPath(), fmt.Sprintf("honeypot_%s.jsonl", prevMonth.Format("200601"))),
	}

	setDownloadHeader(w, exportFilename("honeypot_log", "csv"), "text/csv; charset=utf-8")
	_, _ = w.Write(csvBOM)

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"日時", "IP", "メソッド", "パス", "クエリ", "トリガー", "User-Agent", "POSTボディ", "WL"})

	for _, pat := range patterns {
		f, err := os.Open(pat)
		if err != nil {
			continue
		}
		dec := json.NewDecoder(f)
		for {
			var rec hpRecord
			if err := dec.Decode(&rec); err != nil {
				break
			}
			ua := ""
			if rec.Headers != nil {
				ua = rec.Headers["User-Agent"]
			}
			wl := "0"
			if rec.IsWhitelisted {
				wl = "1"
			}
			_ = cw.Write([]string{
				csvSafe(rec.Ts),
				csvSafe(rec.IP),
				rec.Method,
				csvSafe(rec.Path),
				csvSafe(rec.Query),
				rec.Trigger,
				csvSafe(ua),
				csvSafe(rec.PostBody),
				wl,
			})
		}
		_ = f.Close()
	}
	cw.Flush()
}

// ---- Nextcloud ログイン履歴 ----

func exportNextcloud(w http.ResponseWriter) {
	d := GetNCLoginHistory()
	setDownloadHeader(w, exportFilename("nextcloud_login_history", "txt"), "text/plain; charset=utf-8")

	var sb strings.Builder
	sb.WriteString("Nextcloud ログイン履歴\n")
	sb.WriteString(fmt.Sprintf("出力日時: %s\n", time.Now().In(heartdesk.JST()).Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("件数: %d\n\n", len(d.Logins)))
	sep := strings.Repeat("-", 100) + "\n"
	sb.WriteString(sep)
	sb.WriteString(fmt.Sprintf("%-25s  %-8s  %-20s  %-16s  %-10s  %s\n", "時刻", "結果", "ユーザー", "IP", "UAタイプ", "UA"))
	sb.WriteString(sep)
	for _, e := range d.Logins {
		sb.WriteString(fmt.Sprintf("%-25s  %-8s  %-20s  %-16s  %-10s  %s\n",
			e.Time, e.Result, e.User, e.IP, e.UAType, e.UA))
	}
	_, _ = w.Write([]byte(sb.String()))
}

// ---- 監査ログ異常 ----

func exportAuditAnomaly(w http.ResponseWriter) {
	d := GetAuditAnomaly()
	setDownloadHeader(w, exportFilename("nextcloud_audit_anomaly", "txt"), "text/plain; charset=utf-8")

	var sb strings.Builder
	sb.WriteString("Nextcloud 監査ログ異常検知\n")
	sb.WriteString(fmt.Sprintf("出力日時: %s\n", time.Now().In(heartdesk.JST()).Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("直近%d分 合計: %d件 / 前期間: %d件\n\n",
		d.Summary.WindowMin, d.Summary.TotalRecent, d.Summary.TotalPrev))

	sep := strings.Repeat("-", 100) + "\n"
	sb.WriteString(sep)
	sb.WriteString(fmt.Sprintf("%-40s  %8s  %8s  %8s  %-25s\n", "イベント", "直近", "前期間", "比率", "最終時刻"))
	sb.WriteString(sep)
	for _, a := range d.Anomalies {
		ratio := "—"
		if a.Ratio != nil {
			ratio = fmt.Sprintf("%.2f", *a.Ratio)
		}
		sb.WriteString(fmt.Sprintf("%-40s  %8d  %8d  %8s  %-25s\n",
			a.Event, a.Recent, a.Prev, ratio, a.LastTime))
	}
	_, _ = w.Write([]byte(sb.String()))
}

// ---- BAN 一覧 ----

func exportBan(w http.ResponseWriter) {
	d := GetFail2ban()
	setDownloadHeader(w, exportFilename("fail2ban_status", "txt"), "text/plain; charset=utf-8")

	var sb strings.Builder
	sb.WriteString("fail2ban BAN 一覧\n")
	sb.WriteString(fmt.Sprintf("出力日時: %s\n", time.Now().In(heartdesk.JST()).Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("BAN 総数: %d\n\n", d.BanTotal))

	for _, j := range d.Jails {
		sb.WriteString(fmt.Sprintf("=== Jail: %s (BAN:%d / Found:%d) ===\n", j.Name, j.BanCount, j.TotalFound))
		for _, ip := range j.BannedIPs {
			sb.WriteString("  " + ip + "\n")
		}
		sb.WriteString("\n")
	}
	_, _ = w.Write([]byte(sb.String()))
}

// ---- heartdesk ログイン履歴 ----

func exportLoginHistory(w http.ResponseWriter) {
	d := GetNginxLoginHistories()
	entries := d.Heartdesk.Entries
	setDownloadHeader(w, exportFilename("login_history", "txt"), "text/plain; charset=utf-8")
	writeNginxLoginText(w, "heartdesk ログイン履歴", entries)
}

// ---- phpMyAdmin ログイン履歴 ----

func exportPhpMyAdminLogin(w http.ResponseWriter) {
	d := GetNginxLoginHistories()
	entries := d.PhpMyAdmin.Entries
	setDownloadHeader(w, exportFilename("phpmyadmin_login_history", "txt"), "text/plain; charset=utf-8")
	writeNginxLoginText(w, "phpMyAdmin ログイン履歴", entries)
}

func writeNginxLoginText(w http.ResponseWriter, title string, entries []NginxLoginEntry) {
	var sb strings.Builder
	sb.WriteString(title + "\n")
	sb.WriteString(fmt.Sprintf("出力日時: %s\n", time.Now().In(heartdesk.JST()).Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("件数: %d\n\n", len(entries)))

	sep := strings.Repeat("-", 100) + "\n"
	sb.WriteString(sep)
	sb.WriteString(fmt.Sprintf("%-25s  %-8s  %-20s  %-16s  %-10s  %s\n", "時刻", "結果", "ユーザー", "IP", "デバイス", "UA"))
	sb.WriteString(sep)
	for _, e := range entries {
		sb.WriteString(fmt.Sprintf("%-25s  %-8s  %-20s  %-16s  %-10s  %s\n",
			e.Time, e.Result, e.User, e.IP, e.Device, e.UA))
	}
	_, _ = w.Write([]byte(sb.String()))
}

// ---- Nginx アクセスログ ----

func exportNginx(w http.ResponseWriter) {
	// 最新 access.log を生ダウンロード（最大 500件 のパース済みエントリとして提供）
	d := GetNginxLog(500)
	setDownloadHeader(w, exportFilename("nginx_access", "txt"), "text/plain; charset=utf-8")

	var sb strings.Builder
	sb.WriteString("Nginx アクセスログ\n")
	sb.WriteString(fmt.Sprintf("出力日時: %s\n", time.Now().In(heartdesk.JST()).Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("件数: %d\n\n", d.Total))

	sep := strings.Repeat("-", 120) + "\n"
	sb.WriteString(sep)
	sb.WriteString(fmt.Sprintf("%-25s  %-16s  %-8s  %-60s  %6s  %10s  %s\n",
		"時刻", "IP", "メソッド", "パス", "状態", "サイズ", "UA"))
	sb.WriteString(sep)
	for _, e := range d.Entries {
		sb.WriteString(fmt.Sprintf("%-25s  %-16s  %-8s  %-60s  %6d  %10d  %s\n",
			e.Time, e.IP, e.Method, e.Path, e.Status, e.Size, e.UA))
	}
	_, _ = w.Write([]byte(sb.String()))
}

// ---- SSH/SFTP ログイン履歴 ----

func exportSSHLogin(w http.ResponseWriter) {
	d := GetSSHLoginHistory()
	setDownloadHeader(w, exportFilename("ssh_login_history", "txt"), "text/plain; charset=utf-8")

	var sb strings.Builder
	sb.WriteString("SSH / SFTP ログイン履歴\n")
	sb.WriteString(fmt.Sprintf("出力日時: %s\n", time.Now().In(heartdesk.JST()).Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("件数: %d\n\n", len(d.Entries)))

	sep := strings.Repeat("-", 100) + "\n"
	sb.WriteString(sep)
	sb.WriteString(fmt.Sprintf("%-25s  %-8s  %-6s  %-20s  %-16s  %-12s  %s\n",
		"時刻", "結果", "種別", "ユーザー", "IP", "認証方式", "鍵名"))
	sb.WriteString(sep)
	for _, e := range d.Entries {
		sb.WriteString(fmt.Sprintf("%-25s  %-8s  %-6s  %-20s  %-16s  %-12s  %s\n",
			e.Time, e.Result, e.Type, e.User, e.IP, e.Method, e.KeyName))
	}
	_, _ = w.Write([]byte(sb.String()))
}

// ---- GeoIP キャッシュ CSV ----

func exportGeoIPCache(w http.ResponseWriter) {
	d := GetGeoIPCache()
	setDownloadHeader(w, exportFilename("geoip_cache", "csv"), "text/csv; charset=utf-8")
	_, _ = w.Write(csvBOM)

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"IP", "国", "最終取得(UnixTS)"})
	for _, e := range d.IPs {
		ts := ""
		if e.TS != nil {
			ts = fmt.Sprintf("%d", *e.TS)
		}
		_ = cw.Write([]string{csvSafe(e.IP), e.Country, ts})
	}
	cw.Flush()
}

// ---- 脅威スコア CSV ----

func exportThreatScore(w http.ResponseWriter) {
	d := GetThreatScore()
	setDownloadHeader(w, exportFilename("threat_score", "csv"), "text/csv; charset=utf-8")
	_, _ = w.Write(csvBOM)

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"タイムスタンプ", "IP", "スコア", "SSH失敗", "スキャン", "危険スキャン", "認証失敗", "NC失敗", "NC4xx", "BAN済", "海外"})
	for _, e := range d.Scores {
		_ = cw.Write([]string{
			csvSafe(e.Timestamp),
			csvSafe(e.IP),
			fmt.Sprintf("%d", e.Score),
			fmt.Sprintf("%d", e.SSHFails),
			fmt.Sprintf("%d", e.ScanHits),
			fmt.Sprintf("%d", e.ScanCriticals),
			fmt.Sprintf("%d", e.AuthFails),
			fmt.Sprintf("%d", e.NCFails),
			fmt.Sprintf("%d", e.NC4xx),
			fmt.Sprintf("%d", e.IsBanned),
			fmt.Sprintf("%d", e.IsForeign),
		})
	}
	cw.Flush()
}

// ---- 要確認IP（高スコア）CSV ----

func exportNCHighScore(w http.ResponseWriter) {
	d := GetNCHighScore()
	setDownloadHeader(w, exportFilename("nc_high_score", "csv"), "text/csv; charset=utf-8")
	_, _ = w.Write(csvBOM)

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"タイムスタンプ", "IP", "スコア", "SSH失敗", "スキャン", "危険スキャン", "認証失敗", "NC失敗", "NC4xx", "BAN済", "海外"})
	for _, e := range d.Scores {
		_ = cw.Write([]string{
			csvSafe(e.Timestamp),
			csvSafe(e.IP),
			fmt.Sprintf("%d", e.Score),
			fmt.Sprintf("%d", e.SSHFails),
			fmt.Sprintf("%d", e.ScanHits),
			fmt.Sprintf("%d", e.ScanCriticals),
			fmt.Sprintf("%d", e.AuthFails),
			fmt.Sprintf("%d", e.NCFails),
			fmt.Sprintf("%d", e.NC4xx),
			fmt.Sprintf("%d", e.IsBanned),
			fmt.Sprintf("%d", e.IsForeign),
		})
	}
	cw.Flush()
}

// ---- 管理IP JSON ----

func exportSSHIP(w http.ResponseWriter) {
	d := GetIPMgmt()
	setDownloadHeader(w, exportFilename("managed_ips", "json"), "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(d.IPs)
}

// ---- 全ログ ZIP ----

func exportAll(w http.ResponseWriter) {
	setDownloadHeader(w, exportFilename("all_logs", "zip"), "application/zip")

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	ts := time.Now().In(heartdesk.JST()).Format("2006-01-02 15:04:05")

	// readme.txt
	if rw, err := zw.Create("readme.txt"); err == nil {
		fmt.Fprintf(rw, "heartdesk 全ログエクスポート\n出力日時: %s\n\n", ts)
		fmt.Fprintf(rw, "ファイル一覧:\n")
		fmt.Fprintf(rw, "  fail2ban_status.txt   - fail2ban BAN 状況\n")
		fmt.Fprintf(rw, "  ssh_login_history.txt - SSH/SFTP ログイン履歴\n")
		fmt.Fprintf(rw, "  login_history.txt - heartdesk ログイン履歴\n")
		fmt.Fprintf(rw, "  phpmyadmin_login.txt  - phpMyAdmin ログイン履歴\n")
		fmt.Fprintf(rw, "  nc_login_history.txt  - Nextcloud ログイン履歴\n")
		fmt.Fprintf(rw, "  threat_score.csv      - 脅威スコア\n")
		fmt.Fprintf(rw, "  nc_high_score.csv     - 要確認IP 高スコア\n")
		fmt.Fprintf(rw, "  geoip_cache.csv       - GeoIP キャッシュ\n")
		fmt.Fprintf(rw, "  managed_ips.json      - 管理IP\n")
	}

	// 各ファイルをインメモリで生成して ZIP に追加
	addText := func(name string, fn func(w http.ResponseWriter)) {
		var rb responseBuffer
		fn(&rb)
		if fw, err := zw.Create(name); err == nil {
			_, _ = io.Copy(fw, bytes.NewReader(rb.body.Bytes()))
		}
	}

	addText("fail2ban_status.txt", exportBan)
	addText("ssh_login_history.txt", exportSSHLogin)
	addText("login_history.txt", exportLoginHistory)
	addText("phpmyadmin_login.txt", exportPhpMyAdminLogin)
	addText("nc_login_history.txt", exportNextcloud)
	addText("threat_score.csv", exportThreatScore)
	addText("nc_high_score.csv", exportNCHighScore)
	addText("geoip_cache.csv", exportGeoIPCache)

	// 管理 IP JSON
	if fw, err := zw.Create("managed_ips.json"); err == nil {
		var rb responseBuffer
		exportSSHIP(&rb)
		_, _ = io.Copy(fw, bytes.NewReader(rb.body.Bytes()))
	}

	_ = zw.Close()
	_, _ = w.Write(buf.Bytes())
}

// responseBuffer は http.ResponseWriter を模倣してレスポンスをバッファに溜める
type responseBuffer struct {
	headers http.Header
	body    bytes.Buffer
	code    int
}

func (rb *responseBuffer) Header() http.Header {
	if rb.headers == nil {
		rb.headers = http.Header{}
	}
	return rb.headers
}

func (rb *responseBuffer) Write(b []byte) (int, error) {
	return rb.body.Write(b)
}

func (rb *responseBuffer) WriteHeader(code int) {
	rb.code = code
}
