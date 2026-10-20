package monitor

import (
	"bufio"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	"golang.org/x/crypto/bcrypt"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// readFileLines はファイルを全行読み込んで返す。読み取れない場合は nil
func readFileLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 512*1024), 512*1024)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

const (
	managedIPsTOMLPath       = "config/managed_ips.toml"
	legacyManagedIPsJSONPath = "data/json/managed_ips.json"
	f2bLocalConf             = "/etc/fail2ban/jail.local"
	limWLM                   = 10
	limWLA                   = 20
	limKnown                 = 50
	limWL                    = 50
)

type managedIPFile struct {
	IPs []SSHAllowedIP `toml:"ips"`
}

// managedIPsMu は managed_ips 台帳の read-modify-write（AddIP/RemoveIP/RenameIP/
// ChangeTypeIP）を直列化し、HTTP の並行ハンドラによる台帳破損（TOCTOU）を防ぐ。
// writeManagedIPs のアトミック書換（temp + os.Rename）と併せて、編集中クラッシュや
// 同時編集による上書き・破損を防止する。
var managedIPsMu sync.Mutex

// 関数内で毎回コンパイルしていた正規表現をパッケージレベルで 1 度だけコンパイルする。
var (
	ncWhitelistSlotRe    = regexp.MustCompile(`^whitelist_\d+$`)
	ncWhitelistSlotNumRe = regexp.MustCompile(`^whitelist_(\d+)$`)
	bfAttemptsRe         = regexp.MustCompile(`attempts:\s*(\d+)`)
	f2bIgnoreIPRe        = regexp.MustCompile(`(?m)^ignoreip = .*`)
)

// writeFileViaTee は root 所有ファイルへ sudo tee 経由で内容を書き込む
func writeFileViaTee(path, content string) error {
	cmd := exec.Command("sudo", "/usr/bin/tee", path)
	cmd.Stdin = strings.NewReader(content)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

// safeJSON は v を JSON へマーシャルし、<script> 内 JS として安全になるよう
// U+2028/U+2029 を \u2028/\u2029 へ置換して返す。
// Go の json.Marshal は <>& を \uXXXX 化するが U+2028/U+2029 は素通しするため、
// template.JS 経由で <script> 内に直接展開する全経路でこのヘルパーを使う。
func safeJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	s := string(b)
	s = strings.ReplaceAll(s, "\u2028", `\u2028`)
	s = strings.ReplaceAll(s, "\u2029", `\u2029`)
	return s
}

// GetIPMgmtJSVars は SSH 許可 IP 情報と BAN 済み IP を JS のグローバル変数宣言文字列として返す。
// ページ読み込み時に HTML へ埋め込み、ipBadges() 等が参照する変数を初期化する。
// GetIPMgmt() より軽量（occ コマンド・Nginx ログ読み取りなし）
func GetIPMgmtJSVars(cfg *config.AppConfig, agentID string) string {
	var ips []SSHAllowedIP
	if loaded, err := loadManagedIPs(); err == nil {
		ips = loaded
	}

	allowedIPs := make([]string, 0, len(ips))
	names := make(map[string]string, len(ips))
	types := make(map[string]string, len(ips))
	knownIPs := make(map[string]string)
	var whitelistIPs []string
	for _, e := range ips {
		if e.IP == "" {
			continue
		}
		allowedIPs = append(allowedIPs, e.IP)
		names[e.IP] = e.Name
		types[e.IP] = e.Type
		if e.Type == "known" {
			knownIPs[e.IP] = e.Name
		}
		if e.Type == "wl" {
			whitelistIPs = append(whitelistIPs, e.IP)
		}
	}
	if whitelistIPs == nil {
		whitelistIPs = strings.Fields(sab.Env("SAB_WHITELIST_IPS"))
	}

	serverIPs := []string{}
	serverIPSeen := map[string]bool{}
	for _, p := range strings.Split(sab.Env("SAB_SERVER_IPS"), ",") {
		p = strings.TrimSpace(p)
		if p == "" || serverIPSeen[p] {
			continue
		}
		serverIPSeen[p] = true
		serverIPs = append(serverIPs, p)
	}
	if hostIP := strings.TrimSpace(sab.Env("SAB_SERVER_HOST")); hostIP != "" && !serverIPSeen[hostIP] {
		serverIPs = append(serverIPs, hostIP)
	}

	sshPort := sab.Env("SAB_SSH_PORT")
	if sshPort == "" {
		sshPort = "22"
	}

	ipTypeLabels := map[string]config.IPTypeLabel{
		"wl":    {Short: "WL", Full: "WL（サーバー）"},
		"wlm":   {Short: "WLM", Full: "WLM（フルアクセス）"},
		"wla":   {Short: "WLA", Full: "WLA（Adminのみ）"},
		"known": {Short: "既知", Full: "既知"},
	}
	if cfg != nil {
		for key, label := range cfg.UI.IPTypeLabels {
			if key == "" {
				continue
			}
			cur := ipTypeLabels[key]
			if label.Short != "" {
				cur.Short = label.Short
			}
			if label.Full != "" {
				cur.Full = label.Full
			}
			ipTypeLabels[key] = cur
		}
	}

	// セキュリティ不変条件: 本関数の戻り値は layout.html の {{.JSVars}}（template.JS で
	// 自動エスケープ無効）として埋め込まれる。値はすべて json.Marshal 出力でのみ生成し、
	// ユーザー入力の文字列連結を template.JS にキャストして埋め込んではならない（XSS 防止）。
	//
	// Go の json.Marshal は <>& は \uXXXX へ
	// エスケープするが、JS では行終端として扱われる U+2028(LINE SEPARATOR)/U+2029(PARAGRAPH
	// SEPARATOR) は素通しする。これらが IP 名等に混入すると <script> 内の JS 文字列リテラルが
	// 途切れ、構文エラーで画面初期化が全停止し得る。safeJSON で両文字を \u2028/\u2029 へ
	// 置換してから埋め込む。
	marshal := func(v interface{}) string {
		return safeJSON(v)
	}
	return "var SSH_ALLOWED_IPS = " + marshal(allowedIPs) + ";\n" +
		"var SSH_ALLOWED_NAMES = " + marshal(names) + ";\n" +
		"var SSH_ALLOWED_TYPES = " + marshal(types) + ";\n" +
		"var KNOWN_IPS = " + marshal(knownIPs) + ";\n" +
		"var WHITELIST_IPS_PHP = " + marshal(whitelistIPs) + ";\n" +
		"var SERVER_IPS = " + marshal(serverIPs) + ";\n" +
		"var IP_TYPE_LABELS = " + marshal(ipTypeLabels) + ";\n" +
		"var NAB_SSH_PORT = " + marshal(sshPort) + ";\n" +
		"var BANNED_IPS = " + marshal(GetActiveBannedIPsWithJail(agentID)) + ";\n"
}

// GetIPMgmt は SSH 許可 IP 一覧を返す（NC状態・BF試行・直近アクセス付き）。
// agentID が指定された場合は Unavailable を返す（ip_mgmt は VPS 直実行専用のため、
// レポートあり・なしに関わらず Agent 経由では取得不可）。
func GetIPMgmt(agentID ...string) IPMgmtData {
	if len(agentID) > 0 && agentID[0] != "" {
		return IPMgmtData{IPs: []SSHAllowedIP{}, Unavailable: true}
	}
	var d IPMgmtData
	d.UpdatedAt = sab.FormatDatetime(time.Now().In(sab.JST()))

	loaded, err := loadManagedIPs()
	if err != nil {
		d.IPs = []SSHAllowedIP{}
		return d
	}
	d.IPs = loaded

	protectedNames := adminProtectNames()

	// updated_at のフォーマット変換
	for i := range d.IPs {
		d.IPs[i].UpdatedAtDisplay = sab.FormatRawDatetime(d.IPs[i].UpdatedAt)
		// 削除・名称変更・種別変更が拒否される行かを画面へ伝える（判定は isAdminProtected と同じ）。
		d.IPs[i].AdminProtected = matchAdminProtected(protectedNames, d.IPs[i].Name)
		switch d.IPs[i].Type {
		case "wlm":
			d.TotalWLM++
		case "wla":
			d.TotalWLA++
		case "wl":
			d.TotalWL++
		default:
			d.TotalKnown++
		}
	}

	// NC bruteforce ホワイトリスト取得（occ config:list bruteForce）
	slotMap := fetchNCBruteforceSlotMap()

	// Nginx ログから直近アクセス取得
	lastAccessMap := fetchLastAccessMap(d.IPs)

	// 各IPに NC状態・直近アクセスを付与
	for i := range d.IPs {
		ip := d.IPs[i].IP
		cidr := ip + "/32"
		d.IPs[i].NCRegistered = slotMap[cidr]
		d.IPs[i].LastAccess = lastAccessMap[ip]
	}

	// BF 試行は IP ごとに occ プロセスを起動するため（N+1）、未登録 IP に限定し
	// 並列度を絞って取得する。各 goroutine は互いに異なる index のみ書くため安全。
	type bfJob struct {
		idx int
		ip  string
	}
	var jobs []bfJob
	for i := range d.IPs {
		if !d.IPs[i].NCRegistered && d.IPs[i].IP != "" {
			jobs = append(jobs, bfJob{idx: i, ip: d.IPs[i].IP})
		}
	}
	if len(jobs) > 0 {
		const maxConc = 5
		sem := make(chan struct{}, maxConc)
		var wg sync.WaitGroup
		for _, j := range jobs {
			wg.Add(1)
			sem <- struct{}{}
			go func(j bfJob) {
				defer wg.Done()
				defer func() { <-sem }()
				d.IPs[j.idx].BFAttempts = fetchBFAttempts(j.ip)
			}(j)
		}
		wg.Wait()
	}

	return d
}

// fetchNCBruteforceSlotMap は Nextcloud の bruteforce ホワイトリスト登録 CIDR を返す
// キー: "1.2.3.4/32" → 値: true（登録済み）
func fetchNCBruteforceSlotMap() map[string]bool {
	raw := sab.RunArgs(30*time.Second, "php", "/var/www/nextcloud/occ", "config:list", "bruteForce", "--private")
	if raw == "" {
		return nil
	}
	var outer struct {
		Apps struct {
			BruteForce map[string]string `json:"bruteForce"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(raw), &outer); err != nil {
		return nil
	}
	result := make(map[string]bool)
	for k, v := range outer.Apps.BruteForce {
		if ncWhitelistSlotRe.MatchString(k) {
			result[strings.TrimSpace(v)] = true
		}
	}
	return result
}

// fetchBFAttempts は occ security:bruteforce:attempts で BF 試行数を返す
func fetchBFAttempts(ip string) int {
	out := sab.RunArgs(10*time.Second, "php", "/var/www/nextcloud/occ", "security:bruteforce:attempts", ip)
	if m := bfAttemptsRe.FindStringSubmatch(out); m != nil {
		n := 0
		fmt.Sscanf(m[1], "%d", &n)
		return n
	}
	return 0
}

// fetchLastAccessMap は logs/nginx.jsonl から各IPの直近アクセス日時を返す
func fetchLastAccessMap(ips []SSHAllowedIP) map[string]string {
	if len(ips) == 0 {
		return nil
	}
	ipSet := make(map[string]bool, len(ips))
	for _, e := range ips {
		if e.IP != "" {
			ipSet[e.IP] = true
		}
	}
	if len(ipSet) == 0 {
		return nil
	}

	result := make(map[string]string)
	_ = ScanJSONL[NginxLogEvent](webAccessJSONLPath(), func(ev NginxLogEvent) bool {
		if !ipSet[ev.IP] {
			return true
		}
		t, err := time.Parse(time.RFC3339, ev.TS)
		if err != nil {
			return true
		}
		// 常に最新のタイムスタンプで上書き（JSONL は時刻順なので最後が最新）
		result[ev.IP] = sab.FormatDatetime(t.In(sab.JST()))
		return true
	})
	return result
}

// ---- IP 管理アクション（Go直接実装）----

// AddIP は SSH 許可 IP リストに IP を追加する
func AddIP(ip, name, ipType, user string) error {
	if !isValidIP(ip) {
		return fmt.Errorf("不正な IP: %s", ip)
	}
	if !isValidIPType(ipType) {
		return fmt.Errorf("不正な type: %s", ipType)
	}
	managedIPsMu.Lock()
	defer managedIPsMu.Unlock()

	data, err := loadManagedIPs()
	if err != nil {
		return fmt.Errorf("追加失敗: %v", err)
	}
	for _, e := range data {
		if e.IP == ip {
			return fmt.Errorf("追加失敗: このIPは既に登録されています")
		}
	}
	limits := map[string]int{"wlm": limWLM, "wla": limWLA, "known": limKnown, "wl": limWL}
	count := 0
	for _, e := range data {
		t := e.Type
		if t == "" {
			t = "wlm"
		}
		if t == ipType {
			count++
		}
	}
	if count >= limits[ipType] {
		return fmt.Errorf("追加失敗: %s は最大%d件まで登録可能です", strings.ToUpper(ipType), limits[ipType])
	}

	now := time.Now().In(sab.JST()).Format("2006-01-02 15:04:05")
	entry := SSHAllowedIP{IP: ip, Name: name, Type: ipType, Added: now, UpdatedAt: now}
	if user != "" {
		entry.UpdatedBy = user
	}
	data = append(data, entry)
	if err := writeManagedIPs(data); err != nil {
		return fmt.Errorf("追加失敗: %v", err)
	}
	if ipType == "wl" {
		return nil
	}
	return syncIPManage(false)
}

// GetIPType は managed_ips 台帳から指定 IP の type を返す。見つからない場合は空文字を返す
func GetIPType(ip string) string {
	data, err := loadManagedIPs()
	if err != nil {
		return ""
	}
	for _, e := range data {
		if e.IP == ip {
			return e.Type
		}
	}
	return ""
}

// RemoveIP は SSH 許可 IP リストから IP を削除する
func RemoveIP(ip string) error {
	if !isValidIP(ip) {
		return fmt.Errorf("不正な IP: %s", ip)
	}
	managedIPsMu.Lock()
	defer managedIPsMu.Unlock()

	data, err := loadManagedIPs()
	if err != nil {
		return fmt.Errorf("削除失敗: %v", err)
	}
	for _, e := range data {
		if e.IP == ip && isAdminProtected(e.Name) {
			return fmt.Errorf("削除失敗: この管理者は削除できません")
		}
	}
	newData := make([]SSHAllowedIP, 0, len(data))
	for _, e := range data {
		if e.IP != ip {
			newData = append(newData, e)
		}
	}
	if len(newData) == len(data) {
		return fmt.Errorf("削除失敗: IPが見つかりません")
	}
	if len(newData) == 0 {
		return fmt.Errorf("削除失敗: 最後の1件は削除できません")
	}
	if err := writeManagedIPs(newData); err != nil {
		return fmt.Errorf("削除失敗: %v", err)
	}
	return syncIPManage(false)
}

// RenameIP は SSH 許可 IP の表示名を変更する
func RenameIP(ip, name, user string) error {
	if !isValidIP(ip) {
		return fmt.Errorf("不正な IP: %s", ip)
	}
	managedIPsMu.Lock()
	defer managedIPsMu.Unlock()

	data, err := loadManagedIPs()
	if err != nil {
		return fmt.Errorf("名称変更失敗: %v", err)
	}
	found := false
	for i := range data {
		if data[i].IP != ip {
			continue
		}
		if isAdminProtected(data[i].Name) {
			return fmt.Errorf("名称変更失敗: この管理者の名前は変更できません")
		}
		data[i].Name = name
		data[i].UpdatedAt = time.Now().In(sab.JST()).Format("2006-01-02 15:04:05")
		if user != "" {
			data[i].UpdatedBy = user
		}
		found = true
		break
	}
	if !found {
		return fmt.Errorf("名称変更失敗: IPが見つかりません")
	}
	if err := writeManagedIPs(data); err != nil {
		return fmt.Errorf("名称変更失敗: %v", err)
	}
	return nil
}

// ChangeTypeIP は SSH 許可 IP の種別を変更する
func ChangeTypeIP(ip, ipType, user string) error {
	if !isValidIP(ip) {
		return fmt.Errorf("不正な IP: %s", ip)
	}
	if !isValidIPType(ipType) {
		return fmt.Errorf("不正な type: %s", ipType)
	}
	managedIPsMu.Lock()
	defer managedIPsMu.Unlock()

	data, err := loadManagedIPs()
	if err != nil {
		return fmt.Errorf("種別変更失敗: %v", err)
	}
	found := false
	for i := range data {
		if data[i].IP != ip {
			continue
		}
		if isAdminProtected(data[i].Name) {
			return fmt.Errorf("種別変更失敗: この管理者の種別は変更できません")
		}
		oldType := data[i].Type
		if oldType == "" {
			oldType = "wlm"
		}
		if oldType == ipType {
			return fmt.Errorf("種別変更失敗: 既に同じ種別です")
		}
		limits := map[string]int{"wlm": limWLM, "wla": limWLA, "known": limKnown, "wl": limWL}
		count := 0
		for _, x := range data {
			t := x.Type
			if t == "" {
				t = "wlm"
			}
			if t == ipType {
				count++
			}
		}
		if count >= limits[ipType] {
			return fmt.Errorf("種別変更失敗: %s は最大%d件まで登録可能です", strings.ToUpper(ipType), limits[ipType])
		}
		data[i].Type = ipType
		data[i].UpdatedAt = time.Now().In(sab.JST()).Format("2006-01-02 15:04:05")
		if user != "" {
			data[i].UpdatedBy = user
		}
		found = true
		break
	}
	if !found {
		return fmt.Errorf("種別変更失敗: IPが見つかりません")
	}
	if err := writeManagedIPs(data); err != nil {
		return fmt.Errorf("種別変更失敗: %v", err)
	}
	return syncIPManage(true) // --skip-nc 相当
}

// ---- managed_ips TOML ヘルパー ----

func loadManagedIPs() ([]SSHAllowedIP, error) {
	tomlPath := sab.SabPath(managedIPsTOMLPath)
	if _, err := os.Stat(tomlPath); err == nil {
		var file managedIPFile
		if _, err := toml.DecodeFile(tomlPath, &file); err != nil {
			return nil, err
		}
		if file.IPs == nil {
			return []SSHAllowedIP{}, nil
		}
		return filterValidManagedIPs(file.IPs), nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	raw, err := os.ReadFile(sab.SabPath(legacyManagedIPsJSONPath))
	if err != nil {
		if os.IsNotExist(err) {
			return []SSHAllowedIP{}, nil
		}
		return nil, err
	}
	var data []SSHAllowedIP
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	return filterValidManagedIPs(data), nil
}

// filterValidManagedIPs は台帳エントリのうち IP/CIDR が不正なものを除外する。
// 台帳が外部で改竄されても不正値が下流の
// fail2ban / NC whitelist 生成へ流れ込まないよう、ロード時点で再検証する。
func filterValidManagedIPs(in []SSHAllowedIP) []SSHAllowedIP {
	out := make([]SSHAllowedIP, 0, len(in))
	for _, e := range in {
		if !isValidManagedIPEntry(e.IP) {
			log.Printf("WARN: loadManagedIPs: 不正な IP/CIDR をスキップ: %q", e.IP)
			continue
		}
		out = append(out, e)
	}
	return out
}

func writeManagedIPs(data []SSHAllowedIP) error {
	path := sab.SabPath(managedIPsTOMLPath)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// 一時ファイルへ書いてから os.Rename でアトミック置換する。
	// 書込中クラッシュや並行編集で正規ファイルが破損するのを防ぐ。
	tmp, err := os.CreateTemp(dir, ".managed_ips-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	file := managedIPFile{IPs: data}
	if err := toml.NewEncoder(tmp).Encode(file); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	renamed = true
	return nil
}

// ---- sync（fail2ban + NC bruteforce whitelist）----
//
// SSH の IP 制限は VPS 提供元のパケットフィルタへ一元化しており、
// iptables SSH_ALLOW チェーンの構築は行わない。
// nginx allowlist の生成も行わない（実体は deploy ツール生成の sab_allowed_ips_*.conf）。
// 本 sync の役割は fail2ban ignoreip / NC bruteforce whitelist の同期のみ。

// SyncIPManage は SAB 起動時など外部から呼ぶための公開ラッパー。
// skipNC=true のとき Nextcloud ブルートフォースホワイトリスト同期をスキップする。
func SyncIPManage(skipNC bool) error {
	return syncIPManage(skipNC)
}

// syncIPManage は managed_ips 台帳を fail2ban / Nextcloud へ同期する。
// skipNC=true のとき Nextcloud ブルートフォースホワイトリスト同期をスキップする（changetype 相当）。
func syncIPManage(skipNC bool) error {
	data, err := loadManagedIPs()
	if err != nil {
		return fmt.Errorf("sync失敗: %v", err)
	}

	// --- fail2ban ignoreip 更新 ---
	syncFail2banIgnoreIP(data)

	// --- Nextcloud bruteforce whitelist ---
	if !skipNC {
		syncNCBruteforceWhitelist(data)
	}

	return nil
}

// syncFail2banIgnoreIP は fail2ban の ignoreip を更新して fail2ban reload する
func syncFail2banIgnoreIP(data []SSHAllowedIP) {
	raw, err := os.ReadFile(f2bLocalConf)
	if err != nil {
		return
	}

	var ignoreIPs []string
	for _, e := range data {
		t := e.Type
		if t == "" {
			t = "wlm"
		}
		if t == "wlm" || t == "wla" || t == "known" {
			if !isValidManagedIPEntry(e.IP) {
				log.Printf("WARN: syncFail2banIgnoreIP: 不正な IP/CIDR をスキップ: %q", e.IP)
				continue
			}
			ignoreIPs = append(ignoreIPs, e.IP)
		}
	}

	ignoreLine := "ignoreip = 127.0.0.1/8 ::1"
	if len(ignoreIPs) > 0 {
		ignoreLine += " " + strings.Join(ignoreIPs, " ")
	}

	// ignoreip 行を置換
	updated := f2bIgnoreIPRe.ReplaceAllString(string(raw), ignoreLine)
	if updated == string(raw) {
		return
	}

	// バックアップ（root所有ファイルのため tee 経由で書き込む）
	_ = writeFileViaTee(f2bLocalConf+".bak", string(raw))
	if err := writeFileViaTee(f2bLocalConf, updated); err != nil {
		return
	}
	sab.RunArgsCombined(10*time.Second, "sudo", "/bin/systemctl", "reload", "fail2ban")
}

// syncNCBruteforceWhitelist は Nextcloud bruteforce ホワイトリストを managed_ips 台帳と同期する
func syncNCBruteforceWhitelist(data []SSHAllowedIP) {
	const occCmd = "sudo"
	occBase := []string{"-u", "www-data", "/usr/bin/php", "/var/www/nextcloud/occ"}
	occRun := func(timeout time.Duration, subArgs ...string) (string, error) {
		args := make([]string, len(occBase)+len(subArgs))
		copy(args, occBase)
		copy(args[len(occBase):], subArgs)
		return sab.RunArgsCombined(timeout, occCmd, args...)
	}

	raw, err := occRun(30*time.Second, "config:list", "bruteForce", "--private")
	if err != nil || raw == "" {
		return
	}
	var outer struct {
		Apps struct {
			BruteForce map[string]string `json:"bruteForce"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(raw), &outer); err != nil {
		return
	}

	registered := map[string]int{} // "x.x.x.x/32" -> slot number
	for k, v := range outer.Apps.BruteForce {
		if m := ncWhitelistSlotNumRe.FindStringSubmatch(k); m != nil {
			n, _ := strconv.Atoi(m[1])
			registered[strings.TrimSpace(v)] = n
		}
	}

	// managed_ips 側の IP
	managedIPs := map[string]string{} // "x.x.x.x/32" -> name
	for _, e := range data {
		managedIPs[e.IP+"/32"] = e.Name
	}

	// 追加
	usedSlots := map[int]bool{}
	for _, slot := range registered {
		usedSlots[slot] = true
	}
	for cidr, name := range managedIPs {
		if _, exists := registered[cidr]; exists {
			continue
		}
		n := 1
		for usedSlots[n] {
			n++
		}
		usedSlots[n] = true
		slot := strconv.Itoa(n)
		occRun(10*time.Second, "config:app:set", "bruteForce", "whitelist_"+slot, "--value", cidr)
		if name != "" {
			occRun(10*time.Second, "config:app:set", "bruteForce", "whitelist_"+slot+"_comment", "--value", name)
		}
	}

	// 削除
	for cidr, slot := range registered {
		if _, exists := managedIPs[cidr]; exists {
			continue
		}
		s := strconv.Itoa(slot)
		occRun(10*time.Second, "config:app:delete", "bruteForce", "whitelist_"+s)
		occRun(10*time.Second, "config:app:delete", "bruteForce", "whitelist_"+s+"_comment")
	}
}

// ---- IP 横断検索（search_ip API）----

// SearchIPHistory は指定 IP に関連するログイベントを各ソースから検索して返す
func SearchIPHistory(ip string) IPSearchData {
	if !isValidIP(ip) {
		return IPSearchData{Results: []IPSearchEntry{}}
	}

	var results []IPSearchEntry
	jst := sab.JST()
	now := time.Now().In(jst)

	// 1. SSH (logs/ssh.jsonl) — Agent が生成した JSONL を参照
	{
		jsonlPath := sab.SabPath("data/logs/ssh.jsonl")
		_ = ScanJSONL[SSHLogEvent](jsonlPath, func(ev SSHLogEvent) bool {
			if ev.IP != ip {
				return true
			}
			entryType := "SSH"
			switch ev.Event {
			case "failed", "invalid_user":
				entryType = "SSH (失敗)"
			case "accepted":
				entryType = "SSH (成功)"
			case "disconnect":
				entryType = "SSH (切断)"
			}
			detail := ev.Event + " user=" + ev.User + " port=" + ev.Port
			if len([]rune(detail)) > 120 {
				detail = string([]rune(detail)[:120])
			}
			results = append(results, IPSearchEntry{
				Time:   ev.TS,
				IP:     ip,
				Type:   entryType,
				Detail: detail,
			})
			return true
		})
	}

	// 2. Honeypot JSONL — 直近3ヶ月分
	for i := 0; i <= 2; i++ {
		ym := now.AddDate(0, -i, 0).Format("200601")
		hpLines := readFileLines(fmt.Sprintf("%s/honeypot_%s.jsonl", hpLogDirPath(), ym))
		for _, line := range hpLines {
			if !strings.Contains(line, ip) {
				continue
			}
			var rec hpRecord
			if err := json.Unmarshal([]byte(line), &rec); err != nil || rec.IP != ip {
				continue
			}
			path := rec.Path
			if rec.Query != "" {
				path += "?" + rec.Query
			}
			detail := rec.Method + " " + path
			if rec.PostBody != "" {
				pb := rec.PostBody
				if len([]rune(pb)) > 40 {
					pb = string([]rune(pb)[:40])
				}
				detail += " POST:" + pb
			}
			if ua := rec.Headers["user-agent"]; ua != "" {
				if len([]rune(ua)) > 60 {
					ua = string([]rune(ua)[:60])
				}
				detail += " [" + ua + "]"
			}
			if len([]rune(detail)) > 120 {
				detail = string([]rune(detail)[:120])
			}
			ts := rec.Ts
			if len(ts) > 19 {
				ts = ts[:19]
			}
			results = append(results, IPSearchEntry{
				Time:   ts,
				IP:     ip,
				Type:   "ハニーポット(" + rec.Trigger + ")",
				Detail: detail,
			})
		}
	}

	// 3. Nextcloud (logs/nextcloud.jsonl) — Agent が生成した JSONL を参照
	_ = ScanJSONL[NCEvent](ncJSONLPath(), func(ev NCEvent) bool {
		if ev.IP != ip {
			return true
		}
		entryType := "NextCloud"
		msg := ev.Msg
		if strings.Contains(strings.ToLower(msg), "login failed") ||
			strings.Contains(strings.ToLower(msg), "failed login") {
			entryType = "NCログイン失敗"
		} else if strings.Contains(strings.ToLower(msg), "login successful") ||
			strings.Contains(strings.ToLower(msg), "successful login") {
			entryType = "NCログイン成功"
		}
		detail := msg
		if len([]rune(detail)) > 120 {
			detail = string([]rune(detail)[:120])
		}
		results = append(results, IPSearchEntry{
			Time:   ev.TS,
			IP:     ip,
			Type:   entryType,
			Detail: detail,
		})
		return true
	})

	// 4. fail2ban（logs/fail2ban.jsonl） — Agent が生成した JSONL を参照
	{
		_ = ScanJSONL[F2BEvent](f2bJSONLPath(), func(ev F2BEvent) bool {
			if ev.IP != ip {
				return true
			}
			entryType := "fail2ban"
			switch ev.Event {
			case "ban":
				entryType = "fail2ban BAN"
			case "unban":
				entryType = "fail2ban 解除"
			}
			detail := ev.Event + " jail=" + ev.Jail
			if len([]rune(detail)) > 120 {
				detail = string([]rune(detail)[:120])
			}
			results = append(results, IPSearchEntry{
				Time:   ev.TS,
				IP:     ip,
				Type:   entryType,
				Detail: detail,
			})
			return true
		})
	}

	// 5. Nginx（logs/nginx.jsonl）— Agent が生成した JSONL を参照
	{
		var nginxResults []IPSearchEntry
		_ = ScanJSONL[NginxLogEvent](webAccessJSONLPath(), func(ev NginxLogEvent) bool {
			if ev.IP != ip {
				return true
			}
			statusStr := fmt.Sprintf("%d", ev.Status)
			entryType := "Nginxアクセス"
			if statusStr == "401" {
				entryType = "Nginx (認証失敗)"
			} else if ev.Status >= 400 {
				entryType = "Nginx (" + statusStr + ")"
			}
			nginxResults = append(nginxResults, IPSearchEntry{
				Time:   ev.TS,
				IP:     ip,
				Type:   entryType,
				Detail: ev.Method + " " + ev.Path + " → " + statusStr,
			})
			return true
		})
		if len(nginxResults) > 200 {
			nginxResults = nginxResults[len(nginxResults)-200:]
		}
		results = append(results, nginxResults...)
	}

	// 6. NC 4xx JSONL — 直近3ヶ月分
	for i := 0; i <= 2; i++ {
		ym := now.AddDate(0, -i, 0).Format("200601")
		nc4xxLines := readFileLines(fmt.Sprintf("%s/nc4xx_%s.jsonl", nc4xxLogDirPath(), ym))
		count := 0
		for _, line := range nc4xxLines {
			if !strings.Contains(line, ip) {
				continue
			}
			var rec struct {
				Ts     string `json:"ts"`
				IP     string `json:"ip"`
				Method string `json:"method"`
				Path   string `json:"path"`
				Status int    `json:"status"`
			}
			if err := json.Unmarshal([]byte(line), &rec); err != nil || rec.IP != ip {
				continue
			}
			detail := rec.Method + " " + rec.Path + " → " + fmt.Sprintf("%d", rec.Status)
			if len([]rune(detail)) > 120 {
				detail = string([]rune(detail)[:120])
			}
			ts := rec.Ts
			if len(ts) > 19 {
				ts = ts[:19]
			}
			results = append(results, IPSearchEntry{
				Time:   ts,
				IP:     ip,
				Type:   fmt.Sprintf("NC 4xx (%d)", rec.Status),
				Detail: detail,
			})
			count++
			if count >= 100 {
				break
			}
		}
	}

	// 時刻の降順でソート
	sort.Slice(results, func(i, j int) bool {
		return results[i].Time > results[j].Time
	})

	// GeoIP 情報
	country := ""
	if flags := GetCountryFlags([]string{ip}); flags != nil {
		country = flags[ip]
	}

	if results == nil {
		results = []IPSearchEntry{}
	}
	return IPSearchData{
		Results: results,
		Count:   len(results),
		Country: country,
		IsJapan: isJapanIP(ip),
	}
}

// isJapanIP は ipset japan_ips でIPが日本のものか判定する
func isJapanIP(ip string) bool {
	// ubuntu は /usr/sbin/ipset test japan_ips * の NOPASSWD を持つ
	out, err := sab.RunArgsCombined(5*time.Second, "sudo", "/usr/sbin/ipset", "test", "japan_ips", ip)
	if err == nil && strings.Contains(out, "is in set") {
		return true
	}
	// パスの違いを吸収
	out2, err2 := sab.RunArgsCombined(5*time.Second, "sudo", "/sbin/ipset", "test", "japan_ips", ip)
	return err2 == nil && strings.Contains(out2, "is in set")
}

func isValidIPType(t string) bool {
	return t == "wlm" || t == "wla" || t == "known" || t == "wl"
}

// isValidManagedIPEntry は managed_ips 台帳の IP/CIDR 文字列を再検証する。
// 台帳の値を fail2ban / NC whitelist の
// 生成内容へ書き込む直前に、単一 IP（net.ParseIP）または CIDR（net.ParseCIDR）として
// 妥当かを確認し、不正値（空・ゴミ・コマンド注入文字列・範囲外マスク等）の混入を防ぐ。
func isValidManagedIPEntry(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return false
}

// adminProtectNames は保護対象管理者の表示名一覧（[security].admin_protect_names）を返す。
// 未設定なら空（保護対象なし）。特定の個人名を既定値としてコードに持たない。
func adminProtectNames() []string {
	// 起動時ロード済みキャッシュを参照する。
	cfg, err := config.CachedAppConfigForTenant("")
	if err != nil || cfg == nil {
		return nil
	}
	return cfg.Security.AdminProtectNames
}

// matchAdminProtected は name が names のいずれかと一致するか（前後の空白は無視）を返す。
// name が空のときは常に false。
func matchAdminProtected(names []string, name string) bool {
	if name == "" {
		return false
	}
	for _, n := range names {
		if strings.TrimSpace(n) == name {
			return true
		}
	}
	return false
}

// isAdminProtected は name が保護対象管理者かを判定する。
// 保護対象は [security].admin_protect_names に列挙された表示名だけで、未設定なら誰も保護しない。
// 削除・名称変更・種別変更の拒否と、IP 一覧の admin_protected の両方がこの判定を使う。
func isAdminProtected(name string) bool {
	return matchAdminProtected(adminProtectNames(), name)
}

// ---- PIN 保護 ----

var (
	pinMu            sync.Mutex
	pinFailures      = make(map[string]int)
	pinLocked        = make(map[string]time.Time)
	pinStateLoadedOK bool
)

const pinMaxFailures = 5

// pinLockoutStatePath は PIN ブルートフォース保護状態の永続化先（0600）。
// プロセス再起動でロック状態が失われ攻撃者にリセットの機会を与えるのを防ぐ。
const pinLockoutStatePath = "data/pin_lockout.json"

type pinLockoutState struct {
	Failures map[string]int       `json:"failures"`
	Locked   map[string]time.Time `json:"locked"`
}

// loadPinStateLocked は永続化された PIN ロック状態を一度だけ読み込む（pinMu 保持下で呼ぶ）。
func loadPinStateLocked() {
	if pinStateLoadedOK {
		return
	}
	pinStateLoadedOK = true
	raw, err := os.ReadFile(sab.SabPath(pinLockoutStatePath))
	if err != nil {
		return // 未作成は正常
	}
	var st pinLockoutState
	if err := json.Unmarshal(raw, &st); err != nil {
		log.Printf("ERROR: ip_mgmt: pin lockout state decode error: %v", err)
		return
	}
	if st.Failures != nil {
		pinFailures = st.Failures
	}
	if st.Locked != nil {
		pinLocked = st.Locked
	}
}

// savePinStateLocked は PIN ロック状態を 0600 で永続化する（pinMu 保持下で呼ぶ）。
func savePinStateLocked() {
	st := pinLockoutState{Failures: pinFailures, Locked: pinLocked}
	raw, err := json.Marshal(st)
	if err != nil {
		log.Printf("ERROR: ip_mgmt: pin lockout state encode error: %v", err)
		return
	}
	path := sab.SabPath(pinLockoutStatePath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Printf("ERROR: ip_mgmt: pin lockout state mkdir error: %v", err)
		return
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		log.Printf("ERROR: ip_mgmt: pin lockout state write error: %v", err)
	}
}

func pinLockDur(cfg *config.AppConfig) time.Duration {
	if cfg != nil && cfg.Security.PinLockMin > 0 {
		return time.Duration(cfg.Security.PinLockMin) * time.Minute
	}
	return 30 * time.Minute
}

// VerifyPIN は WLM 操作用 PIN を検証する。
// 失敗が 5 回を超えると [security].pin_lock_min 分ロックする（デフォルト30分）。
//
// lockKey は失敗カウント / ロックの単位キー。呼び出し側はセッションの username を渡す
// （IP 単独依存をやめ、X-Real-IP 偽装でロックを回避できないようにする）。username が
// 取れない場合のみ trustedProxy 経由 IP をフォールバックに使う。
func VerifyPIN(cfg *config.AppConfig, pin, lockKey string) error {
	pinMu.Lock()
	defer pinMu.Unlock()
	loadPinStateLocked()
	defer savePinStateLocked()

	if lockUntil, locked := pinLocked[lockKey]; locked {
		if time.Now().Before(lockUntil) {
			return fmt.Errorf("ロック中（解除: %s）", lockUntil.Format("15:04:05"))
		}
		delete(pinLocked, lockKey)
		delete(pinFailures, lockKey)
	}

	pinHash := ""
	expected := ""
	if cfg != nil {
		pinHash = strings.TrimSpace(cfg.Security.IPMgmtPinHash)
		expected = strings.TrimSpace(cfg.Security.IPMgmtPin)
	}
	if pinHash == "" && expected == "" {
		return fmt.Errorf("PIN が設定されていません（[security].ip_mgmt_pin）")
	}

	// bcrypt ハッシュがあれば優先、無ければ
	// 平文 PIN を subtle.ConstantTimeCompare で定数時間比較する（生の != 比較を廃止）。
	if !pinMatches(pinHash, expected, pin) {
		pinFailures[lockKey]++
		remaining := pinMaxFailures - pinFailures[lockKey]
		if remaining <= 0 {
			pinLocked[lockKey] = time.Now().Add(pinLockDur(cfg))
			return fmt.Errorf("PIN 誤り。%d 回失敗したためロックしました", pinMaxFailures)
		}
		return fmt.Errorf("PIN が違います（残り %d 回）", remaining)
	}

	// 認証成功 → 失敗カウントリセット
	delete(pinFailures, lockKey)
	return nil
}

// pinMatches は入力 PIN が設定値に一致するかを定数時間で判定する。
// pinHash（bcrypt$<hash> 形式）が設定されていれば bcrypt 比較を優先し、
// 無ければ平文 expected を subtle.ConstantTimeCompare で比較する。
func pinMatches(pinHash, expected, pin string) bool {
	if pinHash != "" {
		raw := strings.TrimPrefix(pinHash, "bcrypt$")
		return bcrypt.CompareHashAndPassword([]byte(raw), []byte(pin)) == nil
	}
	if expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(pin), []byte(expected)) == 1
}
