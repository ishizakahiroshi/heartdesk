package alerts

// Nextcloud の監査ログ（admin_audit が書く audit.log。1 行 1 JSON）から、
// なりすまし等による「ファイルの大量取得」を検知して通知する（通知だけ。自動で止めない）。
//
// 読み方は nc_user_events.go と同じ作法を踏む:
//   - offset で差分だけ読む。初回（その path の offset が未記録）は末尾まで進めるだけで発報しない。
//   - 読めないファイルは offset を記録しない（後から過去分ごと現れたときに一斉発報しないため）。
//
// それに加えて、5 分ごとの実行をまたいで「直近 60 分」を数えるため、利用者ごとの 1 分刻みの
// 小さな集計を別ファイル（nc_file_access_state.json）に持つ。alert_state.json には cooldown
// （LastAlertTime）だけを置き、集計は入れない（肥大させない）。
//
// SAB が別に集めている data/logs/nextcloud.jsonl や data/logs/agents/*/audit.jsonl は使わない
// （環境によって更新が止まっているため）。Nextcloud の audit.log を直接読む。

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/nclog"
)

// ルール ID は core/monitor の AlertRuleDefs と一致させる（ラベルの写しは labels.go）。
const (
	ruleNCMassAccess      = "nc_mass_access"
	ruleNCFolderSweep     = "nc_folder_sweep"
	ruleNCNewIPAccess     = "nc_new_ip_access"
	ruleNCOffHoursAccess  = "nc_off_hours_access"
	ruleNCPublicLinkBurst = "nc_public_link_burst"
	ruleNCServiceNewIP    = "nc_service_new_ip"
	ruleNCServiceVolume   = "nc_service_volume"
)

// ncFADefault はルールごとの既定のしきい値と cooldown。alert_rules.json の threshold /
// cooldown_sec が 0 以下のときに使う（nc_service_volume だけは threshold 0 以下＝判定しない）。
// 既定値は過去 30 日の実データでの試算から決めたもの。
type ncFADefault struct {
	threshold float64
	cooldown  int
}

var ncFADefaults = map[string]ncFADefault{
	ruleNCMassAccess:      {threshold: 300, cooldown: 10800},
	ruleNCFolderSweep:     {threshold: 50, cooldown: 10800},
	ruleNCNewIPAccess:     {threshold: 50, cooldown: 10800},
	ruleNCOffHoursAccess:  {threshold: 100, cooldown: 86400},
	ruleNCPublicLinkBurst: {threshold: 50, cooldown: 10800},
	ruleNCServiceNewIP:    {threshold: 1, cooldown: 86400},
	ruleNCServiceVolume:   {threshold: 0, cooldown: 10800},
}

const (
	// ncFAWindow は数える窓（直近 60 分）。
	ncFAWindow = 60 * time.Minute
	// ncFABucketSec は集計の刻み（1 分）。
	ncFABucketSec = 60
	// ncFAIPHistoryTTL は「過去 30 日に使った接続元」の保持期間。
	ncFAIPHistoryTTL = 30 * 24 * time.Hour
	// ncFALearningPeriod は状態ファイルを初めて作ってから「初めての接続元」の判定を出さない期間。
	ncFALearningPeriod = 3 * 24 * time.Hour
	// ncFAMaxFoldersPerUser は 1 利用者 1 窓あたりに覚えるフォルダ数の上限。
	ncFAMaxFoldersPerUser = 2000
	// ncFAMaxIPsPerUser は 1 利用者あたりに覚える接続元の上限（超えたら最終確認の古い順に捨てる）。
	ncFAMaxIPsPerUser = 1000
	// ncFAMaxLineBytes を超える 1 行は解釈せずに読み飛ばす。
	ncFAMaxLineBytes = 1 << 20
	// ncFAMessageMaxRunes は通知の内容 1 件の上限。チャットの Webhook には見出し＋本文で
	// 4000 文字程度の上限があるものが多いので、通知先で足す定型行（ルール・対象・発生・URL）の
	// 分を残しておく。
	ncFAMessageMaxRunes = 3000
	// ncFACooldownKeyRetention を過ぎた本機能の cooldown キーは alert_state.json から消す
	// （画面の cooldown 上限は 86400 秒なので、これより古いキーは判定に効かない）。
	ncFACooldownKeyRetention = 7 * 24 * time.Hour
	// ncFAFutureTolerance 以上先の時刻の行は数えない（窓に残り続けて発報し続けるのを防ぐ）。
	ncFAFutureTolerance = 5 * time.Minute
	// ncFAMaxAlertsPerRule は 1 回の評価でルールごとに出す通知の上限。超えた分は 1 件にまとめる。
	ncFAMaxAlertsPerRule = 5
	// ncFAOverflowLabels はまとめの通知に例として並べる対象の数。
	ncFAOverflowLabels = 10
	// ncFAHeadBytes は切り替わりの検出に使うファイル先頭の指紋の長さ。
	ncFAHeadBytes    = 512
	ncFAStateVersion = 1
)

// NCFileAccessMaxFoldersPerUser は「多数フォルダ巡回」が数えられるフォルダ数の上限
// （画面のしきい値の上限を合わせるため core/monitor から参照する）。
const NCFileAccessMaxFoldersPerUser = ncFAMaxFoldersPerUser

// テストで差し替えるため var にしている。
var (
	// ncFAAuditLogDefaultPath は設定が何も無いときに読む audit.log。
	ncFAAuditLogDefaultPath = "/var/www/nextcloud/data/audit.log"
	// ncFAMaxLinesPerRun は 1 回に読む行数の上限。超えた分は次回に読む。
	ncFAMaxLinesPerRun = 200000
	// ncFADefaultServiceAccounts は連携用のサービスアカウントの既定値（無し）。
	// 連携用のアカウントがある環境は、任意設定ファイルの service_accounts に書く。
	ncFADefaultServiceAccounts = []string{}
)

var (
	// 取得の行: File with id "123" accessed: "/alice@example.com/files/営業/a.pdf"
	reNCFileAccessed = regexp.MustCompile(`^File with id "?\d+"? accessed: "?(.*?)"?$`)
	// 公開リンクの行（Nextcloud の audit.log に出る形）:
	//   The shared folder with the token "XXXX" by "<持ち主>" has been accessed.
	//   The shared file with the token "XXXX" by "<持ち主>" has been accessed.
	// 行頭・行末に固定する（ログイン名やファイル名に同じ文言を入れた行を数えないため）。
	reNCPublicLink = regexp.MustCompile(`^The shared (?:folder|file) with the token "([^"]+)" by "([^"]*)" has been accessed\.?$`)
)

// ---------------------------------------------------------------------------
// 任意設定ファイル（data/json/nc_file_access.json）
// ---------------------------------------------------------------------------

// ncFileAccessSettings は任意設定ファイルの中身。無ければ既定値で動く。
type ncFileAccessSettings struct {
	AuditLogPath string `json:"audit_log_path"`
	// ServiceAccounts は連携用のサービスアカウント。キー自体が無ければ既定（無し）、
	// 空配列でも「サービスアカウント無し」として扱う。
	ServiceAccounts []string `json:"service_accounts"`
}

func ncFileAccessSettingsPath() string {
	return sab.SabPath("data/json/nc_file_access.json")
}

// loadNCFileAccessSettings は任意設定ファイルを読む。無いときは黙って既定値、
// 読めない・壊れているときはログに 1 行出して既定値で動く。
func loadNCFileAccessSettings() ncFileAccessSettings {
	p := ncFileAccessSettingsPath()
	data, err := os.ReadFile(p)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("alerts: nc_file_access: cannot read settings %s, using defaults: %v", p, err)
		}
		return ncFileAccessSettings{}
	}
	var s ncFileAccessSettings
	if err := json.Unmarshal(data, &s); err != nil {
		log.Printf("alerts: nc_file_access: settings %s is broken, using defaults: %v", p, err)
		return ncFileAccessSettings{}
	}
	return s
}

func (s ncFileAccessSettings) serviceAccountSet() map[string]bool {
	list := s.ServiceAccounts
	if list == nil {
		list = ncFADefaultServiceAccounts
	}
	out := map[string]bool{}
	for _, a := range list {
		if a = strings.TrimSpace(a); a != "" {
			out[a] = true
		}
	}
	return out
}

// ncAuditLogPath は読む audit.log を決める。
//
// internal/config には Nextcloud のデータディレクトリや audit.log そのものの設定が無い
// （あるのはインストール先の [paths].nextcloud_dir だけ）。データディレクトリはインストール先の
// 下とは限らないので、明示の audit_log_path を最優先にし、次に nextcloud_dir/data/audit.log、
// 最後に既定値を使う。
func ncAuditLogPath(cfg *config.AppConfig, s ncFileAccessSettings) string {
	if p := strings.TrimSpace(s.AuditLogPath); p != "" {
		return p
	}
	if cfg != nil {
		if d := strings.TrimSpace(cfg.Paths.NextcloudDir); d != "" {
			return filepath.Join(d, "data", "audit.log")
		}
	}
	return ncFAAuditLogDefaultPath
}

// ncFAStatePath は集計の状態ファイル。常に data/json に置く。
// alert_state.json の置き場所（[alerts].state_file）には合わせない。環境によっては
// それを /tmp に向けていて、再起動で消える。ここには 30 日分の接続元の学習と
// 学習期間の起点が入るので、消えると「初めての接続元」が再起動のたびに 3 日間判定されなくなる。
func ncFAStatePath() string {
	return sab.SabPath("data/json/nc_file_access_state.json")
}

// ---------------------------------------------------------------------------
// 状態（data/json/nc_file_access_state.json）
// ---------------------------------------------------------------------------

// ncFAState は実行をまたいで持つ集計。
//   - Offsets:   audit.log の読み取り済みバイト位置（集計と同じファイルに置き、ずれないようにする）
//   - Inodes:    そのとき読んでいた audit.log の inode（名前を変える切り替えの検出用。取れない環境では無い）
//   - Heads:     そのとき読んでいた audit.log の先頭 512 バイト（短ければその長さ）の SHA-256 と長さ
//     （inode の使い回し・手の切り詰めの検出と、.1 が前回のファイルかの確認に使う）
//   - Users:     利用者ごとの直近 60 分の 1 分刻みの集計と、窓内に取得したフォルダ
//   - Links:     公開リンク（token のハッシュ）ごとの直近 60 分の集計
//   - IPSeen:    利用者ごとの過去 30 日に使った接続元（初回・最終確認、unix 秒）
//   - CreatedAt: 状態を初めて作った時刻。ここから 3 日は「初めての接続元」を判定しない
type ncFAState struct {
	Version   int                            `json:"version"`
	CreatedAt time.Time                      `json:"created_at"`
	Offsets   map[string]int64               `json:"offsets"`
	Inodes    map[string]uint64              `json:"inodes,omitempty"`
	Heads     map[string]ncFAHead            `json:"heads,omitempty"`
	Users     map[string]*ncFAUser           `json:"users"`
	Links     map[string]*ncFALink           `json:"links"`
	IPSeen    map[string]map[string]ncFASeen `json:"ip_seen"`
}

type ncFASeen struct {
	First int64 `json:"f"`
	Last  int64 `json:"l"`
}

// ncFAHead はファイル先頭の指紋。
type ncFAHead struct {
	Hash string `json:"h"`
	Len  int64  `json:"n"`
}

// ncFABucket は 1 分ぶんの集計。Lines はサービスアカウントだけが使う（取得以外も含む行数）。
type ncFABucket struct {
	Min      int64          `json:"t"`
	Count    int            `json:"n,omitempty"`
	OffHours int            `json:"off,omitempty"`
	ByIP     map[string]int `json:"ip,omitempty"`
	ByDevice map[string]int `json:"dev,omitempty"`
	Lines    map[string]int `json:"lines,omitempty"`
}

type ncFAUser struct {
	Buckets []*ncFABucket `json:"b"`
	// Folders はフォルダ（パスのハッシュ）→ 最後に取得した時刻（unix 秒）。パスそのものは残さない。
	Folders map[string]int64 `json:"f,omitempty"`
}

type ncFALink struct {
	// Masked は通知に出す伏せ字（先頭 4 文字＋…）。token そのものは状態にも残さない。
	Masked  string        `json:"masked"`
	Owner   string        `json:"owner,omitempty"`
	Buckets []*ncFABucket `json:"b"`
}

func newNCFAState() *ncFAState {
	st := &ncFAState{Version: ncFAStateVersion}
	st.ensure()
	return st
}

func (st *ncFAState) ensure() {
	if st.Version == 0 {
		st.Version = ncFAStateVersion
	}
	if st.Offsets == nil {
		st.Offsets = map[string]int64{}
	}
	if st.Inodes == nil {
		st.Inodes = map[string]uint64{}
	}
	if st.Heads == nil {
		st.Heads = map[string]ncFAHead{}
	}
	if st.Users == nil {
		st.Users = map[string]*ncFAUser{}
	}
	if st.Links == nil {
		st.Links = map[string]*ncFALink{}
	}
	if st.IPSeen == nil {
		st.IPSeen = map[string]map[string]ncFASeen{}
	}
	// 手で直した・壊れた状態ファイルの null を取り除く（集計中に nil を踏まないため）。
	for uid, u := range st.Users {
		if u == nil {
			delete(st.Users, uid)
			continue
		}
		u.Buckets = dropNilBuckets(u.Buckets)
	}
	for k, l := range st.Links {
		if l == nil {
			delete(st.Links, k)
			continue
		}
		l.Buckets = dropNilBuckets(l.Buckets)
	}
}

func dropNilBuckets(bs []*ncFABucket) []*ncFABucket {
	out := bs[:0]
	for _, b := range bs {
		if b != nil {
			out = append(out, b)
		}
	}
	return out
}

// loadNCFAState は状態ファイルを読む。2 つ目の戻り値は「ファイルが既にあったか」。
// 壊れているときはログに出して作り直す（offset も消えるので、次の 1 回は末尾まで進めるだけになる）。
func loadNCFAState(p string) (*ncFAState, bool) {
	data, err := os.ReadFile(p)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("alerts: nc_file_access: cannot read state %s, starting over: %v", p, err)
			return newNCFAState(), true
		}
		return newNCFAState(), false
	}
	var st ncFAState
	if err := json.Unmarshal(data, &st); err != nil {
		log.Printf("alerts: nc_file_access: state %s is broken, starting over: %v", p, err)
		return newNCFAState(), true
	}
	st.ensure()
	return &st, true
}

// saveNCFAState は一時ファイルに書いてから置き換える（書きかけで壊さない）。
// 利用者 ID と接続元を含むので 0600 にする。
func saveNCFAState(p string, st *ncFAState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".nc_file_access_state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, p); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

func (st *ncFAState) user(uid string) *ncFAUser {
	u := st.Users[uid]
	if u == nil {
		u = &ncFAUser{}
		st.Users[uid] = u
	}
	return u
}

// touchIP は利用者の接続元の履歴を更新する。30 日を超えて空いてから再び現れた接続元は、
// その時点を新しい「初回」として扱う（過去 30 日に使っていない接続元になる）。
func (st *ncFAState) touchIP(uid, ip string, ts int64) {
	m := st.IPSeen[uid]
	if m == nil {
		m = map[string]ncFASeen{}
		st.IPSeen[uid] = m
	}
	s, ok := m[ip]
	ttl := int64(ncFAIPHistoryTTL / time.Second)
	switch {
	case !ok || ts-s.Last > ttl:
		s = ncFASeen{First: ts, Last: ts}
	default:
		if ts > s.Last {
			s.Last = ts
		}
		if ts < s.First {
			s.First = ts
		}
	}
	m[ip] = s
}

// ncFAIPUnit は「初めての接続元」を判定する単位。IPv4 はアドレスそのもの、IPv6 は /64
// （一時アドレスが毎日変わっても同じ回線を新しい接続元と数えないため）。解釈できなければそのまま。
func ncFAIPUnit(ip string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ip
	}
	a = a.WithZone("").Unmap()
	if a.Is4() {
		return a.String()
	}
	p, err := a.Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}

// isNewIP は、その接続元（ncFAIPUnit の単位）が窓の始まりより前（過去 30 日）に使われていないかを返す。
// 履歴に無いもの（上限で捨てたもの）は新しい接続元として扱う。
func (st *ncFAState) isNewIP(uid, unit string, windowStart int64) bool {
	s, ok := st.IPSeen[uid][unit]
	if !ok {
		return true
	}
	return s.First > windowStart
}

func bucketFor(buckets *[]*ncFABucket, minute int64) *ncFABucket {
	bs := *buckets
	for i := len(bs) - 1; i >= 0; i-- {
		if bs[i].Min == minute {
			return bs[i]
		}
	}
	b := &ncFABucket{Min: minute}
	*buckets = append(bs, b)
	return b
}

func incr(m *map[string]int, key string) {
	if *m == nil {
		*m = map[string]int{}
	}
	(*m)[key]++
}

// ncFAInWindow は時刻 ts（unix 秒）を窓で数えるか。窓の開始より前に始まる 1 分刻みは数えない
// （1 分刻みの丸めで窓が 61 分にならないよう、59〜60 分の側に寄せる）。
func ncFAInWindow(ts, windowStart int64) bool {
	return ts > windowStart && ts-ts%ncFABucketSec >= windowStart
}

// keepBuckets は窓の中に始まるバケットだけを残す。
func keepBuckets(bs []*ncFABucket, windowStart int64) []*ncFABucket {
	out := bs[:0]
	for _, b := range bs {
		if b != nil && b.Min >= windowStart {
			out = append(out, b)
		}
	}
	return out
}

// prune は窓から外れた集計と、30 日より古い接続元の履歴を捨てる。
func (st *ncFAState) prune(now time.Time) {
	ws := now.Add(-ncFAWindow).Unix()
	for uid, u := range st.Users {
		u.Buckets = keepBuckets(u.Buckets, ws)
		for f, last := range u.Folders {
			if !ncFAInWindow(last, ws) {
				delete(u.Folders, f)
			}
		}
		if len(u.Buckets) == 0 && len(u.Folders) == 0 {
			delete(st.Users, uid)
		}
	}
	for k, l := range st.Links {
		l.Buckets = keepBuckets(l.Buckets, ws)
		if len(l.Buckets) == 0 {
			delete(st.Links, k)
		}
	}
	ttlStart := now.Add(-ncFAIPHistoryTTL).Unix()
	for uid, ips := range st.IPSeen {
		for ip, s := range ips {
			if s.Last < ttlStart {
				delete(ips, ip)
			}
		}
		if len(ips) > ncFAMaxIPsPerUser {
			type kv struct {
				ip   string
				last int64
			}
			list := make([]kv, 0, len(ips))
			for ip, s := range ips {
				list = append(list, kv{ip, s.Last})
			}
			sort.Slice(list, func(i, j int) bool {
				if list[i].last != list[j].last {
					return list[i].last > list[j].last
				}
				return list[i].ip < list[j].ip
			})
			for _, e := range list[ncFAMaxIPsPerUser:] {
				delete(ips, e.ip)
			}
		}
		if len(ips) == 0 {
			delete(st.IPSeen, uid)
		}
	}
}

// ---------------------------------------------------------------------------
// 読み取り（offset・ローテーション・行数上限）
// ---------------------------------------------------------------------------

type ncFAReadStats struct {
	consumed int64 // 読み進めたバイト数
	lines    int   // 読み進めた行数（空行・壊れた行も数える）
	eof      bool  // 末尾まで読み切ったか
}

// ncFAReadFrom は f の start から最大 budget 行を読み、行ごとに fn を呼ぶ。
// finalFile=false のときは改行で終わっていない最後の行（書きかけ）を読まずに残す。
func ncFAReadFrom(f *os.File, start int64, budget int, finalFile bool, fn func([]byte)) (ncFAReadStats, error) {
	var rs ncFAReadStats
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return rs, err
	}
	r := bufio.NewReaderSize(f, 64*1024)
	for rs.lines < budget {
		b, err := r.ReadBytes('\n')
		if len(b) > 0 {
			if b[len(b)-1] != '\n' && !finalFile {
				// 書きかけの行。次回、続きが書かれてから読む。
				rs.eof = true
				break
			}
			rs.consumed += int64(len(b))
			rs.lines++
			if len(b) <= ncFAMaxLineBytes {
				fn(b)
			}
		}
		if err != nil {
			if err == io.EOF {
				rs.eof = true
				return rs, nil
			}
			return rs, err
		}
	}
	if !rs.eof {
		// 上限ちょうどで読み終えた場合を「残りあり」と誤認しない。
		if _, err := r.Peek(1); err == io.EOF {
			rs.eof = true
		}
	}
	return rs, nil
}

// ncFAFileIDFn はファイルの識別子（Linux では inode）を返す。取れなければ ok=false。
// テストで差し替えて、inode の取れない Windows でも名前を変える切り替えを模せるようにしている。
var ncFAFileIDFn = func(_ string, fi os.FileInfo) (uint64, bool) {
	return ncFAFileIDFromInfo(fi)
}

// ncFAPos は audit.log の読み取り位置と、そのとき読んでいたファイルの識別子（inode）・先頭の指紋。
type ncFAPos struct {
	Offset  int64
	ID      uint64
	HasID   bool
	Head    ncFAHead
	HasHead bool
}

// ncFAHeadOf はファイルの先頭 n バイトの指紋を作る。n バイト読めなければ ok=false。
func ncFAHeadOf(f *os.File, n int64) (ncFAHead, bool) {
	if n < 0 {
		return ncFAHead{}, false
	}
	buf := make([]byte, n)
	if n > 0 {
		if got, _ := f.ReadAt(buf, 0); int64(got) != n {
			return ncFAHead{}, false
		}
	}
	sum := sha256.Sum256(buf)
	return ncFAHead{Hash: hex.EncodeToString(sum[:]), Len: n}, true
}

// ncFAHeadMatches はファイルの先頭が記録した指紋と同じか。
func ncFAHeadMatches(f *os.File, size int64, h ncFAHead) bool {
	if h.Len < 0 || size < h.Len {
		return false
	}
	got, ok := ncFAHeadOf(f, h.Len)
	return ok && got.Hash == h.Hash
}

// ncFATail は audit.log を前回の位置から差分で読み、次回の位置と「読めたか」を返す。
//
//   - 読めない: 位置を変えず readable=false（呼び出し側は記録しない）。ファイルが無い以外の理由
//     （権限・ディレクトリ等）は毎回ログに 1 行出す
//   - 初回（seen=false）: 読まずに末尾の位置を返す（過去分で発報しない）
//   - 切り替わり: サイズが記録位置より小さい（copytruncate・手の切り詰め）、inode が変わった
//     （名前を .1 に変えて作り直す create 方式）、先頭の指紋が記録と違う（inode の使い回し・
//     作り直した後に記録位置より大きく育った・inode が取れない環境）のどれか。
//     このときは、先頭の指紋が記録と一致する audit.log.1 だけを記録位置から末尾まで読み
//     （ncFAReadRotated）、続けて新しい audit.log を 0 から読む。.1.gz は読まない
//   - 1 回に読む行数は budget まで。残りは次回
func ncFATail(p string, prev ncFAPos, seen bool, budget int, fn func([]byte)) (ncFAPos, bool) {
	f, err := os.Open(p)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("alerts: nc_file_access: cannot read audit log: %v", err)
		}
		return prev, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		log.Printf("alerts: nc_file_access: cannot read audit log %s: %v", p, err)
		return prev, false
	}
	if fi.IsDir() {
		log.Printf("alerts: nc_file_access: cannot read audit log %s: is a directory", p)
		return prev, false
	}
	size := fi.Size()
	cur := ncFAPos{Offset: size}
	cur.ID, cur.HasID = ncFAFileIDFn(p, fi)
	recordHead := func() {
		n := size
		if n > ncFAHeadBytes {
			n = ncFAHeadBytes
		}
		cur.Head, cur.HasHead = ncFAHeadOf(f, n)
	}
	if !seen || prev.Offset < 0 {
		recordHead()
		return cur, true
	}
	start := prev.Offset

	rotated := size < start ||
		(cur.HasID && prev.HasID && cur.ID != prev.ID) ||
		(prev.HasHead && !ncFAHeadMatches(f, size, prev.Head))
	if !rotated {
		rs, err := ncFAReadFrom(f, start, budget, false, fn)
		if err != nil {
			log.Printf("alerts: nc_file_access: read %s: %v", p, err)
		}
		if err == nil && !rs.eof {
			log.Printf("alerts: nc_file_access: read limit (%d lines) reached for %s, the rest is read next run", budget, p)
		}
		cur.Offset = start + rs.consumed
		recordHead()
		return cur, true
	}

	log.Printf("alerts: nc_file_access: %s was rotated or truncated, reading it from the start", p)
	remaining := budget - ncFAReadRotated(p+".1", prev, budget, fn)
	if remaining <= 0 {
		cur.Offset = 0
		recordHead()
		return cur, true
	}
	rs, err := ncFAReadFrom(f, 0, remaining, false, fn)
	if err != nil {
		log.Printf("alerts: nc_file_access: read %s: %v", p, err)
	}
	if err == nil && !rs.eof {
		log.Printf("alerts: nc_file_access: read limit (%d lines) reached for %s, the rest is read next run", budget, p)
	}
	cur.Offset = rs.consumed
	recordHead()
	return cur, true
}

// ncFAReadRotated は切り替わりの直後に、前回読んでいたファイルの残りを rot（audit.log.1）から読む。
// 戻り値は読み進めた行数。
//
// rot の先頭の指紋が前回のファイルの指紋と一致し、記録位置以上の大きさがあるときだけ、記録位置から
// 末尾まで読む（名前を変えた前回のファイル・copytruncate のコピー）。一致しない（前回から 2 回以上
// 切り替わった・別のファイル）とき、指紋を記録していないときは読まない。
func ncFAReadRotated(rot string, prev ncFAPos, budget int, fn func([]byte)) int {
	rf, err := os.Open(rot)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("alerts: nc_file_access: cannot read rotated audit log: %v", err)
		}
		return 0
	}
	defer rf.Close()
	rfi, err := rf.Stat()
	if err != nil || rfi.IsDir() {
		log.Printf("alerts: nc_file_access: cannot read rotated audit log %s", rot)
		return 0
	}
	if !prev.HasHead || rfi.Size() < prev.Offset || !ncFAHeadMatches(rf, rfi.Size(), prev.Head) {
		log.Printf("alerts: nc_file_access: %s is not the file read last time, not reading it (the rest of the previous file is skipped)", rot)
		return 0
	}
	rs, err := ncFAReadFrom(rf, prev.Offset, budget, true, fn)
	if err != nil {
		log.Printf("alerts: nc_file_access: read %s: %v", rot, err)
	}
	if err == nil && !rs.eof {
		log.Printf("alerts: nc_file_access: read limit (%d lines) reached in %s, the rest of the rotated file is skipped", budget, rot)
	}
	return rs.lines
}

// ---------------------------------------------------------------------------
// 1 行ずつの取り込み
// ---------------------------------------------------------------------------

// ncAuditLine は audit.log の 1 行のうち使うフィールド。
type ncAuditLine struct {
	Time       string `json:"time"`
	User       string `json:"user"`
	RemoteAddr string `json:"remoteAddr"`
	UserAgent  string `json:"userAgent"`
	Message    string `json:"message"`
}

type ncFAIngester struct {
	st          *ncFAState
	windowStart int64
	ttlStart    int64
	futureLimit int64 // これ以降の時刻の行は数えない
	jst         *time.Location
	services    map[string]bool
	// folderPruned は、この実行でフォルダの上限に当たって一度掃除した利用者（掃除は 1 回だけ）。
	folderPruned map[string]bool

	broken  int // JSON として読めない行
	badTime int // time を解釈できない行
	future  int // 評価時刻より 5 分以上先の行
}

func newNCFAIngester(st *ncFAState, now time.Time, services map[string]bool) *ncFAIngester {
	return &ncFAIngester{
		st:           st,
		futureLimit:  now.Add(ncFAFutureTolerance).Unix(),
		windowStart:  now.Add(-ncFAWindow).Unix(),
		ttlStart:     now.Add(-ncFAIPHistoryTTL).Unix(),
		jst:          sab.JST(),
		services:     services,
		folderPruned: map[string]bool{},
	}
}

func (g *ncFAIngester) add(raw []byte) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return
	}
	var l ncAuditLine
	if err := json.Unmarshal(raw, &l); err != nil {
		g.broken++
		return
	}
	t, ok := nclog.ParseTime(strings.TrimSpace(l.Time))
	if !ok {
		g.badTime++
		return
	}
	ts := t.Unix()
	if ts >= g.futureLimit {
		// 時計のずれた行など。窓に残り続けて cooldown が明けるたびに発報するのを防ぐ。
		g.future++
		return
	}
	uid := ncFANormUser(l.User)
	ip := strings.TrimSpace(l.RemoteAddr)
	msg := strings.TrimSpace(l.Message)

	// 接続元の履歴は取得以外の行（ログイン等）からも覚える。IPv6 は /64 単位。
	if uid != "" && ip != "" && ts > g.ttlStart {
		g.st.touchIP(uid, ncFAIPUnit(ip), ts)
	}
	if !ncFAInWindow(ts, g.windowStart) {
		return
	}
	minute := ts - ts%ncFABucketSec
	isService := uid != "" && g.services[uid]

	if p, ok := ncFAParseAccess(msg); ok {
		if uid != "" {
			u := g.st.user(uid)
			b := bucketFor(&u.Buckets, minute)
			b.Count++
			if ip != "" {
				incr(&b.ByIP, ip)
			}
			incr(&b.ByDevice, ncFADeviceClass(l.UserAgent))
			if ncFAIsOffHours(t, g.jst) {
				b.OffHours++
			}
			if !isService {
				g.addFolder(uid, u, p, ts)
			}
		}
	} else if token, owner, ok := ncFAParsePublicLink(msg); ok && uid == "" {
		// 公開リンクの行は user が空（または --）。user が入っている行は公開リンクとして数えない。
		key := ncFATokenKey(token)
		lk := g.st.Links[key]
		if lk == nil {
			lk = &ncFALink{Masked: ncFAMaskToken(token)}
			g.st.Links[key] = lk
		}
		if owner = ncFASanitize(owner, 128); owner != "" {
			lk.Owner = owner
		}
		b := bucketFor(&lk.Buckets, minute)
		b.Count++
		if ip != "" {
			incr(&b.ByIP, ip)
		}
	}

	if isService && ip != "" {
		b := bucketFor(&g.st.user(uid).Buckets, minute)
		incr(&b.Lines, ip)
	}
}

func (g *ncFAIngester) addFolder(uid string, u *ncFAUser, filePath string, ts int64) {
	dir := path.Dir(filePath)
	if dir == "." || dir == "" {
		return
	}
	key := ncFAFolderKey(dir)
	if u.Folders == nil {
		u.Folders = map[string]int64{}
	}
	if last, ok := u.Folders[key]; ok {
		if ts > last {
			u.Folders[key] = ts
		}
		return
	}
	if len(u.Folders) >= ncFAMaxFoldersPerUser {
		if !g.folderPruned[uid] {
			g.folderPruned[uid] = true
			for f, last := range u.Folders {
				if !ncFAInWindow(last, g.windowStart) {
					delete(u.Folders, f)
				}
			}
		}
		if len(u.Folders) >= ncFAMaxFoldersPerUser {
			return
		}
	}
	u.Folders[key] = ts
}

func (g *ncFAIngester) logSkipped(p string) {
	if g.broken > 0 || g.badTime > 0 || g.future > 0 {
		log.Printf("alerts: nc_file_access: skipped lines in %s (broken JSON %d, unknown time %d, future %d)", p, g.broken, g.badTime, g.future)
	}
}

// ncFANormUser は user を正規化する。公開リンク経由などで `--` になる場合は空として扱う。
func ncFANormUser(u string) string {
	u = strings.TrimSpace(u)
	if u == "--" {
		return ""
	}
	return u
}

// ncFAParseAccess は取得の行からファイルのパスを取り出す。
func ncFAParseAccess(msg string) (string, bool) {
	m := reNCFileAccessed.FindStringSubmatch(msg)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ncFAParsePublicLink は公開リンクの行から token と（あれば）持ち主を取り出す。
func ncFAParsePublicLink(msg string) (token, owner string, ok bool) {
	m := reNCPublicLink.FindStringSubmatch(msg)
	if m == nil || m[1] == "" {
		return "", "", false
	}
	return m[1], strings.TrimSpace(m[2]), true
}

// ncFAIsOffHours は JST 22:00〜06:00 または土日か。
func ncFAIsOffHours(t time.Time, jst *time.Location) bool {
	jt := t.In(jst)
	switch jt.Weekday() {
	case time.Saturday, time.Sunday:
		return true
	}
	h := jt.Hour()
	return h >= 22 || h < 6
}

// ncFADeviceClass は userAgent を端末の種類に分ける。
func ncFADeviceClass(ua string) string {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return "不明"
	}
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "mirall"):
		return "同期アプリ"
	case strings.Contains(lower, "nextcloud-android"), strings.Contains(lower, "nextcloud-ios"):
		return "スマホ"
	case strings.Contains(lower, "mozilla"):
		return "ブラウザ"
	}
	first := ua
	if i := strings.IndexAny(first, " \t"); i >= 0 {
		first = first[:i]
	}
	if i := strings.Index(first, "/"); i >= 0 {
		first = first[:i]
	}
	if first = ncFASanitize(first, 40); first == "" {
		return "不明"
	}
	return first
}

// ncFATokenKey は公開リンクの token を状態・cooldown のキーにするためのハッシュ。
// token は共有を開く鍵そのものなので、状態ファイルにも alert_state.json にも生では残さない。
func ncFATokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:16])
}

func ncFAFolderKey(dir string) string {
	h := fnv.New64a()
	h.Write([]byte(dir))
	return strconv.FormatUint(h.Sum64(), 16)
}

// ncFAMaskToken は token を先頭 4 文字＋… に伏せる（短すぎる token は半分だけ出す）。
func ncFAMaskToken(token string) string {
	r := []rune(ncFASanitize(token, 64))
	n := 4
	if len(r) <= n {
		n = len(r) / 2
	}
	return string(r[:n]) + "…"
}

// ncFASanitize はログ由来の文字列から制御文字・行区切り（Zl）・段落区切り（Zp）・書式制御（Cf。
// RLO 等の向きの上書きやゼロ幅文字）を ? に置き換え、max 文字で切る（通知文を崩さないため）。
func ncFASanitize(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			b.WriteString("…")
			break
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Zl, unicode.Zp, unicode.Cf) {
			r = '?'
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// ncFAShellArg は uid を初動のコマンド例へそのまま貼れる形にする（空白や記号があれば単引用符で囲む）。
var reNCFAPlainArg = regexp.MustCompile(`^[A-Za-z0-9_.@+-]+$`)

func ncFAShellArg(s string) string {
	if reNCFAPlainArg.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ---------------------------------------------------------------------------
// 評価
// ---------------------------------------------------------------------------

// evaluateNCFileAccess は audit.log を差分で読み、直近 60 分の取得を利用者・公開リンクごとに
// 数えて、しきい値を超えたものを通知する（Run() の 6 番目）。
//
// ルールが無効でも読み取りと集計は続ける（offset を最新に保ち、接続元の学習を進めておくため。
// 有効にした時点で「初めての接続元」の判定がすぐ使える）。
func evaluateNCFileAccess(cfg *config.AppConfig, rules AlertRules, state *AlertState) []string {
	settings := loadNCFileAccessSettings()
	services := settings.serviceAccountSet()
	auditPath := ncAuditLogPath(cfg, settings)
	statePath := ncFAStatePath()

	st, existed := loadNCFAState(statePath)
	now := nowFn()
	if st.CreatedAt.IsZero() {
		st.CreatedAt = now
	}

	ing := newNCFAIngester(st, now, services)
	prevOffset, seen := st.Offsets[auditPath]
	prevID, prevHasID := st.Inodes[auditPath]
	prevHead, prevHasHead := st.Heads[auditPath]
	prev := ncFAPos{Offset: prevOffset, ID: prevID, HasID: prevHasID, Head: prevHead, HasHead: prevHasHead}
	next, readable := ncFATail(auditPath, prev, seen, ncFAMaxLinesPerRun, ing.add)
	if readable {
		// 設定でパスが変わった場合に古いパスの位置を残さない。
		st.Offsets = map[string]int64{auditPath: next.Offset}
		st.Inodes = map[string]uint64{}
		if next.HasID {
			st.Inodes[auditPath] = next.ID
		}
		st.Heads = map[string]ncFAHead{}
		if next.HasHead {
			st.Heads[auditPath] = next.Head
		}
	} else if !existed {
		// audit.log がまだ無い（読めない）ホスト。状態ファイルも作らない。
		return nil
	}
	ing.logSkipped(auditPath)

	st.prune(now)
	out := ncFAEvaluate(cfg, rules, state, st, now, services)
	ncFAPruneCooldowns(state, now)

	if err := saveNCFAState(statePath, st); err != nil {
		log.Printf("alerts: nc_file_access: save state %s: %v", statePath, err)
	}
	return out
}

// ncFARuleParams は有効なルールのしきい値と cooldown を返す。0 以下は既定値で埋める
// （nc_service_volume だけは threshold 0 以下＝判定しない）。
func ncFARuleParams(rules AlertRules, ruleID string) (float64, int, bool) {
	r, defined := rules.Rules[ruleID]
	if !defined || !r.Enabled {
		return 0, 0, false
	}
	d := ncFADefaults[ruleID]
	th := r.Threshold
	if th <= 0 {
		if ruleID == ruleNCServiceVolume {
			return 0, 0, false
		}
		th = d.threshold
	}
	cd := r.CooldownSec
	if cd <= 0 {
		cd = d.cooldown
	}
	return th, cd, true
}

type ncFAAgg struct {
	count    int
	offHours int
	byIP     map[string]int
	byDevice map[string]int
	lines    map[string]int
}

func ncFAAggregate(bs []*ncFABucket) ncFAAgg {
	a := ncFAAgg{byIP: map[string]int{}, byDevice: map[string]int{}, lines: map[string]int{}}
	for _, b := range bs {
		a.count += b.Count
		a.offHours += b.OffHours
		for k, v := range b.ByIP {
			a.byIP[k] += v
		}
		for k, v := range b.ByDevice {
			a.byDevice[k] += v
		}
		for k, v := range b.Lines {
			a.lines[k] += v
		}
	}
	return a
}

// ncFATopKey は件数の最も多いキー（同数なら辞書順で先）を返す。無ければ空。
func ncFATopKey(m map[string]int) string {
	best, bestN := "", -1
	for k, v := range m {
		if v > bestN || (v == bestN && k < best) {
			best, bestN = k, v
		}
	}
	return best
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func orUnknown(s string) string {
	if s == "" {
		return "不明"
	}
	return s
}

// ncFAScopeLabel は通知文に出す環境（nc_user_events.go の local の label と同じ取り方）。
func ncFAScopeLabel(cfg *config.AppConfig) string {
	if cfg != nil {
		if t := strings.TrimSpace(cfg.VendorLicense.TenantID); t != "" {
			return t
		}
	}
	return "local"
}

func ncFATrimMessage(msg string) string {
	r := []rune(msg)
	if len(r) <= ncFAMessageMaxRunes {
		return msg
	}
	return string(r[:ncFAMessageMaxRunes-1]) + "…"
}

const (
	ncFAFirstStepUserFmt  = "初動: 本人確認 → occ user:disable %s → 監査ログで範囲確定"
	ncFAFirstStepUsers    = "初動: 利用者ごとに本人確認 → occ user:disable <uid> → 監査ログで範囲確定"
	ncFAFirstStepLink     = "初動: リンクの持ち主に確認 → 不要なら共有を削除"
	ncFAFirstStepService  = "初動: 連携先の処理か確認 → 心当たりが無ければアプリパスワードを再発行"
	ncFAOverflowSubject   = "\x00overflow" // まとめの通知の cooldown 用（利用者 ID にはならない値）
	ncFACooldownHashBytes = 8              // cooldown キーのハッシュ（16 文字）
)

// ncFARuleOrder は通知を組み立てる順（ルールごとの上限もこの単位で数える）。
var ncFARuleOrder = []string{
	ruleNCMassAccess, ruleNCFolderSweep, ruleNCNewIPAccess, ruleNCOffHoursAccess,
	ruleNCPublicLinkBurst, ruleNCServiceNewIP, ruleNCServiceVolume,
}

// ncFACooldownKey は alert_state.json に置く cooldown のキー。0644 のファイルなので、
// 利用者 ID・接続元・token を生で入れず、対象をハッシュにする（ルール ID の部分は掃除のために残す）。
func ncFACooldownKey(ruleID, subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return ruleID + ":" + hex.EncodeToString(sum[:ncFACooldownHashBytes])
}

func ncFAInCooldown(key string, cooldownSec int, state *AlertState, now time.Time) bool {
	last, ok := state.LastAlertTime[key]
	return ok && cooldownSec > 0 && now.Sub(last) < time.Duration(cooldownSec)*time.Second
}

// ncFACand はしきい値を超えた 1 件（通知の候補）。
type ncFACand struct {
	subject   string // cooldown の対象（ハッシュする前）
	label     string // まとめの通知に例として出す短い名前
	body      string
	firstStep string
}

func ncFAOverflowFirstStep(ruleID string) string {
	switch ruleID {
	case ruleNCPublicLinkBurst:
		return ncFAFirstStepLink
	case ruleNCServiceNewIP, ruleNCServiceVolume:
		return ncFAFirstStepService
	}
	return ncFAFirstStepUsers
}

func ncFAEvaluate(cfg *config.AppConfig, rules AlertRules, state *AlertState, st *ncFAState, now time.Time, services map[string]bool) []string {
	scope := ncFAScopeLabel(cfg)
	jst := sab.JST()
	wsTime := now.Add(-ncFAWindow)
	ws := wsTime.Unix()
	window := wsTime.In(jst).Format("15:04") + "〜" + now.In(jst).Format("15:04")
	windowMin := int(ncFAWindow / time.Minute)
	learning := now.Sub(st.CreatedAt) < ncFALearningPeriod

	cands := map[string][]ncFACand{}
	cooldowns := map[string]int{}
	add := func(ruleID string, cooldown int, c ncFACand) {
		cands[ruleID] = append(cands[ruleID], c)
		cooldowns[ruleID] = cooldown
	}

	for _, uid := range sortedKeys(st.Users) {
		u := st.Users[uid]
		agg := ncFAAggregate(u.Buckets)
		name := ncFASanitize(uid, 128)
		mainIP := orUnknown(ncFASanitize(ncFATopKey(agg.byIP), 64))
		device := orUnknown(ncFATopKey(agg.byDevice))

		if services[uid] {
			if th, cd, ok := ncFARuleParams(rules, ruleNCServiceNewIP); ok && !learning {
				// 接続元を判定の単位（IPv6 は /64）にまとめる。本文には実際のアドレスを出す。
				units := map[string]map[string]int{}
				for ip, n := range agg.lines {
					unit := ncFAIPUnit(ip)
					if units[unit] == nil {
						units[unit] = map[string]int{}
					}
					units[unit][ip] += n
				}
				for _, unit := range sortedKeys(units) {
					n := 0
					for _, v := range units[unit] {
						n += v
					}
					if !st.isNewIP(uid, unit, ws) || float64(n) < th {
						continue
					}
					ip := ncFASanitize(ncFATopKey(units[unit]), 64)
					extra := ""
					if len(units[unit]) > 1 {
						extra = fmt.Sprintf("・同じ /64 の接続元 %d 件", len(units[unit]))
					}
					body := fmt.Sprintf("%s が過去 30 日に使っていない接続元 %s から使われた（直近 %d 分で %d 件の記録%s）",
						name, ip, windowMin, n, extra)
					add(ruleNCServiceNewIP, cd, ncFACand{subject: uid + "\x00" + unit, label: name + "（" + ip + "）", body: body, firstStep: ncFAFirstStepService})
				}
			}
			if th, cd, ok := ncFARuleParams(rules, ruleNCServiceVolume); ok && agg.count > 0 && float64(agg.count) >= th {
				body := fmt.Sprintf("%s が直近 %d 分で %d 件取得（主な接続元 %s・端末 %s）",
					name, windowMin, agg.count, mainIP, device)
				add(ruleNCServiceVolume, cd, ncFACand{subject: uid, label: name, body: body, firstStep: ncFAFirstStepService})
			}
			continue
		}

		if agg.count == 0 {
			continue
		}
		firstStep := fmt.Sprintf(ncFAFirstStepUserFmt, ncFAShellArg(name))
		folders := len(u.Folders)

		if th, cd, ok := ncFARuleParams(rules, ruleNCMassAccess); ok && float64(agg.count) >= th {
			body := fmt.Sprintf("%s が直近 %d 分で %d 件取得（フォルダ %d・主な接続元 %s・端末 %s）",
				name, windowMin, agg.count, folders, mainIP, device)
			add(ruleNCMassAccess, cd, ncFACand{subject: uid, label: name, body: body, firstStep: firstStep})
		}
		if th, cd, ok := ncFARuleParams(rules, ruleNCFolderSweep); ok && float64(folders) >= th {
			body := fmt.Sprintf("%s が直近 %d 分で %d フォルダから取得（取得 %d 件・主な接続元 %s・端末 %s）",
				name, windowMin, folders, agg.count, mainIP, device)
			add(ruleNCFolderSweep, cd, ncFACand{subject: uid, label: name, body: body, firstStep: firstStep})
		}
		if th, cd, ok := ncFARuleParams(rules, ruleNCNewIPAccess); ok && !learning {
			newCount := 0
			newIPs := map[string]int{}
			for ip, n := range agg.byIP {
				if st.isNewIP(uid, ncFAIPUnit(ip), ws) {
					newCount += n
					newIPs[ip] = n
				}
			}
			if newCount > 0 && float64(newCount) >= th {
				ipLabel := ncFASanitize(ncFATopKey(newIPs), 64)
				if len(newIPs) > 1 {
					ipLabel += fmt.Sprintf(" ほか %d 件", len(newIPs)-1)
				}
				body := fmt.Sprintf("%s が過去 30 日に使っていない接続元から直近 %d 分で %d 件取得（新しい接続元 %s・取得計 %d 件・端末 %s）",
					name, windowMin, newCount, ipLabel, agg.count, device)
				add(ruleNCNewIPAccess, cd, ncFACand{subject: uid, label: name, body: body, firstStep: firstStep})
			}
		}
		if th, cd, ok := ncFARuleParams(rules, ruleNCOffHoursAccess); ok && agg.offHours > 0 && float64(agg.offHours) >= th {
			body := fmt.Sprintf("%s が直近 %d 分のうち夜間・土日（JST 22:00〜06:00・土日）に %d 件取得（取得計 %d 件・主な接続元 %s・端末 %s）",
				name, windowMin, agg.offHours, agg.count, mainIP, device)
			add(ruleNCOffHoursAccess, cd, ncFACand{subject: uid, label: name, body: body, firstStep: firstStep})
		}
	}

	if th, cd, ok := ncFARuleParams(rules, ruleNCPublicLinkBurst); ok {
		for _, key := range sortedKeys(st.Links) {
			lk := st.Links[key]
			agg := ncFAAggregate(lk.Buckets)
			if agg.count == 0 || float64(agg.count) < th {
				continue
			}
			owner := ""
			if o := ncFASanitize(lk.Owner, 128); o != "" {
				owner = "（持ち主 " + o + "）"
			}
			body := fmt.Sprintf("公開リンク %s%s へ直近 %d 分で %d 回アクセス（接続元 %d 件・主な接続元 %s）",
				lk.Masked, owner, windowMin, agg.count, len(agg.byIP), orUnknown(ncFASanitize(ncFATopKey(agg.byIP), 64)))
			add(ruleNCPublicLinkBurst, cd, ncFACand{subject: key, label: lk.Masked, body: body, firstStep: ncFAFirstStepLink})
		}
	}

	format := func(ruleID, body, firstStep string) string {
		return ncFATrimMessage(fmt.Sprintf("%s: %s(%s) 窓 %s\n%s", RuleLabel(ruleID), body, scope, window, firstStep))
	}
	var out []string
	for _, ruleID := range ncFARuleOrder {
		list := cands[ruleID]
		if len(list) == 0 {
			continue
		}
		cd := cooldowns[ruleID]
		sent := 0
		var over []ncFACand
		for _, c := range list {
			key := ncFACooldownKey(ruleID, c.subject)
			if ncFAInCooldown(key, cd, state, now) {
				continue
			}
			if sent >= ncFAMaxAlertsPerRule {
				over = append(over, c)
				continue
			}
			if shouldAlert(key, 0, cd, state, now) {
				out = append(out, fire(rules, ruleID, format(ruleID, c.body, c.firstStep)))
				sent++
			}
		}
		if len(over) == 0 {
			continue
		}
		// 上限を超えた分は 1 件にまとめる。まとめにも cooldown を効かせ、まとめた対象はその時点で
		// 通知済みとして扱う。まとめが cooldown 中なら、対象は次の回の候補に残す。
		if !shouldAlert(ncFACooldownKey(ruleID, ncFAOverflowSubject), 0, cd, state, now) {
			continue
		}
		labels := make([]string, 0, ncFAOverflowLabels)
		for i, c := range over {
			if i >= ncFAOverflowLabels {
				break
			}
			labels = append(labels, c.label)
		}
		example := strings.Join(labels, "、")
		if len(over) > len(labels) {
			example += " など"
		}
		body := fmt.Sprintf("ほか %d 件（同じルール）がしきい値を超えた（%s）", len(over), example)
		out = append(out, fire(rules, ruleID, format(ruleID, body, ncFAOverflowFirstStep(ruleID))))
		for _, c := range over {
			state.LastAlertTime[ncFACooldownKey(ruleID, c.subject)] = now
		}
	}
	return out
}

// ncFAPruneCooldowns は本機能の cooldown キーのうち、十分に古いものを alert_state.json から消す
// （利用者・接続元ごとにキーができるので、放っておくと増え続ける）。
func ncFAPruneCooldowns(state *AlertState, now time.Time) {
	for key, last := range state.LastAlertTime {
		i := strings.IndexByte(key, ':')
		if i < 0 {
			continue
		}
		if _, ours := ncFADefaults[key[:i]]; !ours {
			continue
		}
		if now.Sub(last) > ncFACooldownKeyRetention {
			delete(state.LastAlertTime, key)
		}
	}
}
