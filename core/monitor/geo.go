package monitor

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// geoCacheFile は GeoIP キャッシュのテスト用上書きパス。
//
// world-writable な /tmp ではなく、BASE_DIR 配下の data/json/ へ 0640 で保存する。/tmp の第三者汚染による GeoIP 判定改ざんを防ぐ。
// キャッシュ内容は国コードのみでトークンは含まれない。
var geoCacheFile string

func geoCacheFilePath() string {
	if geoCacheFile != "" {
		return geoCacheFile
	}
	return heartdesk.Path("data/json/geoip_cache.json")
}

// geoSettings は geo.go が参照する GeoIP 設定（env 直読みはせず AppConfig 由来）。
// SetGeoConfig で起動時に 1 度だけ設定する。HEARTDESK_IPINFO_TOKEN 等を process env へ
// 書き戻さないことで、util.Run の子プロセス（bash -c 等）へのトークン露出を断つ。
type geoSettings struct {
	Mode         string
	Token        string
	DBPath       string
	CacheTTLDays int
}

var (
	geoCfgMu sync.RWMutex
	geoCfg   geoSettings
)

// SetGeoConfig は AppConfig から GeoIP 設定を取り込む（起動時に main.go から呼ぶ）。
func SetGeoConfig(cfg *config.AppConfig) {
	if cfg == nil {
		return
	}
	geoCfgMu.Lock()
	geoCfg = geoSettings{
		Mode:         strings.TrimSpace(cfg.GeoIP.Mode),
		Token:        strings.TrimSpace(cfg.GeoIP.Token),
		DBPath:       strings.TrimSpace(cfg.Paths.GeoIPDB),
		CacheTTLDays: cfg.GeoIP.CacheTTLDays,
	}
	geoCfgMu.Unlock()
}

func geoSettingsSnapshot() geoSettings {
	geoCfgMu.RLock()
	defer geoCfgMu.RUnlock()
	return geoCfg
}

// geoCacheIPTTL は IP エントリの有効期限（geoip.cache_ttl_days、デフォルト7日）
func geoCacheIPTTL() time.Duration {
	if d := geoSettingsSnapshot().CacheTTLDays; d > 0 {
		return time.Duration(d) * 24 * time.Hour
	}
	return 7 * 24 * time.Hour
}

// geoMemCacheTTL はメモリキャッシュのリロード間隔（5分）
const geoMemCacheTTL = 5 * time.Minute

var geoMu sync.Mutex
var geoMemCache map[string]geoCacheEntry
var geoMemMeta geoCacheMeta
var geoMemLoadedAt time.Time
var geoHTTPClient = &http.Client{Timeout: 3 * time.Second}
var geoIPBatchURL = "https://api.ipinfo.io/batch/lite"
var geoLookupDB = lookupCountryFlagsFromDB

const (
	geoModeIPInfoAPI    = "ipinfo_api"
	geoModeIPInfoDB     = "ipinfo_db"
	geoModeIPInfoHybrid = "ipinfo_hybrid"
)

type geoCacheEntry struct {
	Country string `json:"country"`
	Ts      int64  `json:"ts"`
}

type geoCacheMeta struct {
	Provider   string `json:"provider,omitempty"`
	LastCallTS int64  `json:"last_call_ts,omitempty"`
	TotalCalls int    `json:"total_calls,omitempty"`
}

func geoLoadFile() (map[string]geoCacheEntry, geoCacheMeta) {
	raw, err := os.ReadFile(geoCacheFilePath())
	if err != nil {
		return make(map[string]geoCacheEntry), geoCacheMeta{}
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		return make(map[string]geoCacheEntry), geoCacheMeta{}
	}
	cache := make(map[string]geoCacheEntry, len(payload))
	var meta geoCacheMeta
	for key, value := range payload {
		if key == "_meta" {
			_ = json.Unmarshal(value, &meta)
			continue
		}
		var entry geoCacheEntry
		if err := json.Unmarshal(value, &entry); err == nil && entry.Country != "" {
			cache[key] = entry
			continue
		}
		var country string
		if err := json.Unmarshal(value, &country); err == nil && country != "" {
			cache[key] = geoCacheEntry{Country: country}
		}
	}
	return cache, meta
}

func geoSaveFile(cache map[string]geoCacheEntry, meta geoCacheMeta) {
	payload := make(map[string]interface{}, len(cache)+1)
	for ip, entry := range cache {
		payload[ip] = entry
	}
	if meta.Provider != "" || meta.LastCallTS != 0 || meta.TotalCalls != 0 {
		payload["_meta"] = meta
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	// 0640（heartdesk:heartdesk）で保存。world-readable を廃止。
	path := geoCacheFilePath()
	_ = os.MkdirAll(filepath.Dir(path), 0750)
	_ = os.WriteFile(path, raw, 0640)
}

type ipInfoResult struct {
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
}

func fetchIPInfoLite(ips []string) map[string]string {
	if len(ips) == 0 {
		return nil
	}
	token := geoSettingsSnapshot().Token
	if token == "" {
		return nil
	}
	batch := ips
	if len(batch) > 100 {
		batch = batch[:100]
	}
	body, _ := json.Marshal(batch)
	endpoint, err := url.Parse(geoIPBatchURL)
	if err != nil {
		return nil
	}
	query := endpoint.Query()
	query.Set("token", token)
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequest(http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := geoHTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var results map[string]ipInfoResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil
	}
	fetched := make(map[string]string, len(results))
	for ip, r := range results {
		if r.CountryCode == "" {
			continue
		}
		cc := strings.ToLower(r.CountryCode)
		flag := ccToFlag(cc)
		name := ccToName(cc)
		if r.IP != "" {
			ip = r.IP
		}
		fetched[ip] = strings.TrimSpace(flag + " " + name)
	}
	return fetched
}

func geoLookupMode() string {
	mode := strings.TrimSpace(geoSettingsSnapshot().Mode)
	switch mode {
	case "", geoModeIPInfoHybrid:
		return geoModeIPInfoHybrid
	case geoModeIPInfoAPI, geoModeIPInfoDB:
		return mode
	default:
		return geoModeIPInfoHybrid
	}
}

type ipInfoMMDBRecord struct {
	CountryCode string `maxminddb:"country_code"`
	Country     struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// geoDB は MaxMind DB ハンドルを遅延オープンして保持する。ルックアップごとの
// Open/Close を避け、パスが変わった場合のみ開き直す。maxminddb.Reader は
// 複数 goroutine からの Lookup に対して安全なため共有してよい。
var (
	geoDBMu     sync.Mutex
	geoDBReader *maxminddb.Reader
	geoDBPath   string
)

func geoDB(dbPath string) (*maxminddb.Reader, error) {
	geoDBMu.Lock()
	defer geoDBMu.Unlock()
	if geoDBReader != nil && geoDBPath == dbPath {
		return geoDBReader, nil
	}
	r, err := maxminddb.Open(dbPath)
	if err != nil {
		return nil, err
	}
	if geoDBReader != nil {
		_ = geoDBReader.Close()
	}
	geoDBReader = r
	geoDBPath = dbPath
	return geoDBReader, nil
}

func lookupCountryFlagsFromDB(ips []string) map[string]string {
	dbPath := strings.TrimSpace(geoSettingsSnapshot().DBPath)
	if dbPath == "" || len(ips) == 0 {
		return nil
	}

	db, err := geoDB(dbPath)
	if err != nil {
		return nil
	}

	fetched := make(map[string]string, len(ips))
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		var record ipInfoMMDBRecord
		if err := db.Lookup(parsed, &record); err != nil {
			continue
		}
		cc := strings.TrimSpace(record.CountryCode)
		if cc == "" {
			cc = strings.TrimSpace(record.Country.ISOCode)
		}
		if cc == "" {
			continue
		}
		cc = strings.ToLower(cc)
		flag := ccToFlag(cc)
		name := ccToName(cc)
		fetched[ip] = strings.TrimSpace(flag + " " + name)
	}
	return fetched
}

// GetCountryFlags は IP リストの国旗付き国名マップを返す (PHP get_country_flags() 相当)
func GetCountryFlags(ips []string) map[string]string {
	if len(ips) == 0 {
		return map[string]string{}
	}

	// Phase 1: キャッシュチェック
	geoMu.Lock()
	if geoMemCache == nil || time.Since(geoMemLoadedAt) > geoMemCacheTTL {
		geoMemCache, geoMemMeta = geoLoadFile()
		geoMemLoadedAt = time.Now()
	}
	result := make(map[string]string, len(ips))
	now := time.Now().Unix()
	ttlSec := int64(geoCacheIPTTL().Seconds())
	var lookupIPs []string
	for _, ip := range ips {
		if ip == "" || ip == "127.0.0.1" {
			continue
		}
		if e, ok := geoMemCache[ip]; ok && now-e.Ts < ttlSec {
			result[ip] = e.Country
		} else {
			// 期限切れ／Ts=0 のレガシーエントリでも旧国名があれば暫定値として先に入れておく
			// （stale-while-revalidate）。再取得が成功すれば後段で上書きされ、失敗（トークン未設定・
			// API 一時障害・mmdb 未配置）した場合は旧値が維持され、結果からの脱落を防ぐ。
			if ok && e.Country != "" {
				result[ip] = e.Country
			}
			lookupIPs = append(lookupIPs, ip)
		}
	}
	geoMu.Unlock()

	if len(lookupIPs) == 0 {
		return result
	}

	switch geoLookupMode() {
	case geoModeIPInfoDB:
		dbFetched := geoLookupDB(lookupIPs)
		if len(dbFetched) > 0 {
			geoMu.Lock()
			for ip, country := range dbFetched {
				result[ip] = country
				geoMemCache[ip] = geoCacheEntry{Country: country, Ts: now}
			}
			geoMemMeta.Provider = geoModeIPInfoDB
			geoSaveFile(geoMemCache, geoMemMeta)
			geoMu.Unlock()
		}
	case geoModeIPInfoAPI:
		fetched := fetchIPInfoLite(lookupIPs)
		if len(fetched) > 0 {
			geoMu.Lock()
			for ip, country := range fetched {
				result[ip] = country
				geoMemCache[ip] = geoCacheEntry{Country: country, Ts: now}
			}
			geoMemMeta.Provider = geoModeIPInfoAPI
			geoMemMeta.LastCallTS = now
			geoMemMeta.TotalCalls++
			geoSaveFile(geoMemCache, geoMemMeta)
			geoMu.Unlock()
		}
	default:
		// hybrid: まず DB、未解決のみ API へフォールバック
		dbFetched := geoLookupDB(lookupIPs)
		if len(dbFetched) > 0 {
			geoMu.Lock()
			for ip, country := range dbFetched {
				result[ip] = country
				geoMemCache[ip] = geoCacheEntry{Country: country, Ts: now}
			}
			geoMemMeta.Provider = geoModeIPInfoHybrid
			geoSaveFile(geoMemCache, geoMemMeta)
			geoMu.Unlock()
		}

		apiLookupIPs := make([]string, 0, len(lookupIPs))
		for _, ip := range lookupIPs {
			if _, ok := dbFetched[ip]; ok {
				continue
			}
			apiLookupIPs = append(apiLookupIPs, ip)
		}

		fetched := fetchIPInfoLite(apiLookupIPs)
		if len(fetched) > 0 {
			geoMu.Lock()
			for ip, country := range fetched {
				result[ip] = country
				geoMemCache[ip] = geoCacheEntry{Country: country, Ts: now}
			}
			geoMemMeta.Provider = geoModeIPInfoHybrid
			geoMemMeta.LastCallTS = now
			geoMemMeta.TotalCalls++
			geoSaveFile(geoMemCache, geoMemMeta)
			geoMu.Unlock()
		}
	}

	return result
}

// ccToFlag は 2 文字の国コードを Unicode 国旗絵文字に変換する
func ccToFlag(cc string) string {
	if len(cc) != 2 {
		return ""
	}
	r1 := rune(0x1F1E6 + int(cc[0]-'a'))
	r2 := rune(0x1F1E6 + int(cc[1]-'a'))
	return string(r1) + string(r2)
}

// ccNames は 2 文字の国コード → 日本語国名のマップ（毎回生成を避けるためパッケージ変数化）。
var ccNames = map[string]string{
	"ad": "アンドラ", "ae": "アラブ首長国連邦", "af": "アフガニスタン", "ag": "アンティグア・バーブーダ",
	"al": "アルバニア", "am": "アルメニア", "ao": "アンゴラ", "ar": "アルゼンチン",
	"at": "オーストリア", "au": "オーストラリア", "az": "アゼルバイジャン",
	"ba": "ボスニア・ヘルツェゴビナ", "bd": "バングラデシュ", "be": "ベルギー",
	"bf": "ブルキナファソ", "bg": "ブルガリア", "bh": "バーレーン", "bi": "ブルンジ",
	"bj": "ベナン", "bn": "ブルネイ", "bo": "ボリビア", "br": "ブラジル",
	"bt": "ブータン", "bw": "ボツワナ", "by": "ベラルーシ", "bz": "ベリーズ",
	"ca": "カナダ", "cd": "コンゴ民主共和国", "cf": "中央アフリカ", "cg": "コンゴ共和国",
	"ch": "スイス", "ci": "コートジボワール", "cl": "チリ", "cm": "カメルーン",
	"cn": "中国", "co": "コロンビア", "cr": "コスタリカ", "cu": "キューバ",
	"cy": "キプロス", "cz": "チェコ", "de": "ドイツ", "dj": "ジブチ",
	"dk": "デンマーク", "do": "ドミニカ共和国", "dz": "アルジェリア",
	"ec": "エクアドル", "ee": "エストニア", "eg": "エジプト", "er": "エリトリア",
	"es": "スペイン", "et": "エチオピア", "fi": "フィンランド", "fr": "フランス",
	"ga": "ガボン", "gb": "イギリス", "ge": "ジョージア", "gh": "ガーナ",
	"gn": "ギニア", "gq": "赤道ギニア", "gr": "ギリシャ", "gt": "グアテマラ",
	"gy": "ガイアナ", "hk": "香港", "hn": "ホンジュラス", "hr": "クロアチア",
	"ht": "ハイチ", "hu": "ハンガリー", "id": "インドネシア", "ie": "アイルランド",
	"il": "イスラエル", "in": "インド", "iq": "イラク", "ir": "イラン",
	"is": "アイスランド", "it": "イタリア", "jm": "ジャマイカ", "jo": "ヨルダン",
	"jp": "日本", "ke": "ケニア", "kg": "キルギス", "kh": "カンボジア",
	"kp": "北朝鮮", "kr": "韓国", "kw": "クウェート", "kz": "カザフスタン",
	"la": "ラオス", "lb": "レバノン", "lk": "スリランカ", "lr": "リベリア",
	"lt": "リトアニア", "lu": "ルクセンブルク", "lv": "ラトビア", "ly": "リビア",
	"ma": "モロッコ", "md": "モルドバ", "me": "モンテネグロ", "mg": "マダガスカル",
	"mk": "北マケドニア", "ml": "マリ", "mm": "ミャンマー", "mn": "モンゴル",
	"mo": "マカオ", "mr": "モーリタニア", "mt": "マルタ", "mu": "モーリシャス",
	"mv": "モルディブ", "mw": "マラウイ", "mx": "メキシコ", "my": "マレーシア",
	"mz": "モザンビーク", "na": "ナミビア", "ne": "ニジェール", "ng": "ナイジェリア",
	"ni": "ニカラグア", "nl": "オランダ", "no": "ノルウェー", "np": "ネパール",
	"nz": "ニュージーランド", "om": "オマーン", "pa": "パナマ", "pe": "ペルー",
	"pg": "パプアニューギニア", "ph": "フィリピン", "pk": "パキスタン",
	"pl": "ポーランド", "pr": "プエルトリコ", "ps": "パレスチナ", "pt": "ポルトガル",
	"py": "パラグアイ", "qa": "カタール", "ro": "ルーマニア", "rs": "セルビア",
	"ru": "ロシア", "rw": "ルワンダ", "sa": "サウジアラビア", "sd": "スーダン",
	"se": "スウェーデン", "sg": "シンガポール", "si": "スロベニア", "sk": "スロバキア",
	"sl": "シエラレオネ", "sn": "セネガル", "so": "ソマリア", "ss": "南スーダン",
	"sv": "エルサルバドル", "sy": "シリア", "th": "タイ", "tj": "タジキスタン",
	"tm": "トルクメニスタン", "tn": "チュニジア", "tr": "トルコ",
	"tt": "トリニダード・トバゴ", "tw": "台湾", "tz": "タンザニア",
	"ua": "ウクライナ", "ug": "ウガンダ", "us": "アメリカ", "uy": "ウルグアイ",
	"uz": "ウズベキスタン", "ve": "ベネズエラ", "vn": "ベトナム",
	"ye": "イエメン", "za": "南アフリカ", "zm": "ザンビア", "zw": "ジンバブエ",
}

// ccToName は 2 文字の国コードを日本語国名に変換する
func ccToName(cc string) string {
	if name, ok := ccNames[cc]; ok {
		return name
	}
	return strings.ToUpper(cc)
}
