package monitor

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// testMMDB は全 IPv4 アドレスが country_code=cc を返す最小の MaxMind DB を組み立てる。
// 検索木は 1 ノード（左右とも同じデータへのポインタ）、レコードサイズは 24 ビット。
func testMMDB(cc string) []byte {
	var b bytes.Buffer
	// 検索木: node_count=1。データへのポインタ = node_count + 16 + データ内オフセット(0) = 17。
	rec := []byte{0x00, 0x00, 0x11}
	b.Write(rec)
	b.Write(rec)
	// データ区画の区切り（16 バイトの 0）
	b.Write(make([]byte, 16))
	// データ: {"country_code": cc}
	b.WriteByte(0xE1) // map, 1 エントリ
	b.WriteByte(0x40 | byte(len("country_code")))
	b.WriteString("country_code")
	b.WriteByte(0x40 | byte(len(cc)))
	b.WriteString(cc)
	// メタデータ: {"node_count": 1, "record_size": 24, "ip_version": 4}
	b.WriteString("\xAB\xCD\xEFMaxMind.com")
	b.WriteByte(0xE3) // map, 3 エントリ
	b.WriteByte(0x40 | byte(len("node_count")))
	b.WriteString("node_count")
	b.Write([]byte{0xC1, 0x01}) // uint32 = 1
	b.WriteByte(0x40 | byte(len("record_size")))
	b.WriteString("record_size")
	b.Write([]byte{0xA1, 0x18}) // uint16 = 24
	b.WriteByte(0x40 | byte(len("ip_version")))
	b.WriteString("ip_version")
	b.Write([]byte{0xA1, 0x04}) // uint16 = 4
	return b.Bytes()
}

// writeTestMMDB は cc を返す mmdb をパスへ書き、更新時刻を mtime にそろえる。
func writeTestMMDB(t *testing.T, path, cc string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, testMMDB(cc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

// resetGeoDBForTest は geo.go の DB ハンドルの保持状態をテスト用に初期化し、終了時に戻す。
// DB はファイルを mmap せずに読み込んで開く（Windows では mmap 中のファイルを差し替えられないため）。
// openCount は DB を開いた回数を数える。
func resetGeoDBForTest(t *testing.T) (openCount *int) {
	t.Helper()
	clear := func() {
		geoDBMu.Lock()
		if geoDBReader != nil {
			_ = geoDBReader.Close()
		}
		geoDBReader = nil
		geoDBPath = ""
		geoDBModTime = time.Time{}
		geoDBSize = 0
		geoDBCheckedAt = time.Time{}
		geoDBLastWarn = ""
		geoDBMu.Unlock()
	}
	clear()
	origOpen, origInterval := geoDBOpen, geoDBStatInterval
	n := 0
	geoDBOpen = func(path string) (*maxminddb.Reader, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		n++
		return maxminddb.FromBytes(raw)
	}
	t.Cleanup(func() {
		geoDBOpen, geoDBStatInterval = origOpen, origInterval
		clear()
	})
	return &n
}

// resetGeoCacheForTest は国コードのキャッシュ（ファイル・メモリ）をテスト用の空の状態にする。
func resetGeoCacheForTest(t *testing.T) {
	t.Helper()
	origFile, origMem, origMeta, origAt := geoCacheFile, geoMemCache, geoMemMeta, geoMemLoadedAt
	geoCacheFile = filepath.Join(t.TempDir(), "geo_cache.json")
	geoMemCache, geoMemMeta, geoMemLoadedAt = nil, geoCacheMeta{}, time.Time{}
	t.Cleanup(func() {
		geoCacheFile, geoMemCache, geoMemMeta, geoMemLoadedAt = origFile, origMem, origMeta, origAt
	})
}

const testIP = "203.0.113.5"

func lookupOne(t *testing.T) string {
	t.Helper()
	return lookupCountryFlagsFromDB([]string{testIP})[testIP]
}

func TestTestMMDBIsReadable(t *testing.T) {
	resetGeoDBForTest(t)
	p := filepath.Join(t.TempDir(), "geo.mmdb")
	writeTestMMDB(t, p, "JP", time.Now())
	setGeoCfgForTest(t, geoSettings{DBPath: p})
	if got := lookupOne(t); got != "🇯🇵 日本" {
		t.Fatalf("合成 mmdb の検索結果 = %q, want 🇯🇵 日本", got)
	}
}

// ---- GEO-1: DB ファイルが差し替えられたら開き直す ----

func TestGeoDBReopensWhenFileIsReplaced(t *testing.T) {
	openCount := resetGeoDBForTest(t)
	p := filepath.Join(t.TempDir(), "geo.mmdb")
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	writeTestMMDB(t, p, "JP", t0)
	setGeoCfgForTest(t, geoSettings{DBPath: p})

	geoDBStatInterval = time.Hour
	if got := lookupOne(t); got != "🇯🇵 日本" {
		t.Fatalf("初回 = %q, want 🇯🇵 日本", got)
	}

	// scheduler が別プロセスで DB を差し替えた（サイズは同じ・更新時刻だけ変わる）。
	writeTestMMDB(t, p, "US", t0.Add(24*time.Hour))

	// 確認間隔の内側では stat しないので、まだ旧 DB のまま。
	if got := lookupOne(t); got != "🇯🇵 日本" {
		t.Fatalf("確認間隔内 = %q, want 旧 DB の 🇯🇵 日本（stat は間隔に 1 回）", got)
	}

	// 間隔を過ぎたら差し替えに気づいて開き直す。
	geoDBStatInterval = 0
	if got := lookupOne(t); got != "🇺🇸 アメリカ" {
		t.Fatalf("差し替え後 = %q, want 🇺🇸 アメリカ（開き直されていない）", got)
	}
	if *openCount != 2 {
		t.Errorf("DB を開いた回数 = %d, want 2", *openCount)
	}

	// 変わっていなければ開き直さない。
	_ = lookupOne(t)
	_ = lookupOne(t)
	if *openCount != 2 {
		t.Errorf("未変更なのに開き直した: 開いた回数 = %d, want 2", *openCount)
	}
}

func TestGeoDBReopensWhenSizeChanges(t *testing.T) {
	resetGeoDBForTest(t)
	p := filepath.Join(t.TempDir(), "geo.mmdb")
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	writeTestMMDB(t, p, "JP", t0)
	setGeoCfgForTest(t, geoSettings{DBPath: p})
	geoDBStatInterval = 0
	if got := lookupOne(t); got != "🇯🇵 日本" {
		t.Fatalf("初回 = %q", got)
	}
	// 更新時刻は同じまま、サイズだけ変わる差し替え（国コードが 3 文字 = 1 バイト増える）。
	writeTestMMDB(t, p, "USA", t0)
	// 3 文字の国コードは国旗が付かず、国コードがそのまま名前になる。
	if got := lookupOne(t); got != "USA" {
		t.Fatalf("サイズ変更に気づかず旧 DB のまま: %q, want USA", got)
	}
}

func TestGeoDBKeepsOldReaderWhenReplacementIsBroken(t *testing.T) {
	resetGeoDBForTest(t)
	var buf bytes.Buffer
	origOut, origFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(origOut); log.SetFlags(origFlags) })

	p := filepath.Join(t.TempDir(), "geo.mmdb")
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	writeTestMMDB(t, p, "JP", t0)
	setGeoCfgForTest(t, geoSettings{DBPath: p})
	geoDBStatInterval = 0
	if got := lookupOne(t); got != "🇯🇵 日本" {
		t.Fatalf("初回 = %q", got)
	}

	// 壊れたファイルに差し替わった（ダウンロード途中など）。旧 DB で引き続き答える。
	if err := os.WriteFile(p, []byte("not a mmdb"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, t0.Add(time.Hour), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if got := lookupOne(t); got != "🇯🇵 日本" {
			t.Fatalf("壊れた差し替え後 #%d = %q, want 旧 DB の 🇯🇵 日本", i, got)
		}
	}
	// 同じ理由の警告は繰り返さない。
	if n := strings.Count(buf.String(), "GeoIP DB を使えません"); n != 1 {
		t.Errorf("警告ログ = %d 回, want 1 回:\n%s", n, buf.String())
	}
}

// ---- GEO-5: DB が無い・壊れているときの警告ログ ----

func TestGeoDBWarnsOnceWhenMissing(t *testing.T) {
	resetGeoDBForTest(t)
	var buf bytes.Buffer
	origOut, origFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(origOut); log.SetFlags(origFlags) })

	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such.mmdb")
	setGeoCfgForTest(t, geoSettings{DBPath: missing, Token: "secret-token-value"})

	for i := 0; i < 3; i++ {
		if got := lookupOne(t); got != "" {
			t.Fatalf("DB が無いのに国が返った: %q", got)
		}
	}
	out := buf.String()
	if n := strings.Count(out, "GeoIP DB を使えません"); n != 1 {
		t.Fatalf("警告ログ = %d 回, want 1 回（同じ理由は繰り返さない）:\n%s", n, out)
	}
	if !strings.Contains(out, missing) {
		t.Errorf("警告にパスが含まれていない:\n%s", out)
	}
	if strings.Contains(out, "secret-token-value") {
		t.Errorf("警告に API トークンが含まれている:\n%s", out)
	}

	// 理由（パス）が変われば、また 1 回出す。
	other := filepath.Join(dir, "other.mmdb")
	setGeoCfgForTest(t, geoSettings{DBPath: other})
	_ = lookupOne(t)
	_ = lookupOne(t)
	if n := strings.Count(buf.String(), "GeoIP DB を使えません"); n != 2 {
		t.Fatalf("理由が変わったあとの警告ログ = %d 回, want 2 回:\n%s", n, buf.String())
	}

	// 壊れたファイルも警告する。
	broken := filepath.Join(dir, "broken.mmdb")
	if err := os.WriteFile(broken, []byte("not a mmdb"), 0o600); err != nil {
		t.Fatal(err)
	}
	setGeoCfgForTest(t, geoSettings{DBPath: broken})
	_ = lookupOne(t)
	if n := strings.Count(buf.String(), "GeoIP DB を使えません"); n != 3 {
		t.Fatalf("壊れた DB の警告ログ込み = %d 回, want 3 回:\n%s", n, buf.String())
	}
}

func TestGeoDBNoWarningWhenNotConfigured(t *testing.T) {
	resetGeoDBForTest(t)
	var buf bytes.Buffer
	origOut, origFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(origOut); log.SetFlags(origFlags) })

	setGeoCfgForTest(t, geoSettings{})
	if got := lookupOne(t); got != "" {
		t.Fatalf("DB 未設定なのに国が返った: %q", got)
	}
	if buf.Len() != 0 {
		t.Errorf("DB 未設定（GeoIP を使わない構成）で警告が出た: %s", buf.String())
	}
}

// ---- GEO-2: disk カードの国別集計が [paths].geoip_db を見る ----

func TestGeoipCountryCountsUsesConfiguredDBPath(t *testing.T) {
	resetGeoDBForTest(t)
	resetGeoCacheForTest(t)
	t.Setenv("HEARTDESK_GEOIP_DB", "") // env は無し（TOML 相当の設定だけにパスがある）
	p := filepath.Join(t.TempDir(), "geo.mmdb")
	writeTestMMDB(t, p, "JP", time.Now())
	setGeoCfgForTest(t, geoSettings{DBPath: p, Mode: geoModeIPInfoDB})

	got := geoipCountryCounts(map[string]int{"203.0.113.5": 3, "203.0.113.6": 2})
	if got["日本"] != 5 || len(got) != 1 {
		t.Fatalf("国別集計 = %v, want map[日本:5]", got)
	}
}

func TestGeoipDBPathForCountryCounts(t *testing.T) {
	t.Setenv("HEARTDESK_GEOIP_DB", "/env/geo.mmdb")

	setGeoCfgForTest(t, geoSettings{DBPath: "/cfg/geo.mmdb"})
	if got := geoipDBPathForCountryCounts(); got != "/cfg/geo.mmdb" {
		t.Errorf("設定と env の両方があるとき = %q, want 設定（geo.go と同じ）", got)
	}
	setGeoCfgForTest(t, geoSettings{})
	if got := geoipDBPathForCountryCounts(); got != "/env/geo.mmdb" {
		t.Errorf("設定が無く env だけのとき = %q, want env（従来の挙動）", got)
	}
	t.Setenv("HEARTDESK_GEOIP_DB", "")
	if got := geoipDBPathForCountryCounts(); got != "" {
		t.Errorf("どちらも無いとき = %q, want 空", got)
	}
}
