package heartdesk

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	dbMu sync.RWMutex
	db   *sql.DB
)

// InitDB はアプリケーション共有 DB 接続を初期化する。
// DSN 形式は SQLite ファイルパス（modernc.org/sqlite ドライバ使用）。
func InitDB(dsn string) error {
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("InitDB: open: %w", err)
	}
	if err := conn.Ping(); err != nil {
		conn.Close()
		return fmt.Errorf("InitDB: ping: %w", err)
	}
	dbMu.Lock()
	db = conn
	dbMu.Unlock()
	return nil
}

// DB は初期化済みの共有 DB 接続を返す。InitDB 未呼び出し時は nil。
func DB() *sql.DB {
	dbMu.RLock()
	defer dbMu.RUnlock()
	return db
}

const VendorName = "heartdesk"

// Env は HEARTDESK_* 環境変数の値を返す（未設定なら空文字）。
func Env(key string) string {
	return os.Getenv(key)
}

// BaseDir は HEARTDESK_BASE_DIR 環境変数を返す。未設定時は起動を中止する（サイレント誤動作防止）。
func BaseDir() string {
	v := Env("HEARTDESK_BASE_DIR")
	if v == "" {
		log.Fatal("HEARTDESK_BASE_DIR is not set. Set it via systemd Environment= (e.g. Environment=\"HEARTDESK_BASE_DIR=/var/lib/heartdesk\")")
	}
	return v
}

// Path は HEARTDESK_BASE_DIR を起点とした絶対パスを返す
func Path(rel string) string {
	return filepath.Join(BaseDir(), rel)
}

var weekdays = []string{"日", "月", "火", "水", "木", "金", "土"}

// JST は日本標準時のロケーションを返す
func JST() *time.Location {
	if loc, err := time.LoadLocation("Asia/Tokyo"); err == nil {
		return loc
	}
	return time.FixedZone("JST", 9*60*60)
}

// FormatDatetime は time を "2006-01-02(曜) 15:04:05" 形式に整形する
func FormatDatetime(t time.Time) string {
	return fmt.Sprintf("%s(%s) %s",
		t.Format("2006-01-02"),
		weekdays[t.Weekday()],
		t.Format("15:04:05"),
	)
}

// ParseTimestamp は様々な形式のタイムスタンプ文字列を time.Time に変換する。
// 対応形式: RFC3339（+00:00 等のタイムゾーン付き）/ "2006-01-02T15:04:05"（tz無し JST扱い）/ "2006-01-02 15:04:05"（JST扱い）
// パース失敗時は zero time と error を返す
func ParseTimestamp(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	// RFC3339: タイムゾーン情報付き（例: 2026-04-10T23:55:15+00:00）
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	jst := JST()
	// タイムゾーン無し: ログ内部形式（JST扱い）
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(layout, s, jst); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable timestamp: %s", s)
}

// FormatRawDatetime は各種形式のタイムスタンプ文字列を "2006-01-02(曜) 15:04:05" に変換する。
// パース失敗時は元の文字列をそのまま返す
func FormatRawDatetime(s string) string {
	if t, err := ParseTimestamp(s); err == nil {
		return FormatDatetime(t.In(JST()))
	}
	return strings.TrimSpace(s)
}

// Run は bash -c でスクリプトを実行し、トリムした stdout を返す。エラー時は空文字。
//
// 重要（C7: run-bash-c-residual）: 本関数は `bash -c <script>` でシェル経由実行する。
// script は **リテラル固定文字列専用**であり、HTTP リクエスト由来などの動的入力を
// 連結・埋め込みしてはならない（シェルインジェクションの温床になる）。config 値（TOML）の
// 埋め込みは現状許容しているが、ユーザー入力が混ざりうる箇所は必ず RunArgs /
// RunArgsCombined（引数渡し・シェル非経由）を使うこと。2026-05-30 時点で全 Run 呼び出しを
// 棚卸し済み（cron_status / database / honeypot / kernel / notification_rules / realtime /
// resources / services / updates）。いずれも固定値 / config 値のみで、HTTP リクエスト入力の
// 直挿入は無い（database.go の backupDir, honeypot.go の jail, services.go の unit 等はすべて
// config / サーバー内部値）。
func Run(script string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "bash", "-c", script).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// RunArgs は cmd と args を exec.Command で直接実行し、stdout を返す。
// シェルを経由しないため注入リスクがなく、IP等の動的引数を安全に渡せる。
func RunArgs(timeout time.Duration, cmd string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, cmd, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// RunArgsCombined は cmd と args を exec.Command で直接実行し、
// stdout+stderr の結合出力とエラーを返す。
// 書き込み系コマンド（ssh_ip_manage.sh add/remove等）で終了コードを確認する際に使用する。
func RunArgsCombined(timeout time.Duration, cmd string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, cmd, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
