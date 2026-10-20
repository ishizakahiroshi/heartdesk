// Package nclog は Nextcloud のログ行（nextcloud.log / audit.log）から
// 意味を取り出す純粋関数を置く。
//
// ここに置くのは「文字列と時刻の解釈」だけで、ログの読み方（全件読みか
// オフセット差分読みか）や、読んだ結果をどう通知するかは持たない。
//
// 分けている理由は依存の向き。カード表示は core/monitor、アラートの発火は
// internal/alerts にあり、両方が同じ判定を必要とする。core/monitor は
// internal を import する側なので、判定を core/monitor に置くと
// internal/alerts からは import できない（層が逆流する）。
// かといって両方に書くと、Nextcloud 側のメッセージ書式が変わったときに
// 片方だけ直す事故が起きる。よって下位の共有パッケージへ 1 本化する。
package nclog

import (
	"regexp"
	"strings"
	"time"
)

// パターンは定数なので package レベルで 1 回だけコンパイルする
// （行ごとに呼ばれるため、呼び出しごとのコンパイルを避ける）。
var (
	reLoginUser = []*regexp.Regexp{
		regexp.MustCompile(`Login (?:successful|succeeded|failed|failure): "([^"]+)"`),
		regexp.MustCompile(`Login (?:successful|succeeded|failed|failure): '([^']+)'`),
		regexp.MustCompile(`Successful login: "([^"]+)"`),
		regexp.MustCompile(`Successful login: '([^']+)'`),
		regexp.MustCompile(`Failed login: "([^"]+)"`),
		regexp.MustCompile(`Failed login: '([^']+)'`),
	}
	reUserCreated = []*regexp.Regexp{
		regexp.MustCompile(`User created: "([^"]+)"`),
		regexp.MustCompile(`User created: '([^']+)'`),
	}
)

// ExtractLoginResult はメッセージから login result ("success" / "fail" / "") を返す。
func ExtractLoginResult(msg string) string {
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "login successful") ||
		strings.Contains(lower, "login succeeded") ||
		strings.Contains(lower, "successful login") {
		return "success"
	}
	if strings.Contains(lower, "login failed") ||
		strings.Contains(lower, "login failure") ||
		strings.Contains(lower, "failed login") {
		return "fail"
	}
	return ""
}

// ExtractLoginUserFromMessage はログインのメッセージからユーザー名を抽出する。
// 取れなければ空文字を返す。
func ExtractLoginUserFromMessage(msg string) string {
	return firstSubmatch(reLoginUser, msg)
}

// ExtractUserCreated は audit.log のメッセージから新規作成された uid を返す。
// 出力元は admin_audit の UserManagementEventListener（`User created: "<uid>"`）。
// マッチしなければ空文字を返す。
func ExtractUserCreated(msg string) string {
	return firstSubmatch(reUserCreated, msg)
}

func firstSubmatch(res []*regexp.Regexp, msg string) string {
	for _, re := range res {
		if m := re.FindStringSubmatch(msg); m != nil {
			return strings.TrimSpace(m[1])
		}
	}
	return ""
}

// ParseTime は Nextcloud の time 文字列を time.Time に変換する。
// 解釈できなければ ok=false を返す（呼び出し側は時刻比較を諦める）。
func ParseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	formats := []string{
		"2006-01-02T15:04:05.999999999-07:00",
		"2006-01-02T15:04:05.999999999Z07:00",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
