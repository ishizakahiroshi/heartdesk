// Package user は /module/nextcloud/user/ の HTTP ハンドラを提供する。
// C10 で本格実装する。C2 はスケルトンのみ。
package user

import (
	"fmt"
	"html"
	"net/http"

	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
)

// Handler は User の HTTP ハンドラをまとめる
type Handler struct{}

// NewHandler は User ハンドラを生成する
func NewHandler() *Handler {
	return &Handler{}
}

// ServeHTTP は /module/nextcloud/user/ 配下のリクエストをディスパッチする (http.Handler 実装)
//
// C9-C3: 旧実装は middleware.GetUser（認証セッションの Username）を html/template を介さず
// 素の Fprintf で text/html へ %s 埋め込みしており、ユーザー名に <script> 等が含まれると
// 反射型 XSS が成立した。html.EscapeString で必ずエスケープしてから埋め込むことで止血する
// （main.go が import するのは module/nextcloud/user 側だが、内容同一の重複ファイルとして
// 挙動差を残さないため本ファイルも同等に修正）。
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	middleware.SetHTMLSecurityHeaders(w)
	fmt.Fprintf(w, `<!DOCTYPE html><html lang="ja"><head><meta charset="UTF-8">
<title>NC User</title></head><body>
<h1>NC User — 準備中</h1>
<p>ユーザー: %s</p>
<p>C10 フェーズで実装予定</p>
</body></html>`, html.EscapeString(user))
}
