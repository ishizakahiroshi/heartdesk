package middleware

import (
	"net/http"
	"strings"
)

// NoCacheHTML は HTML レスポンスをブラウザにキャッシュさせないためのヘッダーを付与する。
//
// Monitor / Vendor / Auth ハンドラ chain の最も内側に挟む想定。
// `/static/` には適用しないこと（長期キャッシュ対象）。
//
// `skipPrefixes` に該当するパスは無視する（例: `/monitor/avatar/<user>` のように
// ハンドラ側で独自の Cache-Control を返したいエンドポイント向け）。
//
// 設定ヘッダー：
//
//	Cache-Control: no-cache, no-store, must-revalidate, max-age=0
//	Pragma: no-cache
//	Expires: 0
func NoCacheHTML(skipPrefixes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !shouldSkipNoCache(r.URL.Path, skipPrefixes) {
				h := w.Header()
				h.Set("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")
				h.Set("Pragma", "no-cache")
				h.Set("Expires", "0")
			}
			next.ServeHTTP(w, r)
		})
	}
}

func shouldSkipNoCache(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if p == "" {
			continue
		}
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
