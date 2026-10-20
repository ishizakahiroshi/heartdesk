// Package middleware provides HTTP middleware for heartdesk.
package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
)

type contextKey string

const (
	ScreenKey contextKey = "heartdesk_screen"
	UserKey   contextKey = "heartdesk_user"
	IPKey     contextKey = "heartdesk_ip"
	RoleKey   contextKey = "heartdesk_role"
)

// RequireScreen はセッションを検証し、指定画面へのアクセス権を制御する。
func RequireScreen(screen auth.Screen) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionMgr := auth.DefaultSessionManager()
			sess, ok := sessionMgr.SessionFromRequest(r)
			if !ok {
				handleUnauthorized(w, r)
				return
			}
			if !auth.ScreenAllowed(sess.AccessScreens, screen) {
				http.Error(w, "403 Forbidden: アクセス権限がありません", http.StatusForbidden)
				return
			}

			// C-007: 未知 method は CSRF 検証以前に 405 で reject。
			// 既知の安全 method（GET/HEAD/OPTIONS）と既知の state-changing method
			// （POST/PUT/PATCH/DELETE）のみ通過させ、それ以外（TRACE/CONNECT/独自動詞）は
			// middleware 層で早期に弾く。
			if !isSafeMethod(r.Method) && !isStateChangingMethod(r.Method) {
				w.Header().Set("Allow", "GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE")
				http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}

			// ダブルサブミット法の CSRF トークンを保持（GET で初回発行）
			auth.EnsureCSRFCookie(w, r)
			// C-007: POST のみではなく、すべての state-changing method（POST/PUT/PATCH/DELETE）で
			// CSRF を検証する。middleware が CSRF enforcement の single source of truth であるため、
			// 将来 PUT/DELETE 系エンドポイントが追加されても silent bypass しないよう
			// safe method 以外を一律検証対象にする。
			if !isSafeMethod(r.Method) {
				if err := auth.VerifyCSRF(r); err != nil {
					http.Error(w, "403 Forbidden: CSRF token mismatch", http.StatusForbidden)
					return
				}
			}

			ctx := buildContext(r.Context(), screen, sess.Role, sess.Username, auth.ClientIP(r))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func handleUnauthorized(w http.ResponseWriter, r *http.Request) {
	cfg := routing.Current()
	isAPI := cfg.IsAPIPath(r.URL.Path) ||
		r.Header.Get("X-Requested-With") == "XMLHttpRequest"
	if isAPI {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":      false,
			"message": "認証が必要です",
		})
		return
	}
	next := url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, cfg.LoginPath+"?next="+next, http.StatusFound)
}

func buildContext(ctx context.Context, screen auth.Screen, role, user, ip string) context.Context {
	ctx = context.WithValue(ctx, ScreenKey, screen)
	ctx = context.WithValue(ctx, RoleKey, role)
	ctx = context.WithValue(ctx, UserKey, user)
	ctx = context.WithValue(ctx, IPKey, ip)
	return ctx
}

// GetScreen はコンテキストから現在の画面IDを取得する。
func GetScreen(ctx context.Context) auth.Screen {
	if v, ok := ctx.Value(ScreenKey).(auth.Screen); ok {
		return v
	}
	return ""
}

// GetRole はコンテキストからロールを取得する。
func GetRole(ctx context.Context) string {
	if v, ok := ctx.Value(RoleKey).(string); ok {
		return v
	}
	return ""
}

// GetUser はコンテキストからログインユーザーを取得する。
func GetUser(ctx context.Context) string {
	if v, ok := ctx.Value(UserKey).(string); ok {
		return v
	}
	return ""
}

// GetIP はコンテキストからクライアントIPを取得する。
func GetIP(ctx context.Context) string {
	if v, ok := ctx.Value(IPKey).(string); ok {
		return v
	}
	return ""
}

// InvalidateCache は後方互換のダミー実装（旧IPキャッシュ機能の呼び出し互換）。
func InvalidateCache() {}

// isSafeMethod は CSRF 検証不要な「副作用なし」HTTP method を判定する（RFC 9110 §9.2.1）。
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// isStateChangingMethod は CSRF 検証対象の state-changing HTTP method を判定する。
// 既知の動詞のみを許可し、未知 method は呼び出し側で 405 reject する（C-007）。
func isStateChangingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}
