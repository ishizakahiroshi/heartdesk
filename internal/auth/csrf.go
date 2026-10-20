package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strings"
)

const csrfCookieName = "sab_csrf"

var errInvalidCSRF = errors.New("invalid csrf token")

// EnsureCSRFCookie は CSRF Cookie を確保し、現在値を返す。
//
// C4（csrf-token-not-bound-to-session）: ログイン済み（セッションあり）の場合は
// セッションに束縛されたトークンを正本とし、Cookie 値がそれと異なれば束縛トークンへ
// 揃え直す。これにより別セッションのトークン使い回しを断つ。
// 未ログイン（ログイン画面等）はセッションが無いため、従来どおりランダムトークンを
// 発行する純粋ダブルサブミットとして動く（ログイン成功時に completeLogin が
// ForceReissueCSRFCookie でセッション束縛トークンへ差し替える）。
func EnsureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	// セッションがあれば束縛トークンを正本にする。
	if bound, ok := DefaultSessionManager().CSRFTokenForRequest(r); ok {
		if c, err := r.Cookie(csrfCookieName); err == nil && c.Value == bound {
			return bound
		}
		setCSRFCookie(w, r, bound)
		return bound
	}

	// 未ログイン: 既存 Cookie があれば再利用、無ければ新規発行。
	if c, err := r.Cookie(csrfCookieName); err == nil && strings.TrimSpace(c.Value) != "" {
		return c.Value
	}
	token, err := newCSRFToken()
	if err != nil {
		// fail-safe: 乱数取得失敗時は固定値を返さず、トークンも Cookie も発行しない。
		// 空トークンは VerifyCSRF で必ず拒否されるため、CSRF 保護の迂回は成立しない。
		log.Printf("auth: CSRF token generation failed (crypto/rand): %v", err)
		return ""
	}
	setCSRFCookie(w, r, token)
	return token
}

// ForceReissueCSRFCookie はセッション束縛トークンを Cookie へ強制再発行する。
// C4（session-fixation-no-regenerate）: completeLogin がセッション ID 更新後に呼び、
// ログイン前の使い回しトークンを必ず無効化する。
func ForceReissueCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if bound, ok := DefaultSessionManager().CSRFTokenForRequest(r); ok {
		setCSRFCookie(w, r, bound)
		return bound
	}
	// セッションがまだ確立していない場合のフォールバック（通常は到達しない）。
	return EnsureCSRFCookie(w, r)
}

// ClearCSRFCookie は CSRF Cookie を削除する（ログアウト時）。
func ClearCSRFCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func setCSRFCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false, // ダブルサブミット法でフロントから hidden/header へ載せる
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(DefaultSessionManager().TTL().Seconds()),
	})
}

// VerifyCSRF はダブルサブミット + セッション束縛で CSRF トークンを検証する。
//
// C4（csrf-token-not-bound-to-session）: Cookie 値とリクエスト値（ヘッダ/フォーム）の
// 一致に加え、セッションがある場合は Cookie 値がそのセッションに束縛されたトークンと
// 一致することも要求する。これにより別セッションで発行されたトークンを拒否する。
func VerifyCSRF(r *http.Request) error {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return errInvalidCSRF
	}
	reqToken := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	if reqToken == "" {
		_ = r.ParseForm()
		reqToken = strings.TrimSpace(r.FormValue("csrf_token"))
	}
	if reqToken == "" || subtle.ConstantTimeCompare([]byte(reqToken), []byte(cookie.Value)) != 1 {
		return errInvalidCSRF
	}
	// セッション束縛: ログイン済みなら Cookie 値が束縛トークンと一致しなければならない。
	if bound, ok := DefaultSessionManager().CSRFTokenForRequest(r); ok {
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(bound)) != 1 {
			return errInvalidCSRF
		}
	}
	return nil
}

func newCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
