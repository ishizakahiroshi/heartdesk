package auth

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/audit"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
)

// ncSessionTimeout は Nextcloud OCS API への問い合わせのタイムアウト。
// 応答が無くても数秒で打ち切ってログイン画面へ戻す。
const ncSessionTimeout = 5 * time.Second

// ncSessionEntryPath は「Nextcloud のログインで入る」の入口。nginx がこの 1 本だけを
// heartdesk の <LoginPath>/nc へ渡す（デプロイ側の nginx テンプレート nc_sso.conf.tmpl）。
// Nextcloud は Cookie の Path を自分の置き場所（/nextcloud）に固定して発行する
// （lib/base.php。変える設定は無い）ので、/login の下ではブラウザが Nextcloud の Cookie を送らない。
const ncSessionEntryPath = "/nextcloud/heartdesk-login"

// ncNotRegisteredError は Nextcloud には入れているが heartdesk に登録の無い人へ出す文言。
// 本人が Nextcloud にログイン済みで、分かるのは本人自身の登録状況だけなので、
// パスワード入力の共通文言（ユーザー列挙対策）に揃える必要はない。
// 入力していない人に「入力内容を確認してください」と出すと、壊れているように見える。
const ncNotRegisteredError = "この Nextcloud アカウントは heartdesk に登録されていません。heartdesk の ID とパスワードをお持ちの場合は、そちらで入ってください。"

// ncSessionBaseURL は自ホストの Nextcloud ベース URL を tenants.toml から導く。
// 転送先は設定値（tenants.toml）で固定し、リクエスト由来の値は使わない（SSRF 対策）。
func ncSessionBaseURL() string {
	tenantID := strings.TrimSpace(heartdesk.Env("HEARTDESK_TENANT_ID"))
	if tenantID == "" {
		return ""
	}
	return ncBaseURLForTenant(routing.GetTenantByID(tenantID))
}

// ncBaseURLForTenant はテナントの公開ホストから Nextcloud ベース URL を組み立てる。
// base_host だけを使うと、サブドメイン方式のテナントでは別ホスト（会社のサイト）へ
// 問い合わせて 404 になる。
func ncBaseURLForTenant(tc *routing.TenantConfig) string {
	if tc == nil {
		return ""
	}
	host := tc.PublicHost()
	if host == "" {
		return ""
	}
	return "https://" + host + "/nextcloud"
}

// ocsSucceeded は OCS の meta.statuscode が成功かを返す。
// 成功は v1 が 100、v2 が 200（v1 だけが 200 を 100 に読み替える。Nextcloud の
// lib/private/AppFramework/OCS/V1Response.php）。問い合わせ先は v2 なので実際は 200 が返る。
// 100 だけを成功とすると、ログイン済みでも未ログインと扱われてしまう。
func ocsSucceeded(code int) bool {
	return code == 200 || code == 100
}

type ocsUserResponse struct {
	OCS struct {
		Meta struct {
			StatusCode int `json:"statuscode"`
		} `json:"meta"`
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	} `json:"ocs"`
}

// LoginNC は Nextcloud のログイン状態を使ったログインを処理する。
// 受け取った Cookie をそのまま Nextcloud の OCS API へ転送し、返ってきた uid を
// heartdesk の登録ユーザーと突き合わせる。未登録・無効ユーザーは拒否し、自動作成しない。
func (h *HTTPHandler) LoginNC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	h.loginNCWithBase(w, r, ncSessionBaseURL())
}

// loginNCWithBase は LoginNC の本体。Nextcloud ベース URL を引数で受け取ることで、
// テストから httptest.Server を注入できるようにしている。
func (h *HTTPHandler) loginNCWithBase(w http.ResponseWriter, r *http.Request, base string) {
	next := h.routes.SanitizeNext(r.URL.Query().Get("next"))
	ip := ClientIP(r)

	if base == "" {
		log.Printf("auth: nc_session base url not configured")
		audit.LogRequest(r, "LOGIN_FAILED", "", "", "fail", "nc_session_not_configured", nil)
		h.renderLogin(w, r, genericLoginError, "")
		return
	}

	cookieHeader := r.Header.Get("Cookie")
	if strings.TrimSpace(cookieHeader) == "" {
		h.renderLogin(w, r, "", "Nextcloud にログインしてから、もう一度お試しください。")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), ncSessionTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/ocs/v2.php/cloud/user?format=json", nil)
	if err != nil {
		log.Printf("auth: nc_session request build failed: %v", err)
		audit.LogRequest(r, "LOGIN_FAILED", "", "", "fail", "nc_session_request_error", nil)
		h.renderLogin(w, r, genericLoginError, "")
		return
	}
	req.Header.Set("OCS-APIRequest", "true")
	// 受け取った Cookie をそのまま転送するだけで、保存・ログ出力はしない。
	req.Header.Set("Cookie", cookieHeader)

	client := &http.Client{Timeout: ncSessionTimeout}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("auth: nc_session upstream error ip=%s: %v", ip, err)
		audit.LogRequest(r, "LOGIN_FAILED", "", "", "fail", "nc_session_upstream_error", nil)
		h.renderLogin(w, r, "Nextcloud への確認に失敗しました。時間をおいて再度お試しください。", "")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		log.Printf("auth: nc_session not logged in to nextcloud (401) ip=%s", ip)
		h.renderLogin(w, r, "", "Nextcloud にログインしてから、もう一度お試しください。")
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("auth: nc_session unexpected status=%d ip=%s", resp.StatusCode, ip)
		audit.LogRequest(r, "LOGIN_FAILED", "", "", "fail", "nc_session_unexpected_status", nil)
		h.renderLogin(w, r, genericLoginError, "")
		return
	}

	var body ocsUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		log.Printf("auth: nc_session decode error ip=%s: %v", ip, err)
		audit.LogRequest(r, "LOGIN_FAILED", "", "", "fail", "nc_session_decode_error", nil)
		h.renderLogin(w, r, genericLoginError, "")
		return
	}
	uid := strings.TrimSpace(body.OCS.Data.ID)
	if !ocsSucceeded(body.OCS.Meta.StatusCode) || uid == "" {
		log.Printf("auth: nc_session ocs not ok statuscode=%d uid_len=%d ip=%s", body.OCS.Meta.StatusCode, len([]rune(uid)), ip)
		h.renderLogin(w, r, "", "Nextcloud にログインしてから、もう一度お試しください。")
		return
	}

	user, ok := DefaultStore().GetUser(uid)
	if !ok || user.Disabled {
		log.Printf("auth: nc_session login rejected (unregistered/disabled) uid_len=%d ip=%s", len([]rune(uid)), ip)
		AppendLoginLog(LoginLogEntry{Result: "fail", User: uid, IP: ip, UA: r.UserAgent(), Reason: "nc_session_not_registered"})
		audit.LogRequest(r, "LOGIN_FAILED", uid, "", "fail", "nc_session_not_registered", nil)
		msg := genericLoginError
		if !ok {
			msg = ncNotRegisteredError
		}
		h.renderLogin(w, r, msg, "")
		return
	}

	if len(user.AccessScreens) == 0 {
		log.Printf("auth: login blocked (no access screens) user=%s ip=%s (nc_session)", user.Username, ip)
		AppendLoginLog(LoginLogEntry{Result: "fail", User: user.Username, IP: ip, UA: r.UserAgent(), Reason: "no_access_screens"})
		audit.LogRequest(r, "LOGIN_FAILED", user.Username, user.Role, "fail", "no_access_screens", nil)
		h.renderLogin(w, r, noAccessScreensError, "")
		return
	}

	if err := h.completeLogin(w, r, user, next); err != nil {
		log.Printf("auth: nc_session complete login failed: %v", err)
		audit.LogRequest(r, "LOGIN_FAILED", user.Username, user.Role, "fail", "session_create_failed", nil)
		h.renderLogin(w, r, "ログイン処理に失敗しました。", "")
		return
	}
	log.Printf("auth: login success user=%s ip=%s (nc_session)", user.Username, ip)
	AppendLoginLog(LoginLogEntry{Result: "success", User: user.Username, IP: ip, UA: r.UserAgent()})
	audit.LogRequest(r, "LOGIN", user.Username, user.Role, "success", "nc_session_login_success", nil)
}
