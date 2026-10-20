package auth

import (
	"encoding/csv"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/audit"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/httpsec"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
)

// pwStats は失敗ログ用にパスワードの統計的特徴を返す（平文は含まない）。
func pwStats(pw string) string {
	if pw == "" {
		return "empty"
	}
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	var kinds []string
	if hasLower {
		kinds = append(kinds, "lower")
	}
	if hasUpper {
		kinds = append(kinds, "upper")
	}
	if hasDigit {
		kinds = append(kinds, "digit")
	}
	if hasSymbol {
		kinds = append(kinds, "symbol")
	}
	return fmt.Sprintf("len=%d kinds=%s", len([]rune(pw)), strings.Join(kinds, "+"))
}

const genericLoginError = "ログインに失敗しました。入力内容を確認してください。"
const noAccessScreensError = "利用可能なアプリがありません。管理者にお問い合わせください。"

// LoginPageData は login.html に渡す表示データ。
type LoginPageData struct {
	Next          string
	CSRFToken     string
	Error         string
	Info          string
	StaticBase    string
	AssetVersion  string // 静的アセットのキャッシュバスティング用ビルドID（C2/C3）
	IconPath      string
	LoginPath     string
	NCSessionPath string
	Stage         string
	Username      string
	ChallengeID   string
	SystemInfo    config.SystemInfoData
}

type PasswordPageData struct {
	CSRFToken            string
	StaticBase           string
	AssetVersion         string // 静的アセットのキャッシュバスティング用ビルドID（C2/C3）
	Path                 string
	CurrentUser          string
	Message              string
	Error                string
	BackURL              string
	Settings2FAPath      string
	SettingsPasswordPath string
}

type TwoFASettingsPageData struct {
	CSRFToken            string
	StaticBase           string
	AssetVersion         string // 静的アセットのキャッシュバスティング用ビルドID（C2/C3）
	Path                 string
	CurrentUser          string
	Enabled              bool
	Secret               string
	ProvisioningURI      string
	Message              string
	Error                string
	BackURL              string
	Settings2FAPath      string
	SettingsPasswordPath string
}

type AuditLogPageData struct {
	StaticBase           string
	AssetVersion         string // 静的アセットのキャッシュバスティング用ビルドID（C2/C3）
	CurrentUser          string
	BackURL              string
	Settings2FAPath      string
	SettingsPasswordPath string
	AdminAuditLogPath    string
	Rows                 []audit.Event
	FilterUser           string
	FilterEvent          string
	FilterResult         string
	FilterQuery          string
	FilterFrom           string
	FilterTo             string
	FilterLimit          int
	Error                string
}

// HTTPHandler はログイン/ログアウトを提供する。
type HTTPHandler struct {
	tmpl       *template.Template
	routes     routing.Config
	appCards   config.CardsConfig
	systemInfo config.SystemInfoData
}

// NewHTTPHandler は認証ハンドラを生成する。
func NewHTTPHandler(tmpl *template.Template, routes routing.Config, appCards config.CardsConfig, systemInfo config.SystemInfoData) *HTTPHandler {
	return &HTTPHandler{tmpl: tmpl, routes: routes, appCards: appCards, systemInfo: systemInfo}
}

// Login は GET/POST ログインを処理する。
func (h *HTTPHandler) Login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.renderLogin(w, r, "", "")
	case http.MethodPost:
		h.loginPost(w, r)
	default:
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// Logout は POST ログアウトを処理する。
func (h *HTTPHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := VerifyCSRF(r); err != nil {
		http.Error(w, "403 Forbidden: CSRF token mismatch", http.StatusForbidden)
		return
	}
	sessionMgr := DefaultSessionManager()
	if c, err := r.Cookie(defaultSessionCookieName); err == nil && c.Value != "" {
		if sess, ok := sessionMgr.Get(c.Value); ok {
			log.Printf("auth: logout user=%s ip=%s", sess.Username, ClientIP(r))
			audit.LogRequest(r, "LOGOUT", sess.Username, sess.Role, "success", "logout", nil)
		}
		sessionMgr.Delete(c.Value)
	}
	sessionMgr.ClearCookie(w, r)
	clearChallengeCookie(w, r)
	// C4（session-fixation-no-regenerate）: ログアウト時は heartdesk_csrf を再発行せず明示クリアし、
	// セッション束縛トークンを残さない。次のログイン画面表示で新規発行される。
	ClearCSRFCookie(w, r)
	http.Redirect(w, r, h.routes.LoginPath, http.StatusFound)
}

func (h *HTTPHandler) loginPost(w http.ResponseWriter, r *http.Request) {
	if err := VerifyCSRF(r); err != nil {
		h.renderLogin(w, r, "セッションが無効です。再度ログインしてください。", "")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderLogin(w, r, "入力の解析に失敗しました。", "")
		return
	}
	stage := strings.TrimSpace(r.FormValue("stage"))
	if stage == "totp" {
		h.loginPostTOTP(w, r)
		return
	}
	h.loginPostCredential(w, r)
}

func (h *HTTPHandler) loginPostCredential(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(strings.ToLower(r.FormValue("username")))
	password := r.FormValue("password")
	next := h.routes.SanitizeNext(r.FormValue("next"))
	now := time.Now()
	lockout := DefaultLockoutManager()
	ip := ClientIP(r)
	if lockout.IsLocked(username, ip, now) {
		log.Printf("auth: login blocked (lockout) user=%s ip=%s", username, ip)
		AppendLoginLog(LoginLogEntry{Result: "fail", User: username, IP: ip, UA: r.UserAgent(), Reason: "lockout"})
		audit.LogRequest(r, "LOGIN_FAILED", username, "", "fail", "lockout", nil)
		h.renderLogin(w, r, genericLoginError, "")
		return
	}

	user, err := DefaultStore().Authenticate(username, password)
	if err != nil {
		lockout.RegisterFailure(username, ip, now)
		log.Printf("auth: login failed user=%s user_len=%d pw=%s ip=%s",
			username, len([]rune(username)), pwStats(password), ip)
		AppendLoginLog(LoginLogEntry{Result: "fail", User: username, IP: ip, UA: r.UserAgent(), PwStats: pwStats(password), Reason: "bad_credential"})
		audit.LogRequest(r, "LOGIN_FAILED", username, "", "fail", "bad_credential", nil)
		h.renderLogin(w, r, genericLoginError, "")
		return
	}

	if DefaultTOTPManager().IsEnabled(user.Username) {
		challenge, err := DefaultLoginChallengeManager().Create(user, next, ClientIP(r), r.UserAgent())
		if err != nil {
			log.Printf("auth: challenge create failed: %v", err)
			audit.LogRequest(r, "LOGIN_FAILED", user.Username, user.Role, "fail", "challenge_create_failed", nil)
			h.renderLogin(w, r, "ログイン処理に失敗しました。", "")
			return
		}
		setChallengeCookie(w, r, challenge.ID)
		h.renderLoginWithChallenge(w, r, challenge, "", "認証アプリの6桁コードを入力してください。")
		return
	}

	// TOTP 無効ユーザーはここで access_screens チェック。
	// 明示的空配列/省略どちらも「全画面不可」扱い。ロックアウトは発生させない。
	if len(user.AccessScreens) == 0 {
		log.Printf("auth: login blocked (no access screens) user=%s ip=%s", user.Username, ip)
		AppendLoginLog(LoginLogEntry{Result: "fail", User: user.Username, IP: ip, UA: r.UserAgent(), Reason: "no_access_screens"})
		audit.LogRequest(r, "LOGIN_FAILED", user.Username, user.Role, "fail", "no_access_screens", nil)
		h.renderLogin(w, r, noAccessScreensError, "")
		return
	}

	if err := h.completeLogin(w, r, user, next); err != nil {
		log.Printf("auth: session create failed: %v", err)
		audit.LogRequest(r, "LOGIN_FAILED", user.Username, user.Role, "fail", "session_create_failed", nil)
		h.renderLogin(w, r, "ログイン処理に失敗しました。", "")
		return
	}
	lockout.RegisterSuccess(user.Username, ip)
	log.Printf("auth: login success user=%s ip=%s", user.Username, ip)
	AppendLoginLog(LoginLogEntry{Result: "success", User: user.Username, IP: ip, UA: r.UserAgent()})
	audit.LogRequest(r, "LOGIN", user.Username, user.Role, "success", "password_login_success", nil)
}

func (h *HTTPHandler) loginPostTOTP(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.FormValue("challenge_id"))
	if id == "" {
		if c, err := r.Cookie(loginChallengeCookie); err == nil {
			id = strings.TrimSpace(c.Value)
		}
	}
	challenge, ok := DefaultLoginChallengeManager().Get(id)
	if !ok {
		clearChallengeCookie(w, r)
		h.renderLogin(w, r, "2段階認証の有効期限が切れました。再度ログインしてください。", "")
		return
	}
	code := strings.TrimSpace(r.FormValue("totp_code"))
	now := time.Now()
	lockout := DefaultLockoutManager()
	ip := ClientIP(r)
	// セッション固定 / チャレンジ盗用対策: チャレンジ発行時の IP と一致しない端末からの
	// 消費を拒否する。UA 不一致は誤検知が多いため警告ログのみ（拒否しない）。
	if challenge.IP != "" && challenge.IP != ip {
		log.Printf("auth: totp challenge IP mismatch user=%s issued_ip=%s consume_ip=%s",
			challenge.User.Username, challenge.IP, ip)
		DefaultLoginChallengeManager().Delete(challenge.ID)
		clearChallengeCookie(w, r)
		audit.LogRequest(r, "LOGIN_FAILED", challenge.User.Username, challenge.User.Role, "fail", "challenge_ip_mismatch", nil)
		h.renderLogin(w, r, "2段階認証の有効期限が切れました。再度ログインしてください。", "")
		return
	}
	if ua := strings.TrimSpace(r.UserAgent()); challenge.UserAgent != "" && ua != "" && challenge.UserAgent != ua {
		log.Printf("auth: totp challenge UA mismatch user=%s (警告のみ)", challenge.User.Username)
	}
	if lockout.IsLocked(challenge.User.Username, ip, now) {
		DefaultLoginChallengeManager().Delete(challenge.ID)
		clearChallengeCookie(w, r)
		audit.LogRequest(r, "LOGIN_FAILED", challenge.User.Username, challenge.User.Role, "fail", "lockout", nil)
		h.renderLogin(w, r, genericLoginError, "")
		return
	}
	if !DefaultTOTPManager().Verify(challenge.User.Username, code, now) {
		locked, _ := lockout.RegisterFailure(challenge.User.Username, ip, now)
		log.Printf("auth: totp failed user=%s ip=%s code_len=%d locked=%v",
			challenge.User.Username, ip, len([]rune(code)), locked)
		AppendLoginLog(LoginLogEntry{Result: "fail", User: challenge.User.Username, IP: ip, UA: r.UserAgent(), Reason: "totp_fail"})
		audit.LogRequest(r, "LOGIN_FAILED", challenge.User.Username, challenge.User.Role, "fail", "totp_fail", nil)
		if locked {
			DefaultLoginChallengeManager().Delete(challenge.ID)
			clearChallengeCookie(w, r)
			h.renderLogin(w, r, genericLoginError, "")
			return
		}
		h.renderLoginWithChallenge(w, r, challenge, genericLoginError, "")
		return
	}

	// TOTP 成功後、最新のユーザー情報を再取得して無効化/権限変更を即時反映する。
	// challenge.User はパスワード検証時点（最大 challenge TTL 5分前）のスナップショットのため、
	// その間に管理者が disabled 化・access_screens 縮小・role 変更を行っても反映されない。
	// 資格情報経路（Authenticate）には存在する Disabled 拒否が TOTP 消費経路には無いのを揃える。
	freshUser, ok := DefaultStore().GetUser(challenge.User.Username)
	if !ok || freshUser.Disabled {
		log.Printf("auth: login blocked (user disabled/removed) user=%s ip=%s (totp)", challenge.User.Username, ip)
		AppendLoginLog(LoginLogEntry{Result: "fail", User: challenge.User.Username, IP: ip, UA: r.UserAgent(), Reason: "disabled"})
		audit.LogRequest(r, "LOGIN_FAILED", challenge.User.Username, challenge.User.Role, "fail", "disabled", nil)
		DefaultLoginChallengeManager().Delete(challenge.ID)
		clearChallengeCookie(w, r)
		h.renderLogin(w, r, genericLoginError, "")
		return
	}

	// TOTP 成功後に access_screens チェック。攻撃者には判別できないタイミングなので情報漏洩にならない。
	// 明示的空配列/省略どちらも「全画面不可」扱い。ロックアウトは発生させない。
	if len(freshUser.AccessScreens) == 0 {
		log.Printf("auth: login blocked (no access screens) user=%s ip=%s (totp)", challenge.User.Username, ip)
		AppendLoginLog(LoginLogEntry{Result: "fail", User: challenge.User.Username, IP: ip, UA: r.UserAgent(), Reason: "no_access_screens"})
		audit.LogRequest(r, "LOGIN_FAILED", challenge.User.Username, challenge.User.Role, "fail", "no_access_screens", nil)
		DefaultLoginChallengeManager().Delete(challenge.ID)
		clearChallengeCookie(w, r)
		h.renderLogin(w, r, noAccessScreensError, "")
		return
	}

	if err := h.completeLogin(w, r, freshUser, challenge.Next); err != nil {
		log.Printf("auth: complete login failed: %v", err)
		audit.LogRequest(r, "LOGIN_FAILED", challenge.User.Username, challenge.User.Role, "fail", "session_create_failed", nil)
		h.renderLoginWithChallenge(w, r, challenge, "ログイン処理に失敗しました。", "")
		return
	}
	lockout.RegisterSuccess(challenge.User.Username, ip)
	log.Printf("auth: login success user=%s ip=%s (totp)", challenge.User.Username, ip)
	AppendLoginLog(LoginLogEntry{Result: "success", User: challenge.User.Username, IP: ip, UA: r.UserAgent()})
	audit.LogRequest(r, "LOGIN", challenge.User.Username, challenge.User.Role, "success", "totp_login_success", nil)
	DefaultLoginChallengeManager().Delete(challenge.ID)
	clearChallengeCookie(w, r)
}

func (h *HTTPHandler) completeLogin(w http.ResponseWriter, r *http.Request, user User, next string) error {
	tenantID := ""
	if tc := routing.GetTenantByRequest(r); tc != nil {
		tenantID = tc.TenantID
	}

	sessionMgr := DefaultSessionManager()
	s, err := sessionMgr.Create(user, ClientIP(r), r.UserAgent(), h.appCards, tenantID)
	if err != nil {
		return err
	}
	sessionMgr.SetCookie(w, r, s.ID)
	// C4（session-fixation-no-regenerate）: 新セッションに束縛された CSRF トークンを
	// 明示的に再発行し、ログイン前の使い回しトークンを無効化する。新セッション Cookie は
	// まだ r から読めないため、束縛トークンを直接渡して Cookie へ書く。
	setCSRFCookie(w, r, s.CSRFToken)
	http.Redirect(w, r, next, http.StatusFound)
	return nil
}

func (h *HTTPHandler) renderLogin(w http.ResponseWriter, r *http.Request, errMsg, infoMsg string) {
	if _, ok := DefaultSessionManager().SessionFromRequest(r); ok {
		http.Redirect(w, r, h.routes.SanitizeNext(r.URL.Query().Get("next")), http.StatusFound)
		return
	}

	next := h.routes.SanitizeNext(r.URL.Query().Get("next"))
	if r.Method == http.MethodPost {
		next = h.routes.SanitizeNext(r.FormValue("next"))
	}
	token := EnsureCSRFCookie(w, r)
	stage := "password"
	challengeID := ""
	username := strings.TrimSpace(strings.ToLower(r.FormValue("username")))
	if c, err := r.Cookie(loginChallengeCookie); err == nil && strings.TrimSpace(c.Value) != "" {
		if challenge, ok := DefaultLoginChallengeManager().Get(c.Value); ok {
			stage = "totp"
			challengeID = challenge.ID
			username = challenge.User.Username
			if next == h.routes.MonitorHome() {
				next = challenge.Next
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	httpsec.SetHTMLSecurityHeaders(w)
	data := LoginPageData{
		Next:          next,
		CSRFToken:     token,
		Error:         errMsg,
		Info:          infoMsg,
		StaticBase:    h.routes.StaticBase,
		AssetVersion:  h.systemInfo.AssetVersion,
		IconPath:      h.routes.IconPath(),
		LoginPath:     h.routes.LoginPath,
		NCSessionPath: ncSessionEntryPath + "?next=" + url.QueryEscape(next),
		Stage:         stage,
		Username:      username,
		ChallengeID:   challengeID,
		SystemInfo:    h.systemInfo,
	}
	if err := h.tmpl.ExecuteTemplate(w, "login", data); err != nil {
		log.Printf("auth: login template error: %v", err)
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *HTTPHandler) renderLoginWithChallenge(w http.ResponseWriter, r *http.Request, challenge loginChallenge, errMsg, infoMsg string) {
	token := EnsureCSRFCookie(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	httpsec.SetHTMLSecurityHeaders(w)
	data := LoginPageData{
		Next:         challenge.Next,
		CSRFToken:    token,
		Error:        errMsg,
		Info:         infoMsg,
		StaticBase:   h.routes.StaticBase,
		AssetVersion: h.systemInfo.AssetVersion,
		IconPath:     h.routes.IconPath(),
		LoginPath:    h.routes.LoginPath,
		Stage:        "totp",
		Username:     challenge.User.Username,
		ChallengeID:  challenge.ID,
		SystemInfo:   h.systemInfo,
	}
	if err := h.tmpl.ExecuteTemplate(w, "login", data); err != nil {
		log.Printf("auth: login template error: %v", err)
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
	}
}

// SettingsPassword はログインユーザーのパスワード変更画面。
func (h *HTTPHandler) SettingsPassword(w http.ResponseWriter, r *http.Request) {
	sess, ok := DefaultSessionManager().SessionFromRequest(r)
	if !ok {
		http.Redirect(w, r, h.routes.LoginPath, http.StatusFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.renderPasswordPage(w, r, sess, "", "")
	case http.MethodPost:
		if err := VerifyCSRF(r); err != nil {
			h.renderPasswordPage(w, r, sess, "", "CSRFトークンが不正です。")
			return
		}
		if err := r.ParseForm(); err != nil {
			h.renderPasswordPage(w, r, sess, "", "入力の解析に失敗しました。")
			return
		}
		current := r.FormValue("current_password")
		next := r.FormValue("new_password")
		confirm := r.FormValue("confirm_password")
		if len(next) < 8 {
			h.renderPasswordPage(w, r, sess, "", "新しいパスワードは8文字以上で入力してください。")
			return
		}
		if next != confirm {
			h.renderPasswordPage(w, r, sess, "", "確認用パスワードが一致しません。")
			return
		}
		if _, err := DefaultStore().Authenticate(sess.Username, current); err != nil {
			h.renderPasswordPage(w, r, sess, "", "現在のパスワードが正しくありません。")
			return
		}
		if err := DefaultStore().UpdatePassword(sess.Username, next); err != nil {
			h.renderPasswordPage(w, r, sess, "", "パスワード更新に失敗しました。")
			return
		}
		// C-028（password-change-does-not-revoke-other-sessions）対応:
		// パスワード変更後、他端末・他ブラウザの既存セッションを強制無効化する。
		// 自端末（現セッション）は exceptID で残し、操作中ユーザーをログアウトさせない。
		DefaultSessionManager().DeleteByUsername(sess.Username, sess.ID)
		audit.LogRequest(r, "SETTINGS_CHANGE", sess.Username, sess.Role, "success", "password_changed", nil)
		h.renderPasswordPage(w, r, sess, "パスワードを更新しました。", "")
	default:
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPHandler) renderPasswordPage(w http.ResponseWriter, r *http.Request, sess Session, msg, errMsg string) {
	token := EnsureCSRFCookie(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	httpsec.SetHTMLSecurityHeaders(w)
	data := PasswordPageData{
		CSRFToken:            token,
		StaticBase:           h.routes.StaticBase,
		AssetVersion:         h.systemInfo.AssetVersion,
		Path:                 h.routes.SettingsPasswordPath,
		CurrentUser:          sess.Username,
		Message:              msg,
		Error:                errMsg,
		BackURL:              h.routes.MonitorHome(),
		Settings2FAPath:      h.routes.Settings2FAPath,
		SettingsPasswordPath: h.routes.SettingsPasswordPath,
	}
	if err := h.tmpl.ExecuteTemplate(w, "settings_password", data); err != nil {
		log.Printf("auth: settings_password template error: %v", err)
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
	}
}

// Settings2FA はログインユーザーの2FA設定画面。
func (h *HTTPHandler) Settings2FA(w http.ResponseWriter, r *http.Request) {
	sess, ok := DefaultSessionManager().SessionFromRequest(r)
	if !ok {
		http.Redirect(w, r, h.routes.LoginPath, http.StatusFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.render2FASettingsPage(w, r, sess, "", "")
	case http.MethodPost:
		if err := VerifyCSRF(r); err != nil {
			h.render2FASettingsPage(w, r, sess, "", "CSRFトークンが不正です。")
			return
		}
		if err := r.ParseForm(); err != nil {
			h.render2FASettingsPage(w, r, sess, "", "入力の解析に失敗しました。")
			return
		}
		action := strings.TrimSpace(r.FormValue("action"))
		mgr := DefaultTOTPManager()
		switch action {
		case "generate":
			secret, err := GenerateTOTPSecret()
			if err != nil {
				h.render2FASettingsPage(w, r, sess, "", "2FA秘密鍵の生成に失敗しました。")
				return
			}
			mgr.SetSecret(sess.Username, secret, false)
			audit.LogRequest(r, "SETTINGS_CHANGE", sess.Username, sess.Role, "success", "totp_secret_generated", nil)
			h.render2FASettingsPage(w, r, sess, "秘密鍵を生成しました。コード確認後に有効化してください。", "")
			return
		case "enable":
			secret, enabled, ok := mgr.Get(sess.Username)
			if !ok || secret == "" {
				h.render2FASettingsPage(w, r, sess, "", "先に秘密鍵を生成してください。")
				return
			}
			if enabled {
				h.render2FASettingsPage(w, r, sess, "2FAはすでに有効です。", "")
				return
			}
			code := strings.TrimSpace(r.FormValue("totp_code"))
			// C5（totp-enable-no-replay-counter）: 検証＋有効化を TOTPManager に一本化し、
			// 有効化に使った消費カウンタを LastCounter へ記録する（直後のログインで再利用不可）。
			if !mgr.EnableAfterVerify(sess.Username, code, time.Now()) {
				h.render2FASettingsPage(w, r, sess, "", "認証コードが正しくありません。")
				return
			}
			audit.LogRequest(r, "SETTINGS_CHANGE", sess.Username, sess.Role, "success", "totp_enabled", nil)
			h.render2FASettingsPage(w, r, sess, "2FAを有効化しました。", "")
			return
		case "disable":
			mgr.Disable(sess.Username)
			audit.LogRequest(r, "SETTINGS_CHANGE", sess.Username, sess.Role, "success", "totp_disabled", nil)
			h.render2FASettingsPage(w, r, sess, "2FAを無効化しました。", "")
			return
		default:
			h.render2FASettingsPage(w, r, sess, "", "不正な操作です。")
			return
		}
	default:
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPHandler) render2FASettingsPage(w http.ResponseWriter, r *http.Request, sess Session, msg, errMsg string) {
	token := EnsureCSRFCookie(w, r)
	secret, enabled, ok := DefaultTOTPManager().Get(sess.Username)
	if !ok {
		secret = ""
		enabled = false
	}
	provisioningURI := ""
	if secret != "" {
		provisioningURI = TOTPProvisioningURI("heartdesk", sess.Username, secret)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	httpsec.SetHTMLSecurityHeaders(w)
	data := TwoFASettingsPageData{
		CSRFToken:            token,
		StaticBase:           h.routes.StaticBase,
		AssetVersion:         h.systemInfo.AssetVersion,
		Path:                 h.routes.Settings2FAPath,
		CurrentUser:          sess.Username,
		Enabled:              enabled,
		Secret:               secret,
		ProvisioningURI:      provisioningURI,
		Message:              msg,
		Error:                errMsg,
		BackURL:              h.routes.MonitorHome(),
		Settings2FAPath:      h.routes.Settings2FAPath,
		SettingsPasswordPath: h.routes.SettingsPasswordPath,
	}
	if err := h.tmpl.ExecuteTemplate(w, "settings_2fa", data); err != nil {
		log.Printf("auth: settings_2fa template error: %v", err)
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
	}
}

// requireVendorStaffRole はセッションの role が vendor_staff であることを要求する。
// 権限不足なら 403 を書いて false を返す（呼び出し元は false で即 return すること）。
// auth は middleware を import できない（循環依存）ため、セッションの role で判定する。
func requireVendorStaffRole(w http.ResponseWriter, r *http.Request) bool {
	sess, ok := DefaultSessionManager().SessionFromRequest(r)
	if !ok || Role(NormalizeRole(sess.Role)) != RoleVendorStaff {
		http.Error(w, "403 Forbidden: vendor_staff 権限が必要です", http.StatusForbidden)
		return false
	}
	return true
}

// AdminUnlock はロック中ユーザーを手動解除する。
func (h *HTTPHandler) AdminUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireVendorStaffRole(w, r) {
		return
	}
	if err := VerifyCSRF(r); err != nil {
		http.Error(w, "403 Forbidden: CSRF token mismatch", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "400 Bad Request", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(strings.ToLower(r.FormValue("username")))
	if username == "" {
		http.Error(w, "400 Bad Request", http.StatusBadRequest)
		return
	}
	if sess, ok := DefaultSessionManager().SessionFromRequest(r); ok {
		audit.LogRequest(r, "SETTINGS_CHANGE", sess.Username, sess.Role, "success", "user_unlock", map[string]string{
			"target_user": username,
		})
	}
	DefaultLockoutManager().Unlock(username)
	http.Redirect(w, r, h.routes.AdminAuditLogPath, http.StatusFound)
}

// Settings2FAReset は管理者がユーザーの2FAを強制リセットする。
func (h *HTTPHandler) Settings2FAReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireVendorStaffRole(w, r) {
		return
	}
	if err := VerifyCSRF(r); err != nil {
		http.Error(w, "403 Forbidden: CSRF token mismatch", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "400 Bad Request", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(strings.ToLower(r.FormValue("username")))
	if username == "" {
		http.Error(w, "400 Bad Request", http.StatusBadRequest)
		return
	}
	if sess, ok := DefaultSessionManager().SessionFromRequest(r); ok {
		audit.LogRequest(r, "SETTINGS_CHANGE", sess.Username, sess.Role, "success", "user_2fa_reset", map[string]string{
			"target_user": username,
		})
	}
	DefaultTOTPManager().Reset(username)
	// C-005 / C-028: 管理者による TOTP リセットは「漏洩懸念で 2FA を打ち直す」
	// 典型シナリオなので、対象ユーザーの全セッションを強制無効化する。
	// 実行者自身を含めて全消し（exceptID="" ）。
	DefaultSessionManager().DeleteByUsername(username, "")
	http.Redirect(w, r, h.routes.AdminAuditLogPath, http.StatusFound)
}

// AdminAuditLog は監査ログの閲覧・フィルタ・エクスポート画面。
func (h *HTTPHandler) AdminAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, ok := DefaultSessionManager().SessionFromRequest(r)
	if !ok {
		http.Redirect(w, r, h.routes.LoginPath, http.StatusFound)
		return
	}
	// 監査ログの全件閲覧は vendor_staff のみ（monitor 画面権の tenant_admin による
	// 他テナント・全ユーザーの監査ログ閲覧＝情報漏洩を防ぐ）。
	if Role(NormalizeRole(sess.Role)) != RoleVendorStaff {
		http.Error(w, "403 Forbidden: vendor_staff 権限が必要です", http.StatusForbidden)
		return
	}

	q := r.URL.Query()
	limit := parseAuditLimit(q.Get("limit"))
	from := parseAuditTime(q.Get("from"))
	to := parseAuditTime(q.Get("to"))

	rows, err := audit.List(audit.Filter{
		User:   q.Get("user"),
		Event:  q.Get("event"),
		Result: q.Get("result"),
		Query:  q.Get("q"),
		From:   from,
		To:     to,
		Limit:  limit,
	})
	if err != nil {
		log.Printf("auth: audit log read error: %v", err)
	}

	if strings.EqualFold(strings.TrimSpace(q.Get("export")), "csv") {
		h.exportAuditCSV(w, rows)
		return
	}

	redirectQuery := r.URL.Query()
	redirectQuery.Del("export")
	redirectQuery.Set("view", "audit_log")
	http.Redirect(w, r, h.routes.MonitorBase+"/?"+redirectQuery.Encode(), http.StatusFound)
}

func (h *HTTPHandler) exportAuditCSV(w http.ResponseWriter, rows []audit.Event) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit_log.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "event", "user", "role", "ip", "method", "path", "query", "result", "message"})
	for _, rec := range rows {
		_ = cw.Write([]string{
			rec.Time,
			rec.Event,
			rec.User,
			rec.Role,
			rec.IP,
			rec.Method,
			rec.Path,
			rec.Query,
			rec.Result,
			rec.Message,
		})
	}
	cw.Flush()
}

func parseAuditLimit(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return 200
	}
	if n > 5000 {
		return 5000
	}
	return n
}

func parseAuditTime(raw string) *time.Time {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	t, err := heartdesk.ParseTimestamp(s)
	if err != nil {
		return nil
	}
	return &t
}

func roleLabel(role string) string {
	switch Role(role) {
	case RoleVendorStaff:
		return "ベンダー運用者"
	case RoleTenantAdmin:
		return "テナント管理者"
	case RoleTenantUser:
		return "テナント利用者"
	}
	return "-"
}

func setChallengeCookie(w http.ResponseWriter, r *http.Request, challengeID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     loginChallengeCookie,
		Value:    strings.TrimSpace(challengeID),
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   loginChallengeCookieAge,
	})
}

func clearChallengeCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     loginChallengeCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
