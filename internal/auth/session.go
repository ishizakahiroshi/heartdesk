package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/authz"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
)

const (
	// セッション cookie 名（AuthZ スキーマ v2）
	defaultSessionCookieName = "heartdesk_session_v2"
	defaultSessionTTL        = 8 * time.Hour
)

// Session はログインセッション情報。
type Session struct {
	ID                string
	UserID            string
	Username          string
	Name              string
	Role              string   // vendor_staff / tenant_admin / tenant_user
	AccessScreens     []string // 許可画面IDリスト（monitor / vendor）
	CardModes         map[string]string
	ChildCardModes    map[string]map[string]string
	ActionPermissions map[string]bool
	ClientIP          string
	UserAgent         string
	CreatedAt         time.Time
	ExpiresAt         time.Time
	// CSRFToken はこのセッションに束縛された CSRF トークン。ダブルサブミットの Cookie 値はこの値と
	// 一致しなければならず、別セッションのトークンは VerifyCSRF で拒否される。
	CSRFToken string
	// TenantID はログイン時に解決したテナント ID。tenant_admin の監査ログ閲覧で
	// テナント境界をサーバー側強制するために使う（クライアント指定は信用しない）。
	TenantID string
}

// SessionManager はインメモリセッション管理。
type SessionManager struct {
	mu         sync.RWMutex
	sessions   map[string]Session
	cookieName string
	ttl        time.Duration
}

// sessionUserLookup は Get 時の Disabled / 削除再評価フック。
// 戻り値: exists=false なら「削除済みなので破棄」、disabled=true なら「停止中なので破棄」。
// 既定実装は UserStore.GetUser を引き、テストでは安全に上書きできるようにしてある。
var sessionUserLookup = func(username string) (exists bool, disabled bool) {
	u, ok := DefaultStore().GetUser(username)
	if !ok {
		return false, false
	}
	return true, u.Disabled
}

var (
	defaultSessionOnce sync.Once
	defaultSessionMgr  *SessionManager
)

// DefaultSessionManager は共有セッションマネージャを返す。
func DefaultSessionManager() *SessionManager {
	defaultSessionOnce.Do(func() {
		ttl := defaultSessionTTL
		if v := strings.TrimSpace(heartdesk.Env("HEARTDESK_SESSION_TTL_HOURS")); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				ttl = time.Duration(n) * time.Hour
			}
		}
		defaultSessionMgr = &SessionManager{
			sessions:   map[string]Session{},
			cookieName: sessionCookieName(),
			ttl:        ttl,
		}
	})
	return defaultSessionMgr
}

// TTL は現在のセッション有効期限を返す。
func (m *SessionManager) TTL() time.Duration {
	return m.ttl
}

// Create はユーザーから新規セッションを生成して保存する。
// appCards / tenantID と authz 配下の TOML を用いて tenant -> agent -> user のマージを適用する。
func (m *SessionManager) Create(u User, ip, ua string, appCards config.CardsConfig, tenantID string) (Session, error) {
	id, err := newSessionID()
	if err != nil {
		return Session{}, err
	}
	csrfToken, err := newCSRFToken()
	if err != nil {
		return Session{}, err
	}

	// access_screens は users.toml の明示指定のみを信頼する。
	// 空/省略は「全画面不可」を意味する（role 既定値フォールバックは廃止）。
	// なお本 Create は http.go 側で空チェック後に呼ばれる想定。
	accessScreens := append([]string(nil), u.AccessScreens...)

	resolved := authz.Resolve(authz.ResolveInput{
		TenantID:                tenantID,
		Username:                u.Username,
		AllCardIDs:              navmeta.AllCardIDs(),
		SystemCardDefaults:      appCards.Defaults,
		SystemChildCardDefaults: appCards.ChildDefaults,
		SystemDefaultMode:       appCards.DefaultMode,
		RoleDefaultActions:      roleDefaultActions(u.Role),
	})

	now := time.Now()
	s := Session{
		ID:                id,
		UserID:            u.ID,
		Username:          u.Username,
		Name:              u.Name,
		Role:              NormalizeRole(u.Role),
		AccessScreens:     append([]string(nil), accessScreens...),
		CardModes:         resolved.CardModes,
		ChildCardModes:    resolved.ChildCardModes,
		ActionPermissions: resolved.ActionPermissions,
		ClientIP:          ip,
		UserAgent:         ua,
		CreatedAt:         now,
		ExpiresAt:         now.Add(m.ttl),
		CSRFToken:         csrfToken,
		TenantID:          tenantID,
	}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return s, nil
}

// roleDefaultActions は role に対する全アクションの既定可否マップを返す。
func roleDefaultActions(role string) map[string]bool {
	out := make(map[string]bool, len(actionClasses))
	for action := range actionClasses {
		out[action] = DefaultActionAllowed(role, action)
	}
	return out
}

// Get は sessionID の有効セッションを取得し、スライディング延長する。
//
// users.toml 側で Disabled=true / ユーザー削除が反映された直後でも Cookie ベース
// 継続セッションが生き続けてしまう問題を防ぐため、毎回 UserStore.GetUser(...) を
// 引いて Disabled / 不在を再評価する。UserStore は内部で 30s キャッシュを持つため
// ホットパスでも低コスト（usersCacheTTL のキャッシュに吸収される）。
func (m *SessionManager) Get(sessionID string) (Session, bool) {
	if strings.TrimSpace(sessionID) == "" {
		return Session{}, false
	}
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[sessionID]
	if !ok {
		return Session{}, false
	}
	if now.After(s.ExpiresAt) {
		delete(m.sessions, sessionID)
		return Session{}, false
	}

	// ユーザーが Disabled / 削除されたら即時無効化。lookup フック経由で
	// UserStore.GetUser を引く。username 空セッションは保護的に拒否。
	if strings.TrimSpace(s.Username) == "" {
		delete(m.sessions, sessionID)
		return Session{}, false
	}
	if exists, disabled := sessionUserLookup(s.Username); !exists || disabled {
		delete(m.sessions, sessionID)
		return Session{}, false
	}

	// アクティブ利用時は有効期限を延長
	s.ExpiresAt = now.Add(m.ttl)
	m.sessions[sessionID] = s
	return s, true
}

// Delete はセッションを削除する。
func (m *SessionManager) Delete(sessionID string) {
	if sessionID == "" {
		return
	}
	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
}

// DeleteByUsername は指定 username に紐付く全セッションを走査削除する。
// exceptID が非空のとき、その ID のセッションだけは残す（自端末でのパスワード
// 変更時に「他端末だけログアウトさせたい」用途）。戻り値は削除件数。
//
// admin の Disable / DeleteUser / role 変更 / access_screens 変更 / TOTP リセットや、
// 本人のパスワード変更直後に呼び、権限変更・盗難疑いを即時セッションへ反映する。
func (m *SessionManager) DeleteByUsername(username, exceptID string) int {
	key := strings.TrimSpace(strings.ToLower(username))
	if key == "" {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for id, s := range m.sessions {
		if id == exceptID {
			continue
		}
		if strings.ToLower(strings.TrimSpace(s.Username)) != key {
			continue
		}
		delete(m.sessions, id)
		removed++
	}
	return removed
}

// SessionFromRequest は Cookie からセッションを引く。
func (m *SessionManager) SessionFromRequest(r *http.Request) (Session, bool) {
	c, err := r.Cookie(m.cookieName)
	if err != nil || c.Value == "" {
		return Session{}, false
	}
	return m.Get(c.Value)
}

// CSRFTokenForRequest はリクエストのセッションに束縛された CSRF トークンを返す。
// セッションが無い（未ログイン）場合は ("", false) を返す。VerifyCSRF /
// EnsureCSRFCookie がセッション束縛を判定するために使う。
func (m *SessionManager) CSRFTokenForRequest(r *http.Request) (string, bool) {
	s, ok := m.SessionFromRequest(r)
	if !ok || strings.TrimSpace(s.CSRFToken) == "" {
		return "", false
	}
	return s.CSRFToken, true
}

// SetCookie はセッションクッキーを設定する。
func (m *SessionManager) SetCookie(w http.ResponseWriter, r *http.Request, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(m.ttl.Seconds()),
	})
}

// ClearCookie はセッションクッキーを削除する。
func (m *SessionManager) ClearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func newSessionID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return false
}

// ClientIP は Nginx プロキシ環境を考慮してクライアントIPを返す。
//
// trustedProxy 層（TrustedClientIP）経由で解決する。
// RemoteAddr が信頼プロキシ（loopback / 登録 nginx）のときのみ X-Real-IP を採用し、
// :8765 直結時はヘッダを無視して RemoteAddr を使う。
func ClientIP(r *http.Request) string {
	return TrustedClientIP(r)
}

func sessionCookieName() string {
	if v := heartdesk.Env("HEARTDESK_SESSION_COOKIE_NAME"); v != "" {
		return v
	}
	return defaultSessionCookieName
}
