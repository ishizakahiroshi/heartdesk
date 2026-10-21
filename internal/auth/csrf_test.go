package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// injectSession は default SessionManager にセッションを直接登録し、
// その session_id Cookie を持つリクエストを返す（テスト補助）。
func injectSession(t *testing.T, csrfToken string) (sessionID string) {
	t.Helper()
	// Get が UserStore へ Disabled 再評価を行うため、テスト用 lookup を
	// 上書きして "tester" を常に有効ユーザーとして見せる。
	stubSessionUserLookup(t, map[string]userStub{
		"tester": {Exists: true, Disabled: false},
	})
	m := DefaultSessionManager()
	id, err := newSessionID()
	if err != nil {
		t.Fatalf("newSessionID: %v", err)
	}
	m.mu.Lock()
	m.sessions[id] = Session{
		ID:        id,
		Username:  "tester",
		Role:      string(RoleTenantUser),
		CSRFToken: csrfToken,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	m.mu.Unlock()
	t.Cleanup(func() {
		m.mu.Lock()
		delete(m.sessions, id)
		m.mu.Unlock()
	})
	return id
}

// userStub は sessionUserLookup の戻り値スタブ。
type userStub struct {
	Exists   bool
	Disabled bool
}

// stubSessionUserLookup はテスト中に sessionUserLookup を差し替える。
// t.Cleanup で必ず元に戻す。
func stubSessionUserLookup(t *testing.T, byUser map[string]userStub) {
	t.Helper()
	prev := sessionUserLookup
	sessionUserLookup = func(username string) (exists bool, disabled bool) {
		key := strings.ToLower(strings.TrimSpace(username))
		if s, ok := byUser[key]; ok {
			return s.Exists, s.Disabled
		}
		return false, false
	}
	t.Cleanup(func() {
		sessionUserLookup = prev
	})
}

func reqWithCookies(sessionID, csrfCookie, csrfHeader string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/monitor/?api=x", nil)
	if sessionID != "" {
		r.AddCookie(&http.Cookie{Name: defaultSessionCookieName, Value: sessionID})
	}
	if csrfCookie != "" {
		r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrfCookie})
	}
	if csrfHeader != "" {
		r.Header.Set("X-CSRF-Token", csrfHeader)
	}
	return r
}

// TestVerifyCSRFSessionBinding はセッションへの CSRF トークン束縛を確認する。
func TestVerifyCSRFSessionBinding(t *testing.T) {
	boundToken, _ := newCSRFToken()
	otherToken, _ := newCSRFToken()
	sessionID := injectSession(t, boundToken)

	tests := []struct {
		name       string
		sessionID  string
		csrfCookie string
		csrfHeader string
		wantErr    bool
	}{
		{
			name:       "matching bound token passes",
			sessionID:  sessionID,
			csrfCookie: boundToken,
			csrfHeader: boundToken,
			wantErr:    false,
		},
		{
			name:       "double-submit matches but not bound to session is rejected",
			sessionID:  sessionID,
			csrfCookie: otherToken,
			csrfHeader: otherToken,
			wantErr:    true,
		},
		{
			name:       "cookie and header mismatch is rejected",
			sessionID:  sessionID,
			csrfCookie: boundToken,
			csrfHeader: otherToken,
			wantErr:    true,
		},
		{
			name:       "missing csrf is rejected",
			sessionID:  sessionID,
			csrfCookie: "",
			csrfHeader: "",
			wantErr:    true,
		},
		{
			name:       "no session falls back to pure double-submit (passes)",
			sessionID:  "",
			csrfCookie: otherToken,
			csrfHeader: otherToken,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := reqWithCookies(tt.sessionID, tt.csrfCookie, tt.csrfHeader)
			err := VerifyCSRF(r)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

// TestEnsureCSRFCookieSyncsToBoundToken は logged-in セッションで Cookie が
// 束縛トークンへ揃え直される（使い回し防止）ことを確認する。
func TestEnsureCSRFCookieSyncsToBoundToken(t *testing.T) {
	boundToken, _ := newCSRFToken()
	staleToken, _ := newCSRFToken()
	sessionID := injectSession(t, boundToken)

	// 古い（別の）CSRF Cookie を持つリクエスト。
	r := httptest.NewRequest(http.MethodGet, "/monitor/", nil)
	r.AddCookie(&http.Cookie{Name: defaultSessionCookieName, Value: sessionID})
	r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: staleToken})
	w := httptest.NewRecorder()

	got := EnsureCSRFCookie(w, r)
	if got != boundToken {
		t.Fatalf("EnsureCSRFCookie returned %q, want bound %q", got, boundToken)
	}
	// Set-Cookie が束縛トークンへ更新されていること。
	setCookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, boundToken) {
		t.Fatalf("Set-Cookie should reissue bound token, got %q", setCookie)
	}
}
