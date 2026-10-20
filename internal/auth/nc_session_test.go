package auth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func useNCSessionTestDefaults(t *testing.T, users map[string]User) (*UserStore, *SessionManager) {
	t.Helper()

	// DefaultStore / DefaultSessionManager はプロセス全体の singleton だが、
	// nc_session の認証境界をテストするため、各テスト専用の空間へ差し替える。
	oldStore := DefaultStore()
	store := &UserStore{
		path:     filepath.Join(t.TempDir(), "users.toml"),
		users:    cloneUsers(users),
		loadedAt: time.Now(),
	}
	defaultStore = store

	oldSessionMgr := DefaultSessionManager()
	sessionMgr := &SessionManager{
		sessions:   map[string]Session{},
		cookieName: defaultSessionCookieName,
		ttl:        defaultSessionTTL,
	}
	defaultSessionMgr = sessionMgr

	t.Cleanup(func() {
		defaultStore = oldStore
		defaultSessionMgr = oldSessionMgr
	})
	return store, sessionMgr
}

func ncSessionCookie(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == defaultSessionCookieName && c.Value != "" {
			return c
		}
	}
	return nil
}

func TestLoginNCNoBaseConfigured(t *testing.T) {
	h := testHTTPHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/login/nc", nil)
	w := httptest.NewRecorder()

	h.loginNCWithBase(w, r, "")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (login page re-rendered)", w.Code)
	}
	if got := w.Body.String(); !strings.Contains(got, "ok") {
		t.Fatalf("body = %q, want login template output", got)
	}
}

func TestLoginNCNoCookie(t *testing.T) {
	h := testHTTPHandler(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called when no cookie is present")
	}))
	defer srv.Close()

	r := httptest.NewRequest(http.MethodGet, "/login/nc", nil)
	w := httptest.NewRecorder()

	h.loginNCWithBase(w, r, srv.URL)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestLoginNCUnauthorized(t *testing.T) {
	h := testHTTPHandler(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("OCS-APIRequest") != "true" {
			t.Errorf("missing OCS-APIRequest header")
		}
		if r.Header.Get("Cookie") == "" {
			t.Errorf("cookie was not forwarded")
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	r := httptest.NewRequest(http.MethodGet, "/login/nc", nil)
	r.Header.Set("Cookie", "oc_sessionPassphrase=abc")
	w := httptest.NewRecorder()

	h.loginNCWithBase(w, r, srv.URL)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestLoginNCUpstreamUnreachable(t *testing.T) {
	h := testHTTPHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/login/nc", nil)
	r.Header.Set("Cookie", "oc_sessionPassphrase=abc")
	w := httptest.NewRecorder()

	start := time.Now()
	// 存在しないポート番号（127.0.0.1:1）へ向け、接続失敗を即座に起こす。
	h.loginNCWithBase(w, r, "http://127.0.0.1:1")
	elapsed := time.Since(start)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if elapsed > ncSessionTimeout+2*time.Second {
		t.Fatalf("took %v, want well under timeout (%v)", elapsed, ncSessionTimeout)
	}
}

func TestLoginNCMalformedJSON(t *testing.T) {
	h := testHTTPHandler(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	r := httptest.NewRequest(http.MethodGet, "/login/nc", nil)
	r.Header.Set("Cookie", "oc_sessionPassphrase=abc")
	w := httptest.NewRecorder()

	h.loginNCWithBase(w, r, srv.URL)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestLoginNCStatusCodeNotOK(t *testing.T) {
	h := testHTTPHandler(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ocs":{"meta":{"statuscode":997},"data":{"id":""}}}`))
	}))
	defer srv.Close()

	r := httptest.NewRequest(http.MethodGet, "/login/nc", nil)
	r.Header.Set("Cookie", "oc_sessionPassphrase=abc")
	w := httptest.NewRecorder()

	h.loginNCWithBase(w, r, srv.URL)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == defaultSessionCookieName {
			t.Fatalf("session cookie %q was set, want none (no session should be created)", c.Name)
		}
	}
}

func TestLoginNCServerError(t *testing.T) {
	h := testHTTPHandler(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := httptest.NewRequest(http.MethodGet, "/login/nc", nil)
	r.Header.Set("Cookie", "oc_sessionPassphrase=abc")
	w := httptest.NewRecorder()

	h.loginNCWithBase(w, r, srv.URL)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == defaultSessionCookieName {
			t.Fatalf("session cookie %q was set, want none (no session should be created)", c.Name)
		}
	}
}

func TestLoginNCRejectsUnregisteredUserWithoutCreatingAccountOrSession(t *testing.T) {
	h := testHTTPHandler(t)
	store, sessionMgr := useNCSessionTestDefaults(t, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ocs":{"meta":{"statuscode":100},"data":{"id":"nextcloud-only-user"}}}`))
	}))
	defer srv.Close()

	r := httptest.NewRequest(http.MethodGet, "/login/nc", nil)
	r.Header.Set("Cookie", "oc_sessionPassphrase=abc")
	w := httptest.NewRecorder()

	h.loginNCWithBase(w, r, srv.URL)

	if got := len(store.ListUsers()); got != 0 {
		t.Fatalf("registered users = %d, want 0 (SSO must not auto-create users)", got)
	}
	if c := ncSessionCookie(w); c != nil {
		t.Fatalf("session cookie %q was set for an unregistered user", c.Name)
	}
	if got := len(sessionMgr.sessions); got != 0 {
		t.Fatalf("sessions = %d, want 0", got)
	}
}

func TestLoginNCRejectsDisabledUser(t *testing.T) {
	h := testHTTPHandler(t)
	_, sessionMgr := useNCSessionTestDefaults(t, map[string]User{
		"disabled-user": {
			ID:            "disabled-user",
			Username:      "disabled-user",
			Name:          "Disabled User",
			Role:          string(RoleTenantUser),
			Disabled:      true,
			AccessScreens: []string{string(ScreenMonitor)},
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ocs":{"meta":{"statuscode":100},"data":{"id":"disabled-user"}}}`))
	}))
	defer srv.Close()

	r := httptest.NewRequest(http.MethodGet, "/login/nc", nil)
	r.Header.Set("Cookie", "oc_sessionPassphrase=abc")
	w := httptest.NewRecorder()

	h.loginNCWithBase(w, r, srv.URL)

	if c := ncSessionCookie(w); c != nil {
		t.Fatalf("session cookie %q was set for a disabled user", c.Name)
	}
	if got := len(sessionMgr.sessions); got != 0 {
		t.Fatalf("sessions = %d, want 0", got)
	}
}

func TestLoginNCRoleComesOnlyFromSABUser(t *testing.T) {
	h := testHTTPHandler(t)
	_, sessionMgr := useNCSessionTestDefaults(t, map[string]User{
		"tenant-user": {
			ID:            "tenant-user",
			Username:      "tenant-user",
			Name:          "Tenant User",
			Role:          string(RoleTenantUser),
			AccessScreens: []string{string(ScreenMonitor)},
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Nextcloud 側が管理者相当の groups を返しても、SAB の role へ反映しない。
		w.Write([]byte(`{"ocs":{"meta":{"statuscode":100},"data":{"id":"tenant-user","groups":["admin","vendor_staff"]}}}`))
	}))
	defer srv.Close()

	r := httptest.NewRequest(http.MethodGet, "/login/nc?next=/monitor", nil)
	r.Header.Set("Cookie", "oc_sessionPassphrase=abc")
	w := httptest.NewRecorder()

	h.loginNCWithBase(w, r, srv.URL)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	c := ncSessionCookie(w)
	if c == nil {
		t.Fatal("session cookie was not set for a registered user")
	}
	s, ok := sessionMgr.sessions[c.Value]
	if !ok {
		t.Fatal("created session was not stored")
	}
	if s.Role != string(RoleTenantUser) {
		t.Fatalf("session role = %q, want SAB role %q", s.Role, RoleTenantUser)
	}
	if ActionAllowed(s.ActionPermissions, s.Role, "reboot") {
		t.Fatal("tenant_user gained destructive permission from Nextcloud groups")
	}
}
