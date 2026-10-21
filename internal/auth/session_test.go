package auth

import (
	"strings"
	"testing"
	"time"
)

// TestSessionGetRejectsDisabledUser の回帰テスト。
// Disabled=true になったユーザーの既存セッションが Get で即時失効することを確認する。
func TestSessionGetRejectsDisabledUser(t *testing.T) {
	stubSessionUserLookup(t, map[string]userStub{
		"alice": {Exists: true, Disabled: true},
		"bob":   {Exists: true, Disabled: false},
	})
	m := newIsolatedSessionManager()

	aliceID := injectIsolatedSession(t, m, "alice")
	bobID := injectIsolatedSession(t, m, "bob")

	if _, ok := m.Get(aliceID); ok {
		t.Fatal("expected Get to reject disabled user (alice)")
	}
	m.mu.RLock()
	_, stillStored := m.sessions[aliceID]
	m.mu.RUnlock()
	if stillStored {
		t.Fatal("expected disabled user's session to be deleted from store")
	}

	if _, ok := m.Get(bobID); !ok {
		t.Fatal("expected Get to accept non-disabled user (bob)")
	}
}

// TestSessionGetRejectsDeletedUser は、Disabled だけでなく
// users.toml から削除されたユーザーのセッションも失効することを確認する。
func TestSessionGetRejectsDeletedUser(t *testing.T) {
	stubSessionUserLookup(t, map[string]userStub{
		"alice": {Exists: false, Disabled: false}, // 削除済み
	})
	m := newIsolatedSessionManager()

	id := injectIsolatedSession(t, m, "alice")
	if _, ok := m.Get(id); ok {
		t.Fatal("expected Get to reject deleted user")
	}
}

// TestSessionDeleteByUsernameAll の回帰テスト（exceptID 無し）。
// 同一ユーザーの複数セッションが一括失効し、他ユーザーは影響を受けないことを確認する。
func TestSessionDeleteByUsernameAll(t *testing.T) {
	stubSessionUserLookup(t, map[string]userStub{
		"alice": {Exists: true, Disabled: false},
		"bob":   {Exists: true, Disabled: false},
	})
	m := newIsolatedSessionManager()

	a1 := injectIsolatedSession(t, m, "alice")
	a2 := injectIsolatedSession(t, m, "alice")
	bID := injectIsolatedSession(t, m, "bob")

	removed := m.DeleteByUsername("alice", "")
	if removed != 2 {
		t.Fatalf("DeleteByUsername removed=%d, want 2", removed)
	}
	if _, ok := m.Get(a1); ok {
		t.Fatal("alice session 1 should be removed")
	}
	if _, ok := m.Get(a2); ok {
		t.Fatal("alice session 2 should be removed")
	}
	if _, ok := m.Get(bID); !ok {
		t.Fatal("bob session should survive (different user)")
	}
}

// TestSessionDeleteByUsernameExceptCurrent の回帰テスト。
// パスワード変更時に「自端末（現セッション）だけ残す」ユースケースを確認する。
func TestSessionDeleteByUsernameExceptCurrent(t *testing.T) {
	stubSessionUserLookup(t, map[string]userStub{
		"alice": {Exists: true, Disabled: false},
	})
	m := newIsolatedSessionManager()

	current := injectIsolatedSession(t, m, "alice")
	other1 := injectIsolatedSession(t, m, "alice")
	other2 := injectIsolatedSession(t, m, "alice")

	removed := m.DeleteByUsername("alice", current)
	if removed != 2 {
		t.Fatalf("DeleteByUsername(exceptID) removed=%d, want 2", removed)
	}
	if _, ok := m.Get(current); !ok {
		t.Fatal("current session should be preserved by exceptID")
	}
	if _, ok := m.Get(other1); ok {
		t.Fatal("other1 session should be removed")
	}
	if _, ok := m.Get(other2); ok {
		t.Fatal("other2 session should be removed")
	}
}

// TestSessionDeleteByUsernameIsCaseInsensitive はユーザー名の大文字小文字差異で
// 取りこぼしが起きないことを確認する（store 側のキーは ToLower 済みのため）。
func TestSessionDeleteByUsernameIsCaseInsensitive(t *testing.T) {
	stubSessionUserLookup(t, map[string]userStub{
		"alice": {Exists: true, Disabled: false},
	})
	m := newIsolatedSessionManager()

	id := injectIsolatedSession(t, m, "Alice") // 大文字始まりで登録
	removed := m.DeleteByUsername("ALICE", "")
	if removed != 1 {
		t.Fatalf("DeleteByUsername case-insensitive removed=%d, want 1", removed)
	}
	if _, ok := m.Get(id); ok {
		t.Fatal("session should be removed regardless of case")
	}
}

// TestSessionDeleteByUsernameEmptyIsNoop は空 username で誤動作しないことを確認する。
func TestSessionDeleteByUsernameEmptyIsNoop(t *testing.T) {
	stubSessionUserLookup(t, map[string]userStub{
		"alice": {Exists: true, Disabled: false},
	})
	m := newIsolatedSessionManager()
	_ = injectIsolatedSession(t, m, "alice")

	if got := m.DeleteByUsername("", ""); got != 0 {
		t.Fatalf("empty username should be no-op, removed=%d", got)
	}
	if got := m.DeleteByUsername("   ", ""); got != 0 {
		t.Fatalf("whitespace username should be no-op, removed=%d", got)
	}
}

// --- helpers ---

func newIsolatedSessionManager() *SessionManager {
	return &SessionManager{
		sessions:   map[string]Session{},
		cookieName: defaultSessionCookieName,
		ttl:        time.Hour,
	}
}

func injectIsolatedSession(t *testing.T, m *SessionManager, username string) string {
	t.Helper()
	id, err := newSessionID()
	if err != nil {
		t.Fatalf("newSessionID: %v", err)
	}
	now := time.Now()
	m.mu.Lock()
	m.sessions[id] = Session{
		ID:        id,
		Username:  strings.TrimSpace(username),
		Role:      string(RoleTenantUser),
		CreatedAt: now,
		ExpiresAt: now.Add(m.ttl),
	}
	m.mu.Unlock()
	return id
}
