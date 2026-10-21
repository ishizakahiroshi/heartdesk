package auth

import (
	"fmt"
	"testing"
	"time"
)

// newTestChallengeManager は singleton を経由せずに manager を生成する。
// sweep goroutine を起動しないため、テスト内で明示的に sweep を呼ぶ。
func newTestChallengeManager() *LoginChallengeManager {
	return &LoginChallengeManager{
		challenges: map[string]loginChallenge{},
	}
}

// TestChallengeSweepRemovesExpired は expired entry が sweep で一括 delete される
// （lazy eviction のみで OOM 攻撃が可能になる問題を避ける）ことを確認する。
func TestChallengeSweepRemovesExpired(t *testing.T) {
	m := newTestChallengeManager()
	// 期限切れ entry を 100 件手動で投入。
	past := time.Now().Add(-loginChallengeTTL - time.Minute)
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("expired-%d", i)
		m.challenges[id] = loginChallenge{
			ID:        id,
			User:      User{Username: fmt.Sprintf("user-%d", i)},
			CreatedAt: past,
			ExpiresAt: past.Add(loginChallengeTTL),
		}
	}
	// 有効な entry も 3 件混ぜる。
	now := time.Now()
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("alive-%d", i)
		m.challenges[id] = loginChallenge{
			ID:        id,
			User:      User{Username: "alive"},
			CreatedAt: now,
			ExpiresAt: now.Add(loginChallengeTTL),
		}
	}
	m.sweepExpired()
	if got := len(m.challenges); got != 3 {
		t.Fatalf("expected 3 alive challenges after sweep, got %d", got)
	}
}

// TestChallengeCreatePerUserLimit は同一 user が loginChallengeMaxPerUser を
// 超えて Create しても map が上限に張り付き、古いものから evict されることを確認する。
func TestChallengeCreatePerUserLimit(t *testing.T) {
	m := newTestChallengeManager()
	user := User{ID: "u1", Username: "victim"}

	// 上限の 3 倍を Create しても、user 当たりのエントリは上限以内に収まる。
	for i := 0; i < loginChallengeMaxPerUser*3; i++ {
		if _, err := m.Create(user, "/", "127.0.0.1", "ua"); err != nil {
			t.Fatalf("Create failed at %d: %v", i, err)
		}
	}
	count := 0
	for _, e := range m.challenges {
		if e.User.Username == "victim" {
			count++
		}
	}
	if count > loginChallengeMaxPerUser {
		t.Fatalf("expected per-user count <= %d, got %d", loginChallengeMaxPerUser, count)
	}

	// 他 user の challenge が誤って削除されないことも確認する。
	other := User{ID: "u2", Username: "bystander"}
	if _, err := m.Create(other, "/", "127.0.0.1", "ua"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < loginChallengeMaxPerUser; i++ {
		if _, err := m.Create(user, "/", "127.0.0.1", "ua"); err != nil {
			t.Fatal(err)
		}
	}
	foundBystander := false
	for _, e := range m.challenges {
		if e.User.Username == "bystander" {
			foundBystander = true
		}
	}
	if !foundBystander {
		t.Fatal("bystander challenge was evicted by victim's flood")
	}
}

// TestChallengeGlobalCap は全体上限 (loginChallengeMaxTotal) が enforce されることを
// 軽量化した上限値で検証する。実 const 値（10000）で回すと遅いため、
// この test 関数内では loginChallengeMaxTotal を直接参照する evict 関数のロジックを確認する。
func TestChallengeGlobalCapEvictsOldest(t *testing.T) {
	m := newTestChallengeManager()
	// 古い順に 10 件投入し、evictGlobalLocked(5) で 5 件まで減ることと、
	// CreatedAt が古いものから evict されることを確認する。
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("c-%02d", i)
		m.challenges[id] = loginChallenge{
			ID:        id,
			User:      User{Username: fmt.Sprintf("u-%d", i)},
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
			ExpiresAt: time.Now().Add(loginChallengeTTL),
		}
	}
	m.mu.Lock()
	m.evictGlobalLocked(5)
	m.mu.Unlock()
	if got := len(m.challenges); got != 5 {
		t.Fatalf("expected 5 entries after evictGlobalLocked(5), got %d", got)
	}
	// 古い 5 件 (c-00..c-04) が消え、新しい 5 件 (c-05..c-09) が残るはず。
	for i := 0; i < 5; i++ {
		if _, ok := m.challenges[fmt.Sprintf("c-%02d", i)]; ok {
			t.Errorf("expected oldest entry c-%02d to be evicted", i)
		}
	}
	for i := 5; i < 10; i++ {
		if _, ok := m.challenges[fmt.Sprintf("c-%02d", i)]; !ok {
			t.Errorf("expected newer entry c-%02d to be retained", i)
		}
	}
}

// TestChallengeGetStillEvictsExpiredLazy は既存挙動（Get での lazy eviction）が
// 壊れていないことを念のため確認する。
func TestChallengeGetStillEvictsExpiredLazy(t *testing.T) {
	m := newTestChallengeManager()
	past := time.Now().Add(-loginChallengeTTL - time.Minute)
	id := "expired"
	m.challenges[id] = loginChallenge{
		ID:        id,
		User:      User{Username: "u"},
		CreatedAt: past,
		ExpiresAt: past.Add(loginChallengeTTL),
	}
	if _, ok := m.Get(id); ok {
		t.Fatal("expected Get to return false for expired challenge")
	}
	if _, ok := m.challenges[id]; ok {
		t.Fatal("expected lazy-delete of expired challenge on Get")
	}
}
