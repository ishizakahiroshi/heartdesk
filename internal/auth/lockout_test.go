package auth

import (
	"testing"
	"time"
)

func newTestLockoutManager() *LockoutManager {
	return &LockoutManager{
		threshold: defaultLockoutThreshold,
		duration:  defaultLockoutDuration,
		users:     map[string]lockoutState{},
	}
}

// TestLockoutUsernameFallback は IP が変わっても username 単独キーで
// ロックが成立する（C3: trust-xff-ip-spoofing）ことを確認する。
func TestLockoutUsernameFallback(t *testing.T) {
	m := newTestLockoutManager()
	now := time.Now()

	// 同一ユーザーに対し毎回別 IP（IP 偽装を模す）で失敗を重ねる。
	for i := 0; i < defaultLockoutThreshold; i++ {
		ip := "203.0.113." + string(rune('1'+i))
		m.RegisterFailure("alice", ip, now)
	}
	// username 単独キーが閾値に達するため、新しい IP でもロック中になる。
	if !m.IsLocked("alice", "198.51.100.250", now) {
		t.Fatal("expected alice to be locked via username fallback despite IP rotation")
	}
	// 別ユーザーは巻き添えにならない。
	if m.IsLocked("bob", "198.51.100.250", now) {
		t.Fatal("bob must not be locked")
	}
}

// TestLockoutCompositeKey は同一 IP + username の複合キーでロックされることを確認する。
func TestLockoutCompositeKey(t *testing.T) {
	m := newTestLockoutManager()
	now := time.Now()
	for i := 0; i < defaultLockoutThreshold; i++ {
		m.RegisterFailure("carol", "203.0.113.5", now)
	}
	if !m.IsLocked("carol", "203.0.113.5", now) {
		t.Fatal("expected carol locked on composite key")
	}
}

// TestLockoutRegisterSuccessClears は成功で両キーがクリアされることを確認する。
func TestLockoutRegisterSuccessClears(t *testing.T) {
	m := newTestLockoutManager()
	now := time.Now()
	for i := 0; i < defaultLockoutThreshold-1; i++ {
		m.RegisterFailure("dave", "203.0.113.6", now)
	}
	m.RegisterSuccess("dave", "203.0.113.6")
	// クリア後は新たに閾値分失敗するまでロックされない。
	for i := 0; i < defaultLockoutThreshold-1; i++ {
		m.RegisterFailure("dave", "203.0.113.6", now)
	}
	if m.IsLocked("dave", "203.0.113.6", now) {
		t.Fatal("dave should not be locked after success reset and sub-threshold failures")
	}
}

// TestLockoutUnlockRemovesAllKeys は Unlock がユーザーの複合・単独キーを両方削除することを確認する。
func TestLockoutUnlockRemovesAllKeys(t *testing.T) {
	m := newTestLockoutManager()
	now := time.Now()
	for i := 0; i < defaultLockoutThreshold; i++ {
		m.RegisterFailure("erin", "203.0.113.7", now)
	}
	if !m.IsLocked("erin", "203.0.113.7", now) {
		t.Fatal("precondition: erin should be locked")
	}
	m.Unlock("erin")
	if m.IsLocked("erin", "203.0.113.7", now) {
		t.Fatal("erin should be unlocked (composite key)")
	}
	if m.IsLocked("erin", "198.51.100.1", now) {
		t.Fatal("erin should be unlocked (username fallback key)")
	}
}
