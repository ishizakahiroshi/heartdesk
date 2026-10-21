package auth

import (
	"testing"
	"time"
)

// TestLockoutLocksWhenCheckedBeforeEachFailure は、HTTP のログインと同じ順序
// （毎回 IsLocked で確かめてから、失敗なら RegisterFailure）で誤ったパスワードを重ねたとき、
// 閾値の回数でロックが成立することを確認する。
// 以前は、閾値に達する前の状態で IsLocked が失敗回数を 0 に戻していたため、ロックが一度も発動しなかった。
func TestLockoutLocksWhenCheckedBeforeEachFailure(t *testing.T) {
	m := newTestLockoutManager()
	now := time.Now()
	const user, ip = "alice", "203.0.113.10"

	for i := 1; i <= defaultLockoutThreshold; i++ {
		if m.IsLocked(user, ip, now) {
			t.Fatalf("attempt %d: must not be locked before the threshold", i)
		}
		locked, _ := m.RegisterFailure(user, ip, now)
		if i < defaultLockoutThreshold && locked {
			t.Fatalf("attempt %d: locked too early", i)
		}
		if i == defaultLockoutThreshold && !locked {
			t.Fatalf("attempt %d: expected the threshold failure to lock the account", i)
		}
	}
	// 次の試行は、IP が変わっても拒否される（正しいパスワードでも入れない）。
	if !m.IsLocked(user, ip, now.Add(time.Second)) {
		t.Fatal("expected to be locked right after the threshold")
	}
	if !m.IsLocked(user, "198.51.100.77", now.Add(time.Second)) {
		t.Fatal("expected to be locked from another IP (username key)")
	}
	// 別のユーザーは巻き添えにならない。
	if m.IsLocked("bob", ip, now.Add(time.Second)) {
		t.Fatal("bob must not be locked")
	}
	// ロックの時間が過ぎると解除され、失敗の回数も 0 から数え直す。
	after := now.Add(defaultLockoutDuration + time.Second)
	if m.IsLocked(user, ip, after) {
		t.Fatal("expected the lock to expire after the duration")
	}
	if locked, remaining := m.RegisterFailure(user, ip, after); locked || remaining != defaultLockoutThreshold-1 {
		t.Fatalf("expected the count to restart after expiry: locked=%v remaining=%d", locked, remaining)
	}
}

// TestLockoutPartialFailuresAreNotForgottenByCheck は、閾値の手前で IsLocked を呼んでも
// 失敗回数が消えないことを確認する。
func TestLockoutPartialFailuresAreNotForgottenByCheck(t *testing.T) {
	m := newTestLockoutManager()
	now := time.Now()
	m.RegisterFailure("alice", "203.0.113.10", now)
	m.RegisterFailure("alice", "203.0.113.10", now)
	_ = m.IsLocked("alice", "203.0.113.10", now)
	if _, remaining := m.RegisterFailure("alice", "203.0.113.10", now); remaining != defaultLockoutThreshold-3 {
		t.Fatalf("failures were forgotten by IsLocked: remaining=%d", remaining)
	}
}
