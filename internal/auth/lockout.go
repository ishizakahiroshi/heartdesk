package auth

import (
	"strings"
	"sync"
	"time"
)

const (
	defaultLockoutThreshold = 5
	defaultLockoutDuration  = 15 * time.Minute
)

type lockoutState struct {
	Failures  int
	LockedAt  time.Time
	LockedTo  time.Time
	LastIP    string
	LastError time.Time
}

// LockoutManager はユーザー単位の失敗回数とロック状態を保持する。
type LockoutManager struct {
	mu        sync.RWMutex
	threshold int
	duration  time.Duration
	users     map[string]lockoutState
}

var (
	lockoutOnce sync.Once
	lockoutMgr  *LockoutManager
)

// DefaultLockoutManager は共有マネージャを返す。
func DefaultLockoutManager() *LockoutManager {
	lockoutOnce.Do(func() {
		lockoutMgr = &LockoutManager{
			threshold: defaultLockoutThreshold,
			duration:  defaultLockoutDuration,
			users:     map[string]lockoutState{},
		}
	})
	return lockoutMgr
}

// IsLocked は現在ロック中かを返す。
//
// 複合キー（username+ip）に加えてユーザー単独キーの
// フォールバックも判定する。IP が trustedProxy 経由で偽装されても（あるいは
// 取得できなくても）ユーザー単独キーでロックが成立するため、IP 単独依存をやめる。
func (m *LockoutManager) IsLocked(username, ip string, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, key := range lockoutKeys(username, ip) {
		if m.lockedLocked(key, now) {
			return true
		}
	}
	return false
}

// lockedLocked は単一キーのロック状態を判定する（m.mu 保持下で呼ぶこと）。
func (m *LockoutManager) lockedLocked(key string, now time.Time) bool {
	if key == "" {
		return false
	}
	state, ok := m.users[key]
	if !ok {
		return false
	}
	// まだロックされていない（失敗が閾値に達する前）の状態では、失敗回数をここで消さない。
	// LockedTo がゼロ値のまま now.After を比べると常に真になり、ログインのたびに失敗回数が 0 に
	// 戻って閾値に届かず、ロックが一度も発動しなかった。
	if state.LockedTo.IsZero() {
		return false
	}
	if now.After(state.LockedTo) {
		state.Failures = 0
		state.LockedAt = time.Time{}
		state.LockedTo = time.Time{}
		m.users[key] = state
		return false
	}
	return !state.LockedTo.IsZero()
}

// RegisterFailure は失敗を記録し、ロック状態を返す。
//
// 複合キー（username+ip）とユーザー単独キーの両方に
// 失敗を記録する。返り値はいずれかがロック済みなら locked=true、remaining は
// 全キー中で最小の残回数とする。
func (m *LockoutManager) RegisterFailure(username, ip string, now time.Time) (locked bool, remaining int) {
	keys := lockoutKeys(username, ip)
	if len(keys) == 0 {
		return false, m.threshold
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	locked = false
	remaining = m.threshold
	for _, key := range keys {
		l, rem := m.registerFailureLocked(key, ip, now)
		if l {
			locked = true
		}
		if rem < remaining {
			remaining = rem
		}
	}
	return locked, remaining
}

// registerFailureLocked は単一キーへ失敗を記録する（m.mu 保持下で呼ぶこと）。
func (m *LockoutManager) registerFailureLocked(key, ip string, now time.Time) (locked bool, remaining int) {
	state := m.users[key]
	if !state.LockedTo.IsZero() && now.Before(state.LockedTo) {
		return true, 0
	}
	if !state.LockedTo.IsZero() && now.After(state.LockedTo) {
		state = lockoutState{}
	}
	state.Failures++
	state.LastIP = strings.TrimSpace(ip)
	state.LastError = now
	if state.Failures >= m.threshold {
		state.LockedAt = now
		state.LockedTo = now.Add(m.duration)
		m.users[key] = state
		return true, 0
	}
	m.users[key] = state
	return false, m.threshold - state.Failures
}

// RegisterSuccess は成功時に失敗回数をリセットする（複合キー・ユーザー単独キー両方）。
func (m *LockoutManager) RegisterSuccess(username, ip string) {
	keys := lockoutKeys(username, ip)
	if len(keys) == 0 {
		return
	}
	m.mu.Lock()
	for _, key := range keys {
		delete(m.users, key)
	}
	m.mu.Unlock()
}

// Unlock は管理者手動解除。指定ユーザーに紐づく全 IP のロックエントリのみを削除する。
// （従来は全ユーザーのエントリを削除していたバグを修正）
func (m *LockoutManager) Unlock(username string) {
	u := strings.TrimSpace(strings.ToLower(username))
	if u == "" {
		return
	}
	prefix := u + "\x00"
	m.mu.Lock()
	for k := range m.users {
		if strings.HasPrefix(k, prefix) {
			delete(m.users, k)
		}
	}
	m.mu.Unlock()
}

// lockoutKey はユーザー単位 + IP 単位の複合キーを返す。
// 旧実装は IP 単独キーだったため、同一 IP からの別ユーザーへの試行でカウンタが
// 共有され、無関係なユーザーが巻き添えロックされる問題があった。複合キー化で解消する。
// なお、多数の IP を使った単一ユーザーへの分散攻撃は per-IP 方式の本質的限界であり、
// 上位レイヤのレート制限 / CAPTCHA で対処する（本関数の責務外）。
func lockoutKey(username, ip string) string {
	u := strings.TrimSpace(strings.ToLower(username))
	ipv := strings.TrimSpace(ip)
	if u == "" && ipv == "" {
		return ""
	}
	return u + "\x00" + ipv
}

// lockoutKeys は失敗カウントに使うキー一覧を返す。
//
// 複合キー（username+ip）に加え、username が判明している
// 場合はユーザー単独キーも返す。IP が偽装/欠落しても username 単独でロックが成立し、
// IP 単独依存をやめる。ユーザー単独キーは複合キー（ip 空時の "u\x00"）と衝突しないよう
// 別サフィックスを付ける。
//
// Unlock は接頭辞 "u\x00" で削除するため、両キーともこの接頭辞で始まる必要がある。
func lockoutKeys(username, ip string) []string {
	u := strings.TrimSpace(strings.ToLower(username))
	ipv := strings.TrimSpace(ip)
	keys := make([]string, 0, 2)
	if k := lockoutKey(username, ip); k != "" {
		keys = append(keys, k)
	}
	if u != "" && ipv != "" {
		// ユーザー単独フォールバック（IP がある場合のみ複合キーと別に追加）。
		keys = append(keys, u+"\x00\x00user")
	}
	return keys
}
