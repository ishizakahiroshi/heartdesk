package auth

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

const (
	loginChallengeTTL       = 5 * time.Minute
	loginChallengeCookie    = "heartdesk_login_challenge"
	loginChallengeCookieAge = 300

	// loginChallengeSweepInterval は expired entry を一括 delete する周期。
	loginChallengeSweepInterval = 1 * time.Minute
	// loginChallengeMaxPerUser は user 単位の同時 active challenge 数上限。
	// 超過時は当該 user の古い challenge を eviction する（OOM 攻撃面の閉鎖）。
	loginChallengeMaxPerUser = 5
	// loginChallengeMaxTotal は全体の active challenge 数上限。
	// 超過時は CreatedAt が最も古いものから LRU eviction する。
	loginChallengeMaxTotal = 10000
)

type loginChallenge struct {
	ID        string
	User      User
	Next      string
	CreatedAt time.Time
	ExpiresAt time.Time
	IP        string
	UserAgent string
}

// LoginChallengeManager は2FA待ちの一時チャレンジを保持する。
type LoginChallengeManager struct {
	mu         sync.RWMutex
	challenges map[string]loginChallenge
}

var (
	challengeOnce sync.Once
	challengeMgr  *LoginChallengeManager
)

func DefaultLoginChallengeManager() *LoginChallengeManager {
	challengeOnce.Do(func() {
		challengeMgr = &LoginChallengeManager{
			challenges: map[string]loginChallenge{},
		}
		// expired entry を定期的に一括 delete するスイープゴルーチンを起動。
		// プロセス寿命と一致するため明示的な停止口は設けない（Default singleton 専用）。
		go challengeMgr.runSweepLoop(loginChallengeSweepInterval)
	})
	return challengeMgr
}

func (m *LoginChallengeManager) Create(user User, next, ip, ua string) (loginChallenge, error) {
	id, err := newChallengeID()
	if err != nil {
		return loginChallenge{}, err
	}
	now := time.Now()
	entry := loginChallenge{
		ID:        id,
		User:      user,
		Next:      next,
		CreatedAt: now,
		ExpiresAt: now.Add(loginChallengeTTL),
		IP:        strings.TrimSpace(ip),
		UserAgent: strings.TrimSpace(ua),
	}
	m.mu.Lock()
	// (a) expired を機会的に sweep（lazy）— lock 内で一括処理。
	m.sweepExpiredLocked(now)
	// (b) user 単位の上限を enforce。超過分は CreatedAt 古い順に evict。
	m.evictPerUserLocked(user.Username, loginChallengeMaxPerUser-1)
	// (c) 全体上限の LRU eviction（map が limit 以上なら evict）。
	m.evictGlobalLocked(loginChallengeMaxTotal - 1)
	m.challenges[id] = entry
	m.mu.Unlock()
	return entry, nil
}

func (m *LoginChallengeManager) Get(id string) (loginChallenge, bool) {
	key := strings.TrimSpace(id)
	if key == "" {
		return loginChallenge{}, false
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.challenges[key]
	if !ok {
		return loginChallenge{}, false
	}
	if now.After(entry.ExpiresAt) {
		delete(m.challenges, key)
		return loginChallenge{}, false
	}
	return entry, true
}

func (m *LoginChallengeManager) Delete(id string) {
	key := strings.TrimSpace(id)
	if key == "" {
		return
	}
	m.mu.Lock()
	delete(m.challenges, key)
	m.mu.Unlock()
}

// runSweepLoop は loginChallengeSweepInterval ごとに expired entry を一括 delete する。
// Default singleton から起動され、プロセス寿命と一致する。
func (m *LoginChallengeManager) runSweepLoop(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		m.sweepExpired()
	}
}

// sweepExpired は expired entry を全件走査して delete する（lock 取得版）。
func (m *LoginChallengeManager) sweepExpired() {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepExpiredLocked(now)
}

// sweepExpiredLocked は呼び出し側で m.mu が Lock 済みであることを前提に
// expired entry を全件 delete する。
func (m *LoginChallengeManager) sweepExpiredLocked(now time.Time) {
	for id, entry := range m.challenges {
		if now.After(entry.ExpiresAt) {
			delete(m.challenges, id)
		}
	}
}

// evictPerUserLocked は username に紐づく challenge 数が maxKeep 件以下になるまで
// 古いものから delete する。呼び出し側で m.mu が Lock 済みであることを前提とする。
// 新規追加直前に呼ぶことで、追加後に maxKeep+1 件になることを保証する用途。
func (m *LoginChallengeManager) evictPerUserLocked(username string, maxKeep int) {
	if maxKeep < 0 {
		maxKeep = 0
	}
	if username == "" {
		return
	}
	type ref struct {
		id        string
		createdAt time.Time
	}
	var owned []ref
	for id, entry := range m.challenges {
		if entry.User.Username == username {
			owned = append(owned, ref{id: id, createdAt: entry.CreatedAt})
		}
	}
	if len(owned) <= maxKeep {
		return
	}
	// 古い順に並べて先頭から (len - maxKeep) 件 delete。
	// 件数は最大 loginChallengeMaxPerUser 前後の小さい値で、単純ソートで十分。
	for i := 1; i < len(owned); i++ {
		for j := i; j > 0 && owned[j-1].createdAt.After(owned[j].createdAt); j-- {
			owned[j-1], owned[j] = owned[j], owned[j-1]
		}
	}
	for i := 0; i < len(owned)-maxKeep; i++ {
		delete(m.challenges, owned[i].id)
	}
}

// evictGlobalLocked は全体 entry 数が maxKeep 件以下になるまで CreatedAt が古いものから
// delete する。呼び出し側で m.mu が Lock 済みであることを前提とする。
func (m *LoginChallengeManager) evictGlobalLocked(maxKeep int) {
	if maxKeep < 0 {
		maxKeep = 0
	}
	if len(m.challenges) <= maxKeep {
		return
	}
	type ref struct {
		id        string
		createdAt time.Time
	}
	all := make([]ref, 0, len(m.challenges))
	for id, entry := range m.challenges {
		all = append(all, ref{id: id, createdAt: entry.CreatedAt})
	}
	// O(N log N) は避け、必要数だけ partial selection で済ませる。
	// limit (10000) に到達することは通常運用ではほぼ無いため、
	// 単純ソート（sort.Slice）でも問題ないが標準パッケージ依存を増やさず
	// 安価な選択ソートで上位 (len-maxKeep) 件のみ取り出す。
	toEvict := len(all) - maxKeep
	for k := 0; k < toEvict; k++ {
		minIdx := k
		for i := k + 1; i < len(all); i++ {
			if all[i].createdAt.Before(all[minIdx].createdAt) {
				minIdx = i
			}
		}
		all[k], all[minIdx] = all[minIdx], all[k]
		delete(m.challenges, all[k].id)
	}
}

func newChallengeID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
