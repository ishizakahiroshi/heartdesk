package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

const (
	totpDigits = 6
	totpPeriod = 30
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret は Base32 形式の秘密鍵を生成する。
func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return b32.EncodeToString(raw), nil
}

// verifyTOTP は TOTP コードを検証する（±window ステップ許容）。
//
// パッケージ内限定（package-private）。
// 外部はリプレイ防止カウンタを記録する Manager 経由（Verify / EnableAfterVerify）を使う。
// 本関数はカウンタを記録しないため、auth パッケージ内の補助用途に限定する。
//
//nolint:unused // Manager 経由統一により現状未使用。素の検証ロジックの内部リファレンスとして残す。
func verifyTOTP(secret, code string, now time.Time, window int) bool {
	_, ok := verifyTOTPCounter(secret, code, now, window)
	return ok
}

// verifyTOTPCounter は一致した HOTP カウンタ値と検証成否を返す。
// リプレイ防止（使用済みカウンタの拒否）のため、一致したカウンタを呼び出し元へ返す。
func verifyTOTPCounter(secret, code string, now time.Time, window int) (int64, bool) {
	secret = strings.TrimSpace(strings.ToUpper(secret))
	code = strings.TrimSpace(code)
	if secret == "" || len(code) != totpDigits {
		return 0, false
	}
	key, err := b32.DecodeString(secret)
	if err != nil || len(key) == 0 {
		return 0, false
	}
	counter := now.Unix() / totpPeriod
	for i := -window; i <= window; i++ {
		c := counter + int64(i)
		if code == hotpCode(key, c) {
			return c, true
		}
	}
	return 0, false
}

func hotpCode(key []byte, counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))

	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := int(sum[len(sum)-1] & 0x0f)
	value := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)
	mod := value % 1000000
	return fmt.Sprintf("%06d", mod)
}

// TOTPProvisioningURI は authenticator 用 otpauth URI を返す。
func TOTPProvisioningURI(issuer, username, secret string) string {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		issuer = "heartdesk"
	}
	label := url.PathEscape(issuer + ":" + username)
	q := url.Values{}
	q.Set("secret", strings.TrimSpace(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(totpDigits))
	q.Set("period", strconv.Itoa(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

type totpEntry struct {
	Secret  string
	Enabled bool
	// LastCounter はリプレイ防止用に受理済みの最大 HOTP カウンタを保持する。
	LastCounter int64
}

// TOTPManager は 2FA 状態を保持し、config/totp.toml（0600）に永続化する。
// 永続化により、プロセス再起動で 2FA が静かに無効化される問題を防ぐ。
type TOTPManager struct {
	mu    sync.RWMutex
	users map[string]totpEntry
	path  string
}

var (
	totpOnce sync.Once
	totpMgr  *TOTPManager
)

// DefaultTOTPManager は共有 TOTP マネージャを返す。
func DefaultTOTPManager() *TOTPManager {
	totpOnce.Do(func() {
		totpMgr = &TOTPManager{
			users: map[string]totpEntry{},
			path:  heartdesk.Path("config/totp.toml"),
		}
		totpMgr.mu.Lock()
		totpMgr.loadLocked()
		totpMgr.mu.Unlock()
	})
	return totpMgr
}

// --- 永続化（config/totp.toml） ---

type totpPersistRow struct {
	Username    string `toml:"username"`
	Secret      string `toml:"secret"`
	Enabled     bool   `toml:"enabled"`
	LastCounter int64  `toml:"last_counter"`
}

type totpPersistFile struct {
	Users []totpPersistRow `toml:"users"`
}

// loadLocked は永続化ファイルから状態を読み込む（mu 保持下で呼ぶ）。
func (m *TOTPManager) loadLocked() {
	if m.path == "" {
		return
	}
	raw, err := os.ReadFile(m.path)
	if err != nil {
		return // 未作成は正常
	}
	var f totpPersistFile
	if err := toml.Unmarshal(raw, &f); err != nil {
		log.Printf("auth: totp persist decode error: %v", err)
		return
	}
	for _, r := range f.Users {
		key := strings.TrimSpace(strings.ToLower(r.Username))
		if key == "" {
			continue
		}
		m.users[key] = totpEntry{
			Secret:      strings.TrimSpace(strings.ToUpper(r.Secret)),
			Enabled:     r.Enabled,
			LastCounter: r.LastCounter,
		}
	}
}

// saveLocked は状態を 0600 でアトミックに永続化する（mu 保持下で呼ぶ）。
func (m *TOTPManager) saveLocked() {
	if m.path == "" {
		return
	}
	f := totpPersistFile{}
	for k, e := range m.users {
		f.Users = append(f.Users, totpPersistRow{
			Username:    k,
			Secret:      e.Secret,
			Enabled:     e.Enabled,
			LastCounter: e.LastCounter,
		})
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(f); err != nil {
		log.Printf("auth: totp persist encode error: %v", err)
		return
	}
	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("auth: totp persist mkdir error: %v", err)
		return
	}
	tmp, err := os.CreateTemp(dir, ".totp-*.tmp")
	if err != nil {
		log.Printf("auth: totp persist temp error: %v", err)
		return
	}
	tmpPath := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		log.Printf("auth: totp persist write error: %v", err)
		return
	}
	if err := tmp.Close(); err != nil {
		log.Printf("auth: totp persist close error: %v", err)
		return
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		log.Printf("auth: totp persist chmod error: %v", err)
		return
	}
	if err := os.Rename(tmpPath, m.path); err != nil {
		log.Printf("auth: totp persist rename error: %v", err)
		return
	}
	renamed = true
}

// SetSecret はユーザーの秘密鍵を保存する（Enable 指定可能）。
func (m *TOTPManager) SetSecret(username, secret string, enable bool) {
	key := strings.TrimSpace(strings.ToLower(username))
	if key == "" || strings.TrimSpace(secret) == "" {
		return
	}
	m.mu.Lock()
	// 秘密鍵を再設定する場合はリプレイ防止カウンタをリセットする。
	m.users[key] = totpEntry{
		Secret:  strings.TrimSpace(strings.ToUpper(secret)),
		Enabled: enable,
	}
	m.saveLocked()
	m.mu.Unlock()
}

// Get はユーザーの TOTP 設定を返す。
func (m *TOTPManager) Get(username string) (secret string, enabled bool, ok bool) {
	key := strings.TrimSpace(strings.ToLower(username))
	if key == "" {
		return "", false, false
	}
	m.mu.RLock()
	entry, exists := m.users[key]
	m.mu.RUnlock()
	if !exists {
		return "", false, false
	}
	return entry.Secret, entry.Enabled, true
}

// IsEnabled はユーザーの TOTP 有効状態を返す。
func (m *TOTPManager) IsEnabled(username string) bool {
	_, enabled, ok := m.Get(username)
	return ok && enabled
}

// Verify はユーザーの TOTP コードを検証する。
// リプレイ防止のため、一致した HOTP カウンタが受理済み最大カウンタ以下なら拒否する
// （RFC 6238: ウィンドウ内の使用済みコードの再利用を不可とする）。
func (m *TOTPManager) Verify(username, code string, now time.Time) bool {
	key := strings.TrimSpace(strings.ToLower(username))
	if key == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.users[key]
	if !ok || !entry.Enabled {
		return false
	}
	counter, valid := verifyTOTPCounter(entry.Secret, code, now, 1)
	if !valid {
		return false
	}
	if counter <= entry.LastCounter {
		// 使用済み（または巻き戻り）カウンタ → リプレイとして拒否
		return false
	}
	entry.LastCounter = counter
	m.users[key] = entry
	m.saveLocked()
	return true
}

// EnableAfterVerify は 2FA 有効化フロー専用の検証＋有効化を 1 操作で行う。
//
// 有効化はまだ Enabled=false の秘密鍵に対して
// 行うため Verify（Enabled 必須）は使えない。本メソッドは未有効の秘密鍵に対して
// verifyTOTPCounter で検証し、成功時に消費カウンタを LastCounter へ記録したうえで
// Enabled=true にする。これにより有効化に使ったコードが直後のログインで再利用できない。
// 素の VerifyTOTP（カウンタ記録なし）を有効化経路から排除するための統一入口。
func (m *TOTPManager) EnableAfterVerify(username, code string, now time.Time) bool {
	key := strings.TrimSpace(strings.ToLower(username))
	if key == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.users[key]
	if !ok || strings.TrimSpace(entry.Secret) == "" {
		return false
	}
	counter, valid := verifyTOTPCounter(entry.Secret, code, now, 1)
	if !valid {
		return false
	}
	if counter <= entry.LastCounter {
		return false
	}
	entry.LastCounter = counter
	entry.Enabled = true
	m.users[key] = entry
	m.saveLocked()
	return true
}

// Disable はユーザーの2FAを無効化する。
func (m *TOTPManager) Disable(username string) {
	key := strings.TrimSpace(strings.ToLower(username))
	if key == "" {
		return
	}
	m.mu.Lock()
	entry, ok := m.users[key]
	if ok {
		entry.Enabled = false
		m.users[key] = entry
		m.saveLocked()
	}
	m.mu.Unlock()
}

// Reset はユーザーの2FA情報を削除する。
func (m *TOTPManager) Reset(username string) {
	key := strings.TrimSpace(strings.ToLower(username))
	if key == "" {
		return
	}
	m.mu.Lock()
	delete(m.users, key)
	m.saveLocked()
	m.mu.Unlock()
}
