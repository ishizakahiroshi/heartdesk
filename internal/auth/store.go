package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/bcrypt"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

const usersCacheTTL = 30 * time.Second

var (
	errUserNotFound      = errors.New("user not found")
	errInvalidCredential = errors.New("invalid credentials")
	errInvalidUserRole   = errors.New("invalid user role")
	errUserExists        = errors.New("user already exists")
	errLastAdmin         = errors.New("last vendor_staff user cannot be removed")
)

// UserStore は users.toml を読み込んで認証を行う。
type UserStore struct {
	path string

	mu       sync.RWMutex
	users    map[string]User
	loadedAt time.Time
}

var (
	defaultStoreOnce sync.Once
	defaultStore     *UserStore
)

// dummyBcryptHash はユーザー列挙タイミング攻撃対策用の
// 固定 bcrypt ハッシュ。ユーザー不在/Disabled 時にこのハッシュへ
// CompareHashAndPassword を実行し、存在ユーザーと計算時間を揃える。
// パッケージ初期化時に 1 度だけ生成して使い回す。
var dummyBcryptHash = func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("heartdesk-username-enum-timing-dummy"), bcryptCost)
	if err != nil {
		// 生成失敗は致命ではない（タイミング均一化の最善努力）。空なら compare がすぐ失敗する。
		return nil
	}
	return h
}()

// runDummyPasswordCompare はユーザー不在/Disabled 時に呼び、bcrypt 相当の計算時間を消費する。
func runDummyPasswordCompare(password string) {
	if dummyBcryptHash == nil {
		return
	}
	_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
}

// DefaultStore は共有ユーザーストアを返す。
func DefaultStore() *UserStore {
	defaultStoreOnce.Do(func() {
		path := heartdesk.Env("HEARTDESK_USERS_TOML")
		if path == "" {
			path = heartdesk.Env("HEARTDESK_USERS_JSON")
		}
		if path == "" {
			path = heartdesk.Path("config/users.toml")
		}
		defaultStore = &UserStore{
			path:  path,
			users: map[string]User{},
		}
	})
	return defaultStore
}

// Authenticate はユーザー名とパスワードを検証する。
func (s *UserStore) Authenticate(username, password string) (User, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	if username == "" || password == "" {
		return User{}, errInvalidCredential
	}
	users := s.loadUsers()
	u, ok := users[username]
	if !ok || u.Disabled {
		// 不在/Disabled でもダミー bcrypt 比較を実行して
		// 存在ユーザーとの応答時間差を消す（タイミングによるユーザー列挙を防ぐ）。
		runDummyPasswordCompare(password)
		return User{}, errUserNotFound
	}
	if !VerifyPassword(u.PasswordHash, password) {
		return User{}, errInvalidCredential
	}
	// 旧方式（sha256$ 等）で保存されていた場合はログイン成功時に bcrypt へ再ハッシュし、
	// users.toml を無停止で移行する。失敗してもログイン自体は成功扱いとする。
	if needsPasswordRehash(u.PasswordHash) {
		if newHash, err := HashPassword(password); err == nil {
			if mErr := s.mutate(func(users map[string]User) error {
				if cur, ok := users[username]; ok {
					cur.PasswordHash = newHash
					users[username] = cur
				}
				return nil
			}); mErr != nil {
				log.Printf("auth: password rehash persist failed user=%s: %v", username, mErr)
			} else {
				u.PasswordHash = newHash
			}
		}
	}
	return u, nil
}

// ListUsers はユーザー一覧を返す（username 昇順）。
func (s *UserStore) ListUsers() []User {
	users := s.loadUsers()
	rows := make([]User, 0, len(users))
	for _, u := range users {
		rows = append(rows, u)
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Username < rows[j].Username
	})
	return rows
}

// GetUser はユーザー名で1件取得する。
func (s *UserStore) GetUser(username string) (User, bool) {
	key := strings.TrimSpace(strings.ToLower(username))
	if key == "" {
		return User{}, false
	}
	users := s.loadUsers()
	u, ok := users[key]
	return u, ok
}

// AddUser は新規ユーザーを追加する。
func (s *UserStore) AddUser(username, name, role, password string) error {
	key := strings.TrimSpace(strings.ToLower(username))
	if key == "" || strings.TrimSpace(password) == "" {
		return errInvalidCredential
	}
	role = NormalizeRole(role)
	if role == "" {
		return errInvalidUserRole
	}
	if strings.TrimSpace(name) == "" {
		name = key
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	return s.mutate(func(users map[string]User) error {
		if _, exists := users[key]; exists {
			return errUserExists
		}
		users[key] = User{
			ID:           key,
			Username:     key,
			Name:         strings.TrimSpace(name),
			PasswordHash: hash,
			Role:         role,
		}
		return nil
	})
}

// DeleteUser は対象ユーザーを削除する。
func (s *UserStore) DeleteUser(username string) error {
	key := strings.TrimSpace(strings.ToLower(username))
	if key == "" {
		return errUserNotFound
	}
	return s.mutate(func(users map[string]User) error {
		target, ok := users[key]
		if !ok {
			return errUserNotFound
		}
		if target.Role == string(RoleVendorStaff) && countRole(users, string(RoleVendorStaff)) <= 1 {
			return errLastAdmin
		}
		delete(users, key)
		return nil
	})
}

// UpdateAccessScreens はユーザーの access_screens を更新する。
func (s *UserStore) UpdateAccessScreens(username string, screens []string) error {
	key := strings.TrimSpace(strings.ToLower(username))
	if key == "" {
		return errUserNotFound
	}
	return s.mutate(func(users map[string]User) error {
		u, ok := users[key]
		if !ok {
			return errUserNotFound
		}
		u.AccessScreens = sanitizeScreens(screens)
		users[key] = u
		return nil
	})
}

// ResetAccessScreens はユーザーの access_screens を role 既定値にリセットする。
// policy 系（cards_user.toml / actions_user.toml）のリセットは authz.DeleteUserEntries を利用する。
func (s *UserStore) ResetAccessScreens(username string) error {
	key := strings.TrimSpace(strings.ToLower(username))
	if key == "" {
		return errUserNotFound
	}
	return s.mutate(func(users map[string]User) error {
		u, ok := users[key]
		if !ok {
			return errUserNotFound
		}
		u.AccessScreens = nil
		users[key] = u
		return nil
	})
}

// UpdateUserRole はユーザーロールを更新する。
func (s *UserStore) UpdateUserRole(username, role string) error {
	key := strings.TrimSpace(strings.ToLower(username))
	role = NormalizeRole(role)
	if key == "" {
		return errUserNotFound
	}
	if role == "" {
		return errInvalidUserRole
	}
	return s.mutate(func(users map[string]User) error {
		u, ok := users[key]
		if !ok {
			return errUserNotFound
		}
		if u.Role == string(RoleVendorStaff) && role != string(RoleVendorStaff) && countRole(users, string(RoleVendorStaff)) <= 1 {
			return errLastAdmin
		}
		u.Role = role
		users[key] = u
		return nil
	})
}

// UpdateName はユーザーの表示名を更新する。
func (s *UserStore) UpdateName(username, name string) error {
	key := strings.TrimSpace(strings.ToLower(username))
	name = strings.TrimSpace(name)
	if key == "" {
		return errUserNotFound
	}
	if name == "" {
		return errInvalidCredential
	}
	return s.mutate(func(users map[string]User) error {
		u, ok := users[key]
		if !ok {
			return errUserNotFound
		}
		u.Name = name
		users[key] = u
		return nil
	})
}

// UpdatePassword はユーザーパスワードを更新する。
func (s *UserStore) UpdatePassword(username, password string) error {
	key := strings.TrimSpace(strings.ToLower(username))
	if key == "" || strings.TrimSpace(password) == "" {
		return errInvalidCredential
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return s.mutate(func(users map[string]User) error {
		u, ok := users[key]
		if !ok {
			return errUserNotFound
		}
		u.PasswordHash = hash
		users[key] = u
		return nil
	})
}

// rawUser は users.toml デシリアライズ用の一時構造体（旧フィールド検出を含む）。
type rawUser struct {
	ID            string   `toml:"id"`
	Username      string   `toml:"username"`
	Name          string   `toml:"name"`
	PasswordHash  string   `toml:"password_hash"`
	Role          string   `toml:"role"`
	Disabled      bool     `toml:"disabled,omitempty"`
	AccessScreens []string `toml:"access_screens,omitempty"`

	// 旧フィールド検出用（値は使わない）
	AccessOKRoles interface{} `toml:"access_ok_roles,omitempty"`
	Permissions   interface{} `toml:"permissions,omitempty"`
	Denies        interface{} `toml:"denies,omitempty"`
	Policy        interface{} `toml:"policy,omitempty"` // cards_user.toml / actions_user.toml に分離済み
}

type usersFile struct {
	Users []rawUser `toml:"users"`
}

// validateAndConvertRaw は旧スキーマ検出バリデーションを行い、User に変換する。
// 旧スキーマや無効 role を検出した場合は (User{}, error) を返す。
// 呼び出し元（loadUsers / loadUsersNoLock）はホットパスから到達するため
// log.Fatalf 等でプロセスを落としてはならない。起動時の fail-fast 検証は
// ValidateAllOrFatal を main から明示的に呼ぶことで実現する。
//
// 旧フィールド名が users.toml に紛れ込んだだけで稼働中の
// heartdesk プロセスが exit する foot-gun を取り除く。
func validateAndConvertRaw(raw rawUser) (User, error) {
	key := strings.TrimSpace(strings.ToLower(raw.Username))

	// 旧フィールド検出 → error
	if raw.AccessOKRoles != nil {
		return User{}, fmt.Errorf(
			"users.toml: ユーザー %q に旧フィールド access_ok_roles が存在します。"+
				" 新フィールド access_screens に差し替えてください。",
			key,
		)
	}
	if raw.Permissions != nil {
		return User{}, fmt.Errorf(
			"users.toml: ユーザー %q に旧フィールド permissions が存在します。"+
				" policy.actions に統合してください。",
			key,
		)
	}
	if raw.Denies != nil {
		return User{}, fmt.Errorf(
			"users.toml: ユーザー %q に旧フィールド denies が存在します。"+
				" actions_user.toml の deny に統合してください。",
			key,
		)
	}
	if raw.Policy != nil {
		return User{}, fmt.Errorf(
			"users.toml: ユーザー %q に旧フィールド policy が存在します。"+
				" policy.cards/child_cards は cards_user.toml、policy.actions は actions_user.toml に分離してください。",
			key,
		)
	}

	// role バリデーション
	role := NormalizeRole(raw.Role)
	if role == "" {
		return User{}, fmt.Errorf(
			"users.toml: ユーザー %q の role=%q は旧スキーマまたは無効値です。"+
				" 新ロール（vendor_staff / tenant_admin / tenant_user）に差し替えてください。",
			key, raw.Role,
		)
	}

	// password_hash は HashPassword() と同じく "bcrypt$" プレフィックス必須（VerifyPassword が要求する）。
	// 生の bcrypt ハッシュ（$2a$/$2b$/$2y$ 始まり）だけを手で貼ると、ログイン時に
	// 「unknown password hash format」で静かに拒否される。
	if h := strings.TrimSpace(raw.PasswordHash); h != "" && !strings.HasPrefix(h, "bcrypt$") {
		for _, p := range []string{"$2a$", "$2b$", "$2y$"} {
			if strings.HasPrefix(h, p) {
				return User{}, fmt.Errorf(
					"users.toml: ユーザー %q の password_hash に \"bcrypt$\" プレフィックスがありません。"+
						" HashPassword() が生成する形式（bcrypt$ + bcrypt ハッシュ）で保存してください",
					key,
				)
			}
		}
	}

	id := raw.ID
	if id == "" {
		id = key
	}
	name := strings.TrimSpace(raw.Name)
	if name == "" {
		name = key
	}

	return User{
		ID:            id,
		Username:      key,
		Name:          name,
		PasswordHash:  raw.PasswordHash,
		Role:          role,
		Disabled:      raw.Disabled,
		AccessScreens: sanitizeScreens(raw.AccessScreens),
	}, nil
}

// ValidateAllOrFatal は users.toml 全体を読み込み、旧スキーマ・無効 role を
// 1 件でも検出したら log.Fatalf で起動を中断する。起動時の fail-fast 用。
// main.go から **一度だけ** 呼び出すこと。ホットパス（Authenticate / GetUser /
// ListUsers / loadUsers）からは絶対に呼ばないこと。
func (s *UserStore) ValidateAllOrFatal() {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		// 起動時にファイルが無い構成も許容する（後で配布される運用想定）。
		// 警告のみ出して継続する。
		log.Printf("auth: users.toml の読込に失敗（起動時検証スキップ） path=%s err=%v", s.path, err)
		return
	}
	rows, err := decodeUsersFile(raw)
	if err != nil {
		log.Fatalf("[FATAL] users.toml: TOML 解析失敗: %v", err)
	}
	for _, row := range rows {
		if strings.TrimSpace(row.Username) == "" {
			continue
		}
		if _, err := validateAndConvertRaw(row); err != nil {
			log.Fatalf("[FATAL] %v", err)
		}
	}
}

func (s *UserStore) loadUsers() map[string]User {
	s.mu.RLock()
	if len(s.users) > 0 && time.Since(s.loadedAt) < usersCacheTTL {
		out := cloneUsers(s.users)
		s.mu.RUnlock()
		return out
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.users) > 0 && time.Since(s.loadedAt) < usersCacheTTL {
		return cloneUsers(s.users)
	}

	raw, err := os.ReadFile(s.path)
	if err != nil {
		s.loadedAt = time.Now()
		return cloneUsers(s.users)
	}

	rows, err := decodeUsersFile(raw)
	if err != nil {
		s.loadedAt = time.Now()
		return cloneUsers(s.users)
	}

	next := make(map[string]User, len(rows))
	for _, row := range rows {
		userKey := strings.TrimSpace(strings.ToLower(row.Username))
		if userKey == "" {
			continue
		}
		u, err := validateAndConvertRaw(row)
		if err != nil {
			// ホットパスから到達するため fatal にしない。
			// 該当行をスキップし、可能ならキャッシュ済みユーザーを温存する。
			log.Printf("auth: users.toml の行をスキップ user=%q err=%v", userKey, err)
			if cached, ok := s.users[userKey]; ok {
				next[userKey] = cached
			}
			continue
		}
		next[userKey] = u
	}
	s.users = next
	s.loadedAt = time.Now()
	return cloneUsers(next)
}

func (s *UserStore) mutate(fn func(map[string]User) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.loadUsersNoLock()
	if err != nil {
		return err
	}
	if err := fn(users); err != nil {
		return err
	}
	if err := s.saveUsersNoLock(users); err != nil {
		return err
	}
	s.users = cloneUsers(users)
	s.loadedAt = time.Now()
	return nil
}

func (s *UserStore) loadUsersNoLock() (map[string]User, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if len(s.users) > 0 {
			return cloneUsers(s.users), nil
		}
		return map[string]User{}, nil
	}
	rows, err := decodeUsersFile(raw)
	if err != nil {
		return nil, err
	}
	out := make(map[string]User, len(rows))
	for _, row := range rows {
		key := strings.TrimSpace(strings.ToLower(row.Username))
		if key == "" {
			continue
		}
		u, err := validateAndConvertRaw(row)
		if err != nil {
			// ホットパスからの mutate でも fatal は禁止。
			// 既存キャッシュにあれば温存し、無ければ単にスキップ。
			log.Printf("auth: users.toml の行をスキップ user=%q err=%v", key, err)
			if cached, ok := s.users[key]; ok {
				out[key] = cached
			}
			continue
		}
		out[key] = u
	}
	return out, nil
}

func (s *UserStore) saveUsersNoLock(users map[string]User) error {
	type persistedUser struct {
		ID            string   `toml:"id"`
		Username      string   `toml:"username"`
		Name          string   `toml:"name"`
		PasswordHash  string   `toml:"password_hash"`
		Role          string   `toml:"role"`
		Disabled      bool     `toml:"disabled,omitempty"`
		AccessScreens []string `toml:"access_screens,omitempty"`
	}
	rows := make([]persistedUser, 0, len(users))
	for _, u := range users {
		rows = append(rows, persistedUser{
			ID:            u.ID,
			Username:      u.Username,
			Name:          u.Name,
			PasswordHash:  u.PasswordHash,
			Role:          u.Role,
			Disabled:      u.Disabled,
			AccessScreens: sanitizeScreens(u.AccessScreens),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Username < rows[j].Username
	})
	var buf strings.Builder
	enc := toml.NewEncoder(&buf)
	dataFile := struct {
		Users []persistedUser `toml:"users"`
	}{
		Users: rows,
	}
	if err := enc.Encode(dataFile); err != nil {
		return err
	}
	data := []byte(buf.String())
	if len(data) == 0 || data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	return nil
}

func decodeUsersFile(raw []byte) ([]rawUser, error) {
	var doc usersFile
	if _, err := toml.Decode(string(raw), &doc); err != nil {
		return nil, err
	}
	return doc.Users, nil
}

func cloneUsers(src map[string]User) map[string]User {
	dst := make(map[string]User, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func countRole(users map[string]User, role string) int {
	n := 0
	for _, u := range users {
		if u.Role == role {
			n++
		}
	}
	return n
}

func sanitizeScreens(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(src))
	for _, raw := range src {
		screen := NormalizeScreen(raw)
		if screen == "" {
			continue
		}
		if _, ok := seen[screen]; ok {
			continue
		}
		seen[screen] = struct{}{}
		out = append(out, screen)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// bcryptCost は bcrypt のコストパラメータ（GPU 総当たり耐性のため 12 以上）。
const bcryptCost = 12

// HashPassword は users.toml 用のパスワードハッシュを生成する。
// bcrypt（cost=bcryptCost）を使い、方式プレフィックス `bcrypt$` を付与する。
// 注: bcrypt は 72 バイト超を切り捨てるが、管理者パスワード用途では問題ない。
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return "bcrypt$" + string(h), nil
}

// needsPasswordRehash は保存ハッシュが最新方式（bcrypt）でない場合に true を返す。
// 旧 sha256$ などはログイン成功時に再ハッシュして無停止移行する。
func needsPasswordRehash(storedHash string) bool {
	return !strings.HasPrefix(strings.TrimSpace(storedHash), "bcrypt$")
}

// VerifyPassword は users.toml の password_hash を検証する。
// 形式:
//   - bcrypt$<bcrypt-hash>（現行）
//   - sha256$<saltHex>$<hashHex>（旧。ログイン成功時に bcrypt へ再ハッシュ）
//
// plain$ プレフィックスおよびプレフィックスなし平文比較は廃止した（fail-safe）。
// 未知の形式は false を返す。
func VerifyPassword(storedHash, password string) bool {
	storedHash = strings.TrimSpace(storedHash)
	if storedHash == "" {
		return false
	}
	if strings.HasPrefix(storedHash, "bcrypt$") {
		raw := strings.TrimPrefix(storedHash, "bcrypt$")
		return bcrypt.CompareHashAndPassword([]byte(raw), []byte(password)) == nil
	}
	if strings.HasPrefix(storedHash, "sha256$") {
		parts := strings.Split(storedHash, "$")
		if len(parts) != 3 {
			return false
		}
		salt, err := hex.DecodeString(parts[1])
		if err != nil || len(salt) == 0 {
			return false
		}
		expected, err := hex.DecodeString(parts[2])
		if err != nil {
			return false
		}
		sum := sha256.Sum256(append(salt, []byte(":"+password)...))
		if len(expected) != len(sum) {
			return false
		}
		return subtle.ConstantTimeCompare(expected, sum[:]) == 1
	}
	// plain$ / プレフィックスなし平文は廃止。検出したら警告して拒否する。
	if strings.HasPrefix(storedHash, "plain$") {
		log.Printf("auth: rejected legacy plain$ password hash (廃止済み形式). 再設定が必要です")
	} else {
		log.Printf("auth: rejected unknown password hash format")
	}
	return false
}
