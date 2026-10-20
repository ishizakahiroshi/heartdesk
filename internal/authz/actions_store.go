package authz

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

// ActionsTenantsFile は actions_tenants.toml 全体のスキーマ。
type ActionsTenantsFile struct {
	Tenants map[string]ActionsTenantEntry `toml:"tenants"`
}

// ActionsTenantEntry はテナント単位の操作可否。
type ActionsTenantEntry struct {
	// Actions: action ID -> true(許可) / false(禁止)
	// action ID は src/sab/internal/auth/roles.go の actionClasses キーと合わせる。
	Actions map[string]bool `toml:"actions"`
	// Agents: agent_id -> agent固有の操作可否
	Agents map[string]ActionsAgentEntry `toml:"agents"`
}

// ActionsAgentEntry はエージェント単位の操作可否差分。
type ActionsAgentEntry struct {
	Actions map[string]bool `toml:"actions"`
}

// ActionsUserFile は actions_user.toml 全体のスキーマ。
type ActionsUserFile struct {
	Users map[string]ActionsUserEntry `toml:"users"`
}

// ActionsUserEntry はユーザー単位の「追加禁止」指定。
// 上位で許可された action を user が再許可する手段は持たない（deny only）。
type ActionsUserEntry struct {
	Deny []string `toml:"deny"`
}

// LoadActionsTenants は actions_tenants.toml を読み込んで返す。
// ファイル未存在時は空の値を返す（エラーにしない）。
func LoadActionsTenants() (ActionsTenantsFile, error) {
	path := filepath.Join(configDir(), "actions_tenants.toml")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ActionsTenantsFile{}, nil
		}
		return ActionsTenantsFile{}, err
	}
	var doc ActionsTenantsFile
	if _, err := toml.Decode(string(raw), &doc); err != nil {
		return ActionsTenantsFile{}, err
	}
	return doc, nil
}

// LoadActionsUser は actions_user.toml を読み込んで返す。
// ファイル未存在時は空の値を返す（エラーにしない）。
func LoadActionsUser() (ActionsUserFile, error) {
	path := filepath.Join(configDir(), "actions_user.toml")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ActionsUserFile{}, nil
		}
		return ActionsUserFile{}, err
	}
	var doc ActionsUserFile
	if _, err := toml.Decode(string(raw), &doc); err != nil {
		return ActionsUserFile{}, err
	}
	return doc, nil
}

// --- キャッシュ付き読み込み（API 呼び出し判定時に使う想定。C5 で接続予定） ---

var (
	actionsCacheMu         sync.RWMutex
	actionsTenantsCache    *ActionsTenantsFile
	actionsUserCache       *ActionsUserFile
	actionsTenantsLoadedAt time.Time
	actionsUserLoadedAt    time.Time
)

// ActionsTenants はキャッシュ済みの actions_tenants.toml を返す（cardsCacheTTL で失効）。
func ActionsTenants() ActionsTenantsFile {
	actionsCacheMu.RLock()
	if actionsTenantsCache != nil && time.Since(actionsTenantsLoadedAt) < cardsCacheTTL {
		out := *actionsTenantsCache
		actionsCacheMu.RUnlock()
		return out
	}
	actionsCacheMu.RUnlock()

	actionsCacheMu.Lock()
	defer actionsCacheMu.Unlock()
	if actionsTenantsCache != nil && time.Since(actionsTenantsLoadedAt) < cardsCacheTTL {
		return *actionsTenantsCache
	}
	doc, _ := LoadActionsTenants()
	actionsTenantsCache = &doc
	actionsTenantsLoadedAt = time.Now()
	return doc
}

// ActionsUser はキャッシュ済みの actions_user.toml を返す（cardsCacheTTL で失効）。
func ActionsUser() ActionsUserFile {
	actionsCacheMu.RLock()
	if actionsUserCache != nil && time.Since(actionsUserLoadedAt) < cardsCacheTTL {
		out := *actionsUserCache
		actionsCacheMu.RUnlock()
		return out
	}
	actionsCacheMu.RUnlock()

	actionsCacheMu.Lock()
	defer actionsCacheMu.Unlock()
	if actionsUserCache != nil && time.Since(actionsUserLoadedAt) < cardsCacheTTL {
		return *actionsUserCache
	}
	doc, _ := LoadActionsUser()
	actionsUserCache = &doc
	actionsUserLoadedAt = time.Now()
	return doc
}

// ResetActionsCache はキャッシュを破棄する（テスト用）。
func ResetActionsCache() {
	actionsCacheMu.Lock()
	defer actionsCacheMu.Unlock()
	actionsTenantsCache = nil
	actionsUserCache = nil
	actionsTenantsLoadedAt = time.Time{}
	actionsUserLoadedAt = time.Time{}
}
