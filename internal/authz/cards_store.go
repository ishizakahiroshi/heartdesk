package authz

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

// cardsCacheTTL は authz カードキャッシュの有効期限。
// 外部からの TOML 編集を再起動なしで（最大この時間後に）反映させる。
const cardsCacheTTL = 60 * time.Second

// CardsTenantsFile は cards_tenants.toml 全体のスキーマ。
type CardsTenantsFile struct {
	Defaults CardsDefaults               `toml:"defaults"`
	Tenants  map[string]CardsTenantEntry `toml:"tenants"`
}

// CardsDefaults は cards_tenants.toml の [defaults] セクション。
type CardsDefaults struct {
	// DefaultMode: カードIDが tenant/agent どちらにも定義されていない場合の既定モード。
	// 未指定時は "full"。
	DefaultMode string `toml:"default_mode"`
}

// CardsTenantEntry はテナント単位のカード表示設定。
type CardsTenantEntry struct {
	// Cards: カードID -> "full" | "summary" | "hidden"
	Cards map[string]string `toml:"cards"`
	// ChildCards: 親カードID -> 子カードID -> "full" | "summary" | "hidden"
	ChildCards map[string]map[string]string `toml:"child_cards"`
	// Agents: agent_id -> agent固有のカード設定
	Agents map[string]CardsAgentEntry `toml:"agents"`
}

// CardsAgentEntry はエージェント単位のカード表示差分。
type CardsAgentEntry struct {
	Cards      map[string]string            `toml:"cards"`
	ChildCards map[string]map[string]string `toml:"child_cards"`
}

// CardsUserFile は cards_user.toml 全体のスキーマ。
type CardsUserFile struct {
	Users map[string]CardsUserEntry `toml:"users"`
}

// CardsUserEntry はユーザー単位の「追加非表示」指定。
// 上位で hidden のものを復活させる手段は持たない（hide only）。
type CardsUserEntry struct {
	HideCards      []string            `toml:"hide_cards"`
	HideChildCards map[string][]string `toml:"hide_child_cards"`
}

// LoadCardsTenants は cards_tenants.toml を読み込んで返す。
// ファイル未存在時は空の値を返す（エラーにしない）。
func LoadCardsTenants() (CardsTenantsFile, error) {
	path := filepath.Join(configDir(), "cards_tenants.toml")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return CardsTenantsFile{}, nil
		}
		return CardsTenantsFile{}, err
	}
	var doc CardsTenantsFile
	if _, err := toml.Decode(string(raw), &doc); err != nil {
		return CardsTenantsFile{}, err
	}
	return doc, nil
}

// LoadCardsUser は cards_user.toml を読み込んで返す。
// ファイル未存在時は空の値を返す（エラーにしない）。
func LoadCardsUser() (CardsUserFile, error) {
	path := filepath.Join(configDir(), "cards_user.toml")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return CardsUserFile{}, nil
		}
		return CardsUserFile{}, err
	}
	var doc CardsUserFile
	if _, err := toml.Decode(string(raw), &doc); err != nil {
		return CardsUserFile{}, err
	}
	return doc, nil
}

// configDir は HEARTDESK_CONFIG_DIR を返す。未設定時は /var/lib/heartdesk/config。
func configDir() string {
	if v := strings.TrimSpace(heartdesk.Env("HEARTDESK_CONFIG_DIR")); v != "" {
		return v
	}
	return "/var/lib/heartdesk/config"
}

// --- キャッシュ付き読み込み（session 生成時に使う想定） ---

var (
	cardsCacheMu         sync.RWMutex
	cardsTenantsCache    *CardsTenantsFile
	cardsUserCache       *CardsUserFile
	cardsTenantsLoadedAt time.Time
	cardsUserLoadedAt    time.Time
)

// CardsTenants はキャッシュ済みの cards_tenants.toml を返す。
// 初回アクセス時に読み込み、cardsCacheTTL 経過後に再読み込みする。読み込み失敗時も空の値を返す。
func CardsTenants() CardsTenantsFile {
	cardsCacheMu.RLock()
	if cardsTenantsCache != nil && time.Since(cardsTenantsLoadedAt) < cardsCacheTTL {
		out := *cardsTenantsCache
		cardsCacheMu.RUnlock()
		return out
	}
	cardsCacheMu.RUnlock()

	cardsCacheMu.Lock()
	defer cardsCacheMu.Unlock()
	if cardsTenantsCache != nil && time.Since(cardsTenantsLoadedAt) < cardsCacheTTL {
		return *cardsTenantsCache
	}
	doc, _ := LoadCardsTenants()
	cardsTenantsCache = &doc
	cardsTenantsLoadedAt = time.Now()
	return doc
}

// CardsUser はキャッシュ済みの cards_user.toml を返す。
func CardsUser() CardsUserFile {
	cardsCacheMu.RLock()
	if cardsUserCache != nil && time.Since(cardsUserLoadedAt) < cardsCacheTTL {
		out := *cardsUserCache
		cardsCacheMu.RUnlock()
		return out
	}
	cardsCacheMu.RUnlock()

	cardsCacheMu.Lock()
	defer cardsCacheMu.Unlock()
	if cardsUserCache != nil && time.Since(cardsUserLoadedAt) < cardsCacheTTL {
		return *cardsUserCache
	}
	doc, _ := LoadCardsUser()
	cardsUserCache = &doc
	cardsUserLoadedAt = time.Now()
	return doc
}

// ResetCardsCache はキャッシュを破棄する（テスト用）。
func ResetCardsCache() {
	cardsCacheMu.Lock()
	defer cardsCacheMu.Unlock()
	cardsTenantsCache = nil
	cardsUserCache = nil
	cardsTenantsLoadedAt = time.Time{}
	cardsUserLoadedAt = time.Time{}
}
