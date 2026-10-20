package routing

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/ishizakahiroshi/heartdesk/internal"
)

// TenantConfig は tenants.toml の各テナントエントリ。
// カード表示ポリシーは config/cards_tenants.toml 側に集約済み（C5 で分離）。
type TenantConfig struct {
	TenantID    string `toml:"tenant_id"`
	Name        string `toml:"name"`
	TenantSlug  string `toml:"tenant_slug"`
	RoutingMode string `toml:"routing_mode"`
	BaseHost    string `toml:"base_host"`
	// Modules は有効化されているモジュール一覧（例: ["nextcloud", "vendor"]）。
	// 省略時は空スライス扱い（モジュール依存カードは非表示）。
	Modules []string `toml:"modules"`
}

// PublicHost はテナントの公開ホスト名を返す。
// サブドメイン方式は "<tenant_slug>.<base_host>"、パス方式は base_host そのもの。
// base_host だけではサブドメイン方式のホストにならない（例: slug "drive" のテナント）。
// 組み立てられないときは空文字を返す。
func (t TenantConfig) PublicHost() string {
	base := strings.ToLower(strings.TrimSpace(t.BaseHost))
	if base == "" {
		return ""
	}
	if strings.EqualFold(strings.TrimSpace(t.RoutingMode), "subdomain") {
		slug := strings.ToLower(strings.TrimSpace(t.TenantSlug))
		if slug == "" {
			return ""
		}
		return slug + "." + base
	}
	return base
}

type tenantsFile struct {
	Tenants []TenantConfig `toml:"tenants"`
}

var (
	tenantsOnce sync.Once
	tenantsVal  []TenantConfig
)

// AllTenants は tenants.toml を一度だけ読み込み、全テナント一覧を返す。
// ファイルが存在しない場合は空スライスを返す。
func AllTenants() []TenantConfig {
	tenantsOnce.Do(func() {
		tenantsVal = loadTenants()
	})
	return tenantsVal
}

func loadTenants() []TenantConfig {
	dir := strings.TrimSpace(heartdesk.Env("HEARTDESK_CONFIG_DIR"))
	if dir == "" {
		dir = "/var/lib/heartdesk/config"
	}
	path := filepath.Join(dir, "tenants.toml")

	data, err := os.ReadFile(path)
	if err != nil {
		// ファイルなしは想定内（単一テナント環境等）
		return nil
	}

	var tf tenantsFile
	if _, err := toml.Decode(string(data), &tf); err != nil {
		return nil
	}
	return tf.Tenants
}

// GetTenantBySlug はスラッグでテナントを検索する。見つからなければ nil を返す。
func GetTenantBySlug(slug string) *TenantConfig {
	all := AllTenants()
	for i, t := range all {
		if t.TenantSlug == slug {
			return &all[i]
		}
	}
	return nil
}

// GetTenantByID はテナントIDでテナントを検索する。見つからなければ nil を返す。
func GetTenantByID(id string) *TenantConfig {
	all := AllTenants()
	for i, t := range all {
		if t.TenantID == id {
			return &all[i]
		}
	}
	return nil
}

// GetTenantByRequest はリクエストのHostヘッダーまたはURLパスプレフィックスからテナントを特定する。
// サブドメイン方式: Host が "<slug>.<base_host>" に一致するテナントを返す。
// パス方式: URL の先頭パスセグメントが tenant_slug に一致するテナントを返す。
// 見つからなければ nil を返す。
func GetTenantByRequest(r *http.Request) *TenantConfig {
	host := strings.ToLower(strings.SplitN(r.Host, ":", 2)[0])
	all := AllTenants()
	for i, t := range all {
		switch strings.ToLower(t.RoutingMode) {
		case "subdomain":
			if expected := t.PublicHost(); expected != "" && host == expected {
				return &all[i]
			}
		case "path":
			seg := pathFirstSegment(r.URL.Path)
			if seg != "" && seg == strings.ToLower(t.TenantSlug) {
				return &all[i]
			}
		}
	}
	return nil
}

func pathFirstSegment(path string) string {
	path = strings.TrimPrefix(path, "/")
	if idx := strings.Index(path, "/"); idx >= 0 {
		return path[:idx]
	}
	return path
}
