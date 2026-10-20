package config

import (
	"sync"
)

// C3（per-request-config-reload）: AppConfig のプロセス内キャッシュ Provider。
//
// 従来 AgentReportHandler 等の高頻度経路が毎リクエストで LoadAppConfigForTenant を呼び、
// config.toml / secrets.toml / tenant config / tenant secrets を最大 4 回 DecodeFile し、
// vps/rental の *.agent.toml を filepath.Glob していた。これを tenantID→*AppConfig の
// プロセス内キャッシュに置き換え、ディスク I/O と secrets.toml の毎リクエスト読込露出を解消する。
//
// 設定変更時は ReloadConfigCache() で明示的にキャッシュを破棄する（SIGHUP ハンドラ等から呼ぶ）。

var (
	appConfigCacheMu sync.RWMutex
	appConfigCache   = map[string]*AppConfig{}
)

// CachedAppConfigForTenant は tenantID 向け AppConfig をキャッシュ経由で返す。
// 未キャッシュの場合のみ LoadAppConfigForTenant でロードして保持する。
// 返した *AppConfig は共有されるため呼び出し側は変更してはならない（読み取り専用）。
func CachedAppConfigForTenant(tenantID string) (*AppConfig, error) {
	key := tenantID
	if key == "" {
		key = DefaultTenantID
	}

	appConfigCacheMu.RLock()
	cfg, ok := appConfigCache[key]
	appConfigCacheMu.RUnlock()
	if ok {
		return cfg, nil
	}

	appConfigCacheMu.Lock()
	defer appConfigCacheMu.Unlock()
	// ロック取得中に他 goroutine が埋めた可能性を再確認（double-checked locking）。
	if cfg, ok := appConfigCache[key]; ok {
		return cfg, nil
	}
	loaded, err := LoadAppConfigForTenant(key)
	if err != nil {
		return nil, err
	}
	appConfigCache[key] = loaded
	return loaded, nil
}

// ReloadConfigCache はキャッシュ済み AppConfig を全て破棄する。
// 次回 CachedAppConfigForTenant 呼び出し時に再ロードされる。
// 設定ファイル変更を反映したい場合（SIGHUP 等）に呼ぶ。
func ReloadConfigCache() {
	appConfigCacheMu.Lock()
	appConfigCache = map[string]*AppConfig{}
	appConfigCacheMu.Unlock()
}
