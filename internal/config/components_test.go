package config

import (
	"path/filepath"
	"testing"
)

// TestComponentEnabledDefaults は
// 「未設定・nil は既定で有効」「明示 false は尊重」「名前は小文字正規化して比較」を確認する。
func TestComponentEnabledDefaults(t *testing.T) {
	t.Run("nil cfg defaults to enabled", func(t *testing.T) {
		var cfg *AppConfig
		if !cfg.ComponentEnabled("example_module") {
			t.Fatal("nil *AppConfig should treat unknown component as enabled")
		}
	})

	t.Run("unset Components map defaults to enabled", func(t *testing.T) {
		cfg := &AppConfig{}
		if !cfg.ComponentEnabled("example_module") {
			t.Fatal("unset Components map should treat component as enabled")
		}
	})

	t.Run("unlisted component key defaults to enabled", func(t *testing.T) {
		cfg := &AppConfig{Components: map[string]bool{"other": false}}
		if !cfg.ComponentEnabled("example_module") {
			t.Fatal("component not present in map should default to enabled")
		}
	})

	t.Run("explicit false is respected", func(t *testing.T) {
		cfg := &AppConfig{Components: map[string]bool{"example_module": false}}
		if cfg.ComponentEnabled("example_module") {
			t.Fatal("explicit Components[example_module]=false must be respected")
		}
	})

	t.Run("explicit true is respected", func(t *testing.T) {
		cfg := &AppConfig{Components: map[string]bool{"example_module": true}}
		if !cfg.ComponentEnabled("example_module") {
			t.Fatal("explicit Components[example_module]=true must be respected")
		}
	})

	t.Run("name is normalized to lowercase with trimmed space", func(t *testing.T) {
		cfg := &AppConfig{Components: map[string]bool{"example_module": false}}
		if cfg.ComponentEnabled(" Example_Module ") {
			t.Fatal("component name lookup should normalize case/whitespace")
		}
	})
}

// TestComponentsMergePerKeyAcrossLayers は LoadAppConfigForTenant の重ね読み
// （グローバル config → グローバル secrets → テナント config → テナント secrets）で、
// Components map がキー単位にマージされる（他コンポーネントを巻き込まずに 1 個だけ
// 上書きできる）ことを確認する。BurntSushi/toml は同一 map フィールドへの複数回デコードを
// 既存キー上書き + 新規キー追加でマージする（他キー保持）ため、テナント層で
// example_module だけを false にしても、グローバル層で有効な他コンポーネントは残る。
func TestComponentsMergePerKeyAcrossLayers(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SAB_CONFIG_DIR", dir)

	writeTestFile(t, filepath.Join(dir, "config.toml"), `
[components]
example_module = true
other_component = true
`)
	writeTestFile(t, filepath.Join(dir, "tenants", "alpha", "config.toml"), `
[components]
example_module = false
`)

	cfg, err := LoadAppConfigForTenant("alpha")
	if err != nil {
		t.Fatalf("LoadAppConfigForTenant failed: %v", err)
	}
	if cfg.ComponentEnabled("example_module") {
		t.Fatal("tenant layer should override example_module to disabled")
	}
	if !cfg.ComponentEnabled("other_component") {
		t.Fatal("global layer key not touched by tenant layer must remain enabled (per-key merge)")
	}

	// テナント層の上書きを受けない別テナントは、グローバル既定のまま有効であること。
	cfgOther, err := LoadAppConfigForTenant("beta")
	if err != nil {
		t.Fatalf("LoadAppConfigForTenant(beta) failed: %v", err)
	}
	if !cfgOther.ComponentEnabled("example_module") {
		t.Fatal("tenant without an override must keep the global default (enabled)")
	}
}
