package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultDaemonEnvPath(t *testing.T) {
	t.Setenv("HEARTDESK_BASE_DIR", "")
	if got, want := defaultDaemonEnvPath(), filepath.Join("/var/lib/heartdesk", "daemon.env"); got != want {
		t.Errorf("BASE_DIR 未設定: got %q, want %q", got, want)
	}

	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	if got, want := defaultDaemonEnvPath(), filepath.Join(base, "daemon.env"); got != want {
		t.Errorf("BASE_DIR 設定: got %q, want %q", got, want)
	}
}

// loadEnvFile は未設定のキーだけ os.Setenv するので、テスト用キーを確実に未設定にして、後始末で戻す。
func unsetForTest(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	os.Unsetenv(key)
}

func TestLoadDaemonEnvOptional_UsesBaseDir(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	t.Setenv("HEARTDESK_DAEMON_ENV_PATH", "")
	const key = "HEARTDESK_TEST_DAEMON_ENV_KEY"
	unsetForTest(t, key)
	if err := os.WriteFile(filepath.Join(base, "daemon.env"), []byte(key+"=from-base-dir\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := LoadDaemonEnvOptional(); err != nil {
		t.Fatalf("LoadDaemonEnvOptional: %v", err)
	}
	if got := os.Getenv(key); got != "from-base-dir" {
		t.Errorf("BASE_DIR/daemon.env が読まれていない: got %q", got)
	}
}

func TestLoadDaemonEnvOptional_ExplicitPathWins(t *testing.T) {
	base := t.TempDir()
	other := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	const key = "HEARTDESK_TEST_DAEMON_ENV_KEY2"
	unsetForTest(t, key)
	if err := os.WriteFile(filepath.Join(base, "daemon.env"), []byte(key+"=base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	explicit := filepath.Join(other, "custom.env")
	if err := os.WriteFile(explicit, []byte(key+"=explicit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HEARTDESK_DAEMON_ENV_PATH", explicit)
	if err := LoadDaemonEnvOptional(); err != nil {
		t.Fatalf("LoadDaemonEnvOptional: %v", err)
	}
	if got := os.Getenv(key); got != "explicit" {
		t.Errorf("HEARTDESK_DAEMON_ENV_PATH が最優先されていない: got %q", got)
	}
}

func writeMinimalConfig(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[server]\nname = \"basedir-test\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAppConfig_ConfigDirResolution(t *testing.T) {
	t.Run("BASE_DIR/config が使われる", func(t *testing.T) {
		base := t.TempDir()
		t.Setenv("HEARTDESK_BASE_DIR", base)
		t.Setenv("HEARTDESK_CONFIG_DIR", "")
		writeMinimalConfig(t, filepath.Join(base, "config"))
		cfg, err := LoadAppConfig()
		if err != nil {
			t.Fatalf("LoadAppConfig: %v", err)
		}
		if cfg.Server.Name != "basedir-test" {
			t.Errorf("Server.Name = %q", cfg.Server.Name)
		}
		cfg2, err := LoadAppConfigForTenant("")
		if err != nil {
			t.Fatalf("LoadAppConfigForTenant: %v", err)
		}
		if cfg2.Server.Name != "basedir-test" {
			t.Errorf("ForTenant Server.Name = %q", cfg2.Server.Name)
		}
	})

	t.Run("HEARTDESK_CONFIG_DIR が BASE_DIR より優先", func(t *testing.T) {
		base := t.TempDir()
		cfgDir := t.TempDir()
		t.Setenv("HEARTDESK_BASE_DIR", base)
		t.Setenv("HEARTDESK_CONFIG_DIR", cfgDir)
		writeMinimalConfig(t, cfgDir)
		// BASE_DIR/config には何も置かない（そちらが読まれたらエラーになる）
		if _, err := LoadAppConfig(); err != nil {
			t.Fatalf("LoadAppConfig: %v", err)
		}
		if _, err := LoadAppConfigForTenant("default"); err != nil {
			t.Fatalf("LoadAppConfigForTenant: %v", err)
		}
	})

	t.Run("どちらも未設定なら従来の /var/lib/heartdesk/config", func(t *testing.T) {
		t.Setenv("HEARTDESK_BASE_DIR", "")
		t.Setenv("HEARTDESK_CONFIG_DIR", "")
		_, err := LoadAppConfig()
		if err == nil {
			// このマシンに実在して読めた場合。パスの確認はエラー文言でしかできないのでここまで。
			return
		}
		want := filepath.Join("/var/lib/heartdesk", "config", "config.toml")
		if !strings.Contains(err.Error(), want) {
			t.Errorf("エラーに従来のパス %q が含まれない: %v", want, err)
		}
	})
}
