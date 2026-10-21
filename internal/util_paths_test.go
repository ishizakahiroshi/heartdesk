package heartdesk

import (
	"path/filepath"
	"testing"
)

func TestPathOrDefault(t *testing.T) {
	t.Setenv("HEARTDESK_BASE_DIR", "")
	if got, want := PathOrDefault("data/x.json"), filepath.Join(DefaultRoot, "data/x.json"); got != want {
		t.Errorf("BASE_DIR 未設定: PathOrDefault = %q, want %q", got, want)
	}

	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	if got, want := PathOrDefault("data/x.json"), filepath.Join(base, "data/x.json"); got != want {
		t.Errorf("BASE_DIR 設定あり: PathOrDefault = %q, want %q", got, want)
	}
}

func TestConfigDir(t *testing.T) {
	t.Setenv("HEARTDESK_CONFIG_DIR", "")
	t.Setenv("HEARTDESK_BASE_DIR", "")
	if got, want := ConfigDir(), filepath.Join(DefaultRoot, "config"); got != want {
		t.Errorf("どちらも未設定: ConfigDir = %q, want %q", got, want)
	}

	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	if got, want := ConfigDir(), filepath.Join(base, "config"); got != want {
		t.Errorf("BASE_DIR のみ: ConfigDir = %q, want %q", got, want)
	}

	cfg := t.TempDir()
	t.Setenv("HEARTDESK_CONFIG_DIR", cfg)
	if got := ConfigDir(); got != cfg {
		t.Errorf("CONFIG_DIR 優先: ConfigDir = %q, want %q", got, cfg)
	}
}
