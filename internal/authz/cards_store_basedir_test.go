package authz

import (
	"path/filepath"
	"testing"
)

func TestConfigDir_Resolution(t *testing.T) {
	t.Setenv("HEARTDESK_BASE_DIR", "")
	t.Setenv("HEARTDESK_CONFIG_DIR", "")
	if got, want := configDir(), filepath.Join("/var/lib/heartdesk", "config"); got != want {
		t.Errorf("未設定: got %q, want %q", got, want)
	}

	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	if got, want := configDir(), filepath.Join(base, "config"); got != want {
		t.Errorf("BASE_DIR 設定: got %q, want %q", got, want)
	}

	explicit := t.TempDir()
	t.Setenv("HEARTDESK_CONFIG_DIR", explicit)
	if got := configDir(); got != explicit {
		t.Errorf("CONFIG_DIR 優先: got %q, want %q", got, explicit)
	}
}
