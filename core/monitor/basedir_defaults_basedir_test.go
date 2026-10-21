package monitor

import (
	"path/filepath"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// heartdesk 自身の置き場所の既定が HEARTDESK_BASE_DIR 基準になっていることを確かめる。
// BASE_DIR 未設定のときは従来の /var/lib/heartdesk 配下と同じになる。

func TestBaseDirDefaults_UnderBaseDir(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)

	if got, want := avatarDir(), filepath.Join(base, "data", "avatars"); got != want {
		t.Errorf("avatarDir() = %q, want %q", got, want)
	}
	if got, want := ncStorageCacheFile(nil), filepath.Join(base, "data", "json", "nc_storage_summary.json"); got != want {
		t.Errorf("ncStorageCacheFile(nil) = %q, want %q", got, want)
	}
	if got, want := binDir(), filepath.Join(base, "bin"); got != want {
		t.Errorf("binDir() = %q, want %q", got, want)
	}
	if got, want := scriptCheckAlerts(), filepath.Join(base, "bin", "heartdesk-alerts"); got != want {
		t.Errorf("scriptCheckAlerts() = %q, want %q", got, want)
	}
}

func TestBaseDirDefaults_UnsetKeepsLegacyPaths(t *testing.T) {
	t.Setenv("HEARTDESK_BASE_DIR", "")
	root := heartdesk.DefaultRoot

	if got, want := avatarDir(), filepath.Join(root, "data", "avatars"); got != want {
		t.Errorf("avatarDir() = %q, want %q", got, want)
	}
	if got, want := ncStorageCacheFile(nil), filepath.Join(root, "data", "json", "nc_storage_summary.json"); got != want {
		t.Errorf("ncStorageCacheFile(nil) = %q, want %q", got, want)
	}
	if got, want := binDir(), filepath.Join(root, "bin"); got != want {
		t.Errorf("binDir() = %q, want %q", got, want)
	}
	if got, want := scriptCheckAlerts(), filepath.Join(root, "bin", "heartdesk-alerts"); got != want {
		t.Errorf("scriptCheckAlerts() = %q, want %q", got, want)
	}
	// Linux では従来の絶対パスの文字列そのものになる。
	if filepath.Separator == '/' {
		if got := avatarDir(); got != "/var/lib/heartdesk/data/avatars" {
			t.Errorf("avatarDir() = %q", got)
		}
		if got := scriptCheckAlerts(); got != "/var/lib/heartdesk/bin/heartdesk-alerts" {
			t.Errorf("scriptCheckAlerts() = %q", got)
		}
	}
}

func TestNcStorageCacheFile_ConfigOverrideWins(t *testing.T) {
	t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
	cfg := &config.AppConfig{}
	cfg.NextcloudCache.StorageCacheFile = "  /custom/nc_cache.json  "
	if got, want := ncStorageCacheFile(cfg), "/custom/nc_cache.json"; got != want {
		t.Errorf("ncStorageCacheFile(cfg) = %q, want %q", got, want)
	}
	// 空文字の設定は既定にフォールバックする。
	cfg.NextcloudCache.StorageCacheFile = "   "
	if got := ncStorageCacheFile(cfg); got == "" || got == "/custom/nc_cache.json" {
		t.Errorf("ncStorageCacheFile(blank cfg) = %q, want default", got)
	}
}
