package routing

import (
	"os"
	"path/filepath"
	"testing"
)

const basedirTenantsTOML = "[[tenants]]\ntenant_id = \"t-basedir\"\ntenant_slug = \"basedir\"\nrouting_mode = \"path\"\nbase_host = \"example.invalid\"\n"

func TestLoadTenants_ConfigDirResolution(t *testing.T) {
	t.Run("BASE_DIR/config/tenants.toml が読まれる", func(t *testing.T) {
		base := t.TempDir()
		t.Setenv("HEARTDESK_BASE_DIR", base)
		t.Setenv("HEARTDESK_CONFIG_DIR", "")
		if err := os.MkdirAll(filepath.Join(base, "config"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "config", "tenants.toml"), []byte(basedirTenantsTOML), 0o600); err != nil {
			t.Fatal(err)
		}
		got := loadTenants()
		if len(got) != 1 || got[0].TenantID != "t-basedir" {
			t.Errorf("loadTenants() = %+v", got)
		}
	})

	t.Run("HEARTDESK_CONFIG_DIR が BASE_DIR より優先", func(t *testing.T) {
		base := t.TempDir()
		cfgDir := t.TempDir()
		t.Setenv("HEARTDESK_BASE_DIR", base)
		t.Setenv("HEARTDESK_CONFIG_DIR", cfgDir)
		if err := os.WriteFile(filepath.Join(cfgDir, "tenants.toml"), []byte(basedirTenantsTOML), 0o600); err != nil {
			t.Fatal(err)
		}
		got := loadTenants()
		if len(got) != 1 || got[0].TenantID != "t-basedir" {
			t.Errorf("loadTenants() = %+v", got)
		}
	})

	t.Run("BASE_DIR に tenants.toml が無ければ空（従来の /var/lib/heartdesk は見ない）", func(t *testing.T) {
		t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
		t.Setenv("HEARTDESK_CONFIG_DIR", "")
		if got := loadTenants(); len(got) != 0 {
			t.Errorf("loadTenants() = %+v, want empty", got)
		}
	})
}
