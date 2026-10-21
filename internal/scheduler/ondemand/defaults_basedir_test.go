package ondemand

import (
	"path/filepath"
	"testing"
)

func TestOndemandDefaultPathsFollowBaseDir(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)

	cases := map[string][2]string{
		"defaultAptStateDir":  {defaultAptStateDir(), filepath.Join(base, "data", "json")},
		"defaultAptStatePath": {defaultAptStatePath(), filepath.Join(base, "data", "json", "apt_update_state.json")},
		"defaultAptLogDir":    {defaultAptLogDir(), filepath.Join(base, "data", "log")},
		"defaultBackupLog":    {defaultBackupLogPath(), filepath.Join(base, "data", "logs", "mariadb-backup.log")},
	}
	for name, c := range cases {
		if c[0] != c[1] {
			t.Errorf("%s = %q, want %q", name, c[0], c[1])
		}
	}
}

func TestOndemandDefaultPathsWithoutBaseDir(t *testing.T) {
	t.Setenv("HEARTDESK_BASE_DIR", "")
	root := "/var/lib/heartdesk"

	cases := map[string][2]string{
		"defaultAptStatePath": {defaultAptStatePath(), filepath.Join(root, "data/json/apt_update_state.json")},
		"defaultAptLogDir":    {defaultAptLogDir(), filepath.Join(root, "data/log")},
		"defaultBackupLog":    {defaultBackupLogPath(), filepath.Join(root, "data/logs/mariadb-backup.log")},
	}
	for name, c := range cases {
		if c[0] != c[1] {
			t.Errorf("%s = %q, want %q", name, c[0], c[1])
		}
	}
}
