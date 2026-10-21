package main

import (
	"path/filepath"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

func TestResolveDataDir_UnderBaseDir(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_DATA_DIR", "")
	t.Setenv("HEARTDESK_BASE_DIR", base)
	if got, want := resolveDataDir(), filepath.Join(base, "data"); got != want {
		t.Errorf("resolveDataDir() = %q, want %q", got, want)
	}
}

func TestResolveDataDir_UnsetKeepsLegacyPath(t *testing.T) {
	t.Setenv("HEARTDESK_DATA_DIR", "")
	t.Setenv("HEARTDESK_BASE_DIR", "")
	if got, want := resolveDataDir(), filepath.Join(heartdesk.DefaultRoot, "data"); got != want {
		t.Errorf("resolveDataDir() = %q, want %q", got, want)
	}
	if filepath.Separator == '/' {
		if got := resolveDataDir(); got != "/var/lib/heartdesk/data" {
			t.Errorf("resolveDataDir() = %q", got)
		}
	}
}

func TestResolveDataDir_EnvOverrideWins(t *testing.T) {
	t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
	override := t.TempDir()
	t.Setenv("HEARTDESK_DATA_DIR", override)
	if got := resolveDataDir(); got != override {
		t.Errorf("resolveDataDir() = %q, want %q", got, override)
	}
}
