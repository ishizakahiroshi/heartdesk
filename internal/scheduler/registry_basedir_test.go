package scheduler

import (
	"path/filepath"
	"testing"
)

func TestDefaultStateFilePathFollowsBaseDir(t *testing.T) {
	t.Setenv("SCHED_STATE_FILE", "")
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	want := filepath.Join(base, "data", "json", "scheduler_state.json")
	if got := resolveStateFilePath(""); got != want {
		t.Fatalf("resolveStateFilePath(\"\") = %q, want %q", got, want)
	}
}

func TestDefaultStateFilePathWithoutBaseDir(t *testing.T) {
	t.Setenv("SCHED_STATE_FILE", "")
	t.Setenv("HEARTDESK_BASE_DIR", "")
	want := filepath.Join("/var/lib/heartdesk", "data/json/scheduler_state.json")
	if got := resolveStateFilePath(""); got != want {
		t.Fatalf("resolveStateFilePath(\"\") = %q, want %q", got, want)
	}
}

func TestStateFilePathOverridesKeepPriority(t *testing.T) {
	t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
	t.Setenv("SCHED_STATE_FILE", "")
	if got := resolveStateFilePath("/custom/state.json"); got != "/custom/state.json" {
		t.Fatalf("configured path must win over the default, got %q", got)
	}
	t.Setenv("SCHED_STATE_FILE", "/env/state.json")
	if got := resolveStateFilePath("/custom/state.json"); got != "/env/state.json" {
		t.Fatalf("SCHED_STATE_FILE must win over config, got %q", got)
	}
}
