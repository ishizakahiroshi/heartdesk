package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoginLogPath_BaseDir(t *testing.T) {
	t.Setenv("HEARTDESK_LOGIN_LOG_PATH", "")

	t.Setenv("HEARTDESK_BASE_DIR", "")
	want := filepath.Join("/var/lib/heartdesk", "log", "heartdesk_login_events.jsonl")
	if got := LoginLogPath(); got != want {
		t.Errorf("未設定: got %q, want %q", got, want)
	}
	if got := LoginLogResolvedPath(); got != want {
		t.Errorf("Resolved 未設定: got %q, want %q", got, want)
	}

	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	want = filepath.Join(base, "log", "heartdesk_login_events.jsonl")
	if got := LoginLogResolvedPath(); got != want {
		t.Errorf("BASE_DIR 設定: got %q, want %q", got, want)
	}
}

func TestLoginLogResolvedPath_EnvOverrideWins(t *testing.T) {
	t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
	override := filepath.Join(t.TempDir(), "custom.jsonl")
	t.Setenv("HEARTDESK_LOGIN_LOG_PATH", override)
	if got := LoginLogResolvedPath(); got != override {
		t.Errorf("got %q, want %q", got, override)
	}
}

func TestAppendLoginLog_WritesUnderBaseDir(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	t.Setenv("HEARTDESK_LOGIN_LOG_PATH", "")
	if err := os.MkdirAll(filepath.Join(base, "log"), 0o755); err != nil {
		t.Fatal(err)
	}
	AppendLoginLog(LoginLogEntry{Result: "success", User: "u", IP: "192.0.2.1"})
	if _, err := os.Stat(filepath.Join(base, "log", "heartdesk_login_events.jsonl")); err != nil {
		t.Errorf("BASE_DIR 配下に書かれていない: %v", err)
	}
}
