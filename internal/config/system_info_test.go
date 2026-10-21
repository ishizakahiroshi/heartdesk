package config

import "testing"

func TestBuildSystemInfoAppNameDefault(t *testing.T) {
	cfg := &AppConfig{}
	if got := BuildSystemInfo(cfg, "v0", "a1", "heartdesk", "default", "").AppName; got != "heartdesk" {
		t.Errorf("app_name 未設定: AppName = %q, want heartdesk", got)
	}

	cfg.SystemInfo.AppName = "   "
	if got := BuildSystemInfo(cfg, "v0", "a1", "heartdesk", "default", "").AppName; got != "heartdesk" {
		t.Errorf("app_name が空白のみ: AppName = %q, want heartdesk", got)
	}

	cfg.SystemInfo.AppName = "My Console"
	if got := BuildSystemInfo(cfg, "v0", "a1", "heartdesk", "default", "").AppName; got != "My Console" {
		t.Errorf("app_name 設定あり: AppName = %q, want My Console", got)
	}
}
