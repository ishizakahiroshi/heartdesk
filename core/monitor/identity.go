package monitor

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/ishizakahiroshi/heartdesk/internal/authz"
)

// MonitorIdentityConfig names the visible application and its pre-existing
// browser preferences and exported wire fields. Values are fixed at startup.
type MonitorIdentityConfig struct {
	AppName, Subtitle, StorageNamespace, ThemeStorageKey                              string
	LoginLogAppName, AdminLoginLogAppName, LoginHistorySourceKey                      string
	LoginHistoryExportBasename, LoginHistoryArchiveFilename, LoginHistoryArchiveLabel string
	AuditAppTrustedJSONKey                                                            string
}

var monitorIdentity atomic.Pointer[MonitorIdentityConfig]
var identityToken = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
var identityJSONKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func currentCardAliases() map[string]string { return authz.ConfiguredCardAliases() }

func resolvedMonitorIdentity(input *MonitorIdentityConfig) (MonitorIdentityConfig, error) {
	cfg := MonitorIdentityConfig{"heartdesk", "server dashboard", "heartdesk", "heartdesk_theme", "heartdesk_monitor", "heartdesk_admin", "heartdesk", "login_history", "login_history.txt", "heartdesk ログイン履歴", "excluded_app_trusted"}
	if input != nil {
		targets := []*string{&cfg.AppName, &cfg.Subtitle, &cfg.StorageNamespace, &cfg.ThemeStorageKey, &cfg.LoginLogAppName, &cfg.AdminLoginLogAppName, &cfg.LoginHistorySourceKey, &cfg.LoginHistoryExportBasename, &cfg.LoginHistoryArchiveFilename, &cfg.LoginHistoryArchiveLabel, &cfg.AuditAppTrustedJSONKey}
		values := []string{input.AppName, input.Subtitle, input.StorageNamespace, input.ThemeStorageKey, input.LoginLogAppName, input.AdminLoginLogAppName, input.LoginHistorySourceKey, input.LoginHistoryExportBasename, input.LoginHistoryArchiveFilename, input.LoginHistoryArchiveLabel, input.AuditAppTrustedJSONKey}
		for i, value := range values {
			if value != "" {
				*targets[i] = value
			}
		}
	}
	for _, value := range []string{cfg.AppName, cfg.Subtitle, cfg.LoginHistoryArchiveLabel} {
		if strings.ContainsAny(value, "\x00\r\n") {
			return cfg, fmt.Errorf("invalid monitor identity text")
		}
	}
	for _, value := range []string{cfg.StorageNamespace, cfg.ThemeStorageKey, cfg.LoginHistoryExportBasename, cfg.LoginHistoryArchiveFilename} {
		if !identityToken.MatchString(value) || value == "." || value == ".." {
			return cfg, fmt.Errorf("invalid monitor identity name")
		}
	}
	for _, value := range []string{cfg.LoginLogAppName, cfg.AdminLoginLogAppName, cfg.LoginHistorySourceKey, cfg.AuditAppTrustedJSONKey} {
		if !identityJSONKey.MatchString(value) || value == "__proto__" || value == "constructor" || value == "prototype" {
			return cfg, fmt.Errorf("invalid monitor wire key")
		}
	}
	if cfg.LoginHistorySourceKey == "phpmyadmin" {
		return cfg, fmt.Errorf("monitor wire key collides with another source")
	}
	if cfg.LoginLogAppName == cfg.AdminLoginLogAppName {
		return cfg, fmt.Errorf("monitor login application identities collide")
	}
	for _, reserved := range []string{"ssh", "nextcloud", "phpmyadmin"} {
		if cfg.LoginLogAppName == reserved || cfg.AdminLoginLogAppName == reserved {
			return cfg, fmt.Errorf("monitor login identity collides with another application")
		}
	}
	for _, reserved := range []string{"readme.txt", "fail2ban_status.txt", "ssh_login_history.txt", "phpmyadmin_login.txt", "nc_login_history.txt", "threat_score.csv", "nc_high_score.csv", "geoip_cache.csv", "managed_ips.json"} {
		if strings.EqualFold(cfg.LoginHistoryArchiveFilename, reserved) {
			return cfg, fmt.Errorf("monitor archive filename collides with another export")
		}
	}
	if cfg.AuditAppTrustedJSONKey != "excluded_app_trusted" {
		for _, reserved := range []string{"window_min", "total_recent", "total_prev", "excluded_internal_noise", "excluded_lexicon_noise", "log_levels"} {
			if cfg.AuditAppTrustedJSONKey == reserved {
				return cfg, fmt.Errorf("monitor audit key collision")
			}
		}
	}
	return cfg, nil
}

func ValidateMonitorIdentity(input *MonitorIdentityConfig) error {
	_, err := resolvedMonitorIdentity(input)
	return err
}
func ConfigureMonitorIdentity(input *MonitorIdentityConfig) error {
	cfg, err := resolvedMonitorIdentity(input)
	if err != nil {
		return err
	}
	monitorIdentity.Store(&cfg)
	return nil
}
func CurrentMonitorIdentity() MonitorIdentityConfig {
	if cfg := monitorIdentity.Load(); cfg != nil {
		return *cfg
	}
	cfg, _ := resolvedMonitorIdentity(nil)
	return cfg
}

func (value NginxLoginHistoriesResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{CurrentMonitorIdentity().LoginHistorySourceKey: value.Heartdesk, "phpmyadmin": value.PhpMyAdmin})
}

func (value AuditAnomalySummary) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{"window_min": value.WindowMin, "total_recent": value.TotalRecent, "total_prev": value.TotalPrev, CurrentMonitorIdentity().AuditAppTrustedJSONKey: value.ExcludedAppTrusted, "excluded_internal_noise": value.ExcludedInternalNoise, "excluded_lexicon_noise": value.ExcludedLexiconNoise, "log_levels": value.LogLevels})
}
