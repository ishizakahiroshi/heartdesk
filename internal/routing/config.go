package routing

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

type Config struct {
	RoutingMode string
	BaseHost    string
	TenantSlug  string
	PathPrefix  string

	MonitorBase          string
	VendorBase           string
	StaticBase           string
	IconFile             string
	MonitorFaviconFile   string
	LoginPath            string
	LogoutPath           string
	SettingsPasswordPath string
	Settings2FAPath      string
	Settings2FAResetPath string
	AdminAuditLogPath    string
	AdminUnlockPath      string
	MonitorAPIBase       string
}

var (
	cfgOnce sync.Once
	cfgVal  Config
)

var slugCleaner = regexp.MustCompile(`[^a-z0-9-]+`)
var iconFileCleaner = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func Current() Config {
	cfgOnce.Do(func() {
		cfgVal = load()
	})
	return cfgVal
}

// Configure selects explicit routing before any process-wide consumer uses it.
func Configure(value Config) error {
	configured := false
	cfgOnce.Do(func() { cfgVal = value; configured = true })
	if !configured {
		return fmt.Errorf("routing already initialized")
	}
	return nil
}

func load() Config {
	mode := strings.ToLower(strings.TrimSpace(heartdesk.Env("HEARTDESK_ROUTING_MODE")))
	if mode != "path" && mode != "subdomain" {
		mode = "subdomain"
	}

	host := strings.TrimSpace(heartdesk.Env("HEARTDESK_BASE_HOST"))
	if host == "" {
		host = ""
	}

	slug := normalizeSlug(heartdesk.Env("HEARTDESK_TENANT_SLUG"))
	prefix := ""
	if mode == "path" {
		if slug == "" {
			slug = "heartdesk"
		}
		prefix = "/" + slug
	}

	return Config{
		RoutingMode: mode,
		BaseHost:    host,
		TenantSlug:  slug,
		PathPrefix:  prefix,

		MonitorBase:          prefix + "/monitor",
		VendorBase:           prefix + "/monitor",
		StaticBase:           prefix + "/static",
		IconFile:             normalizeIconFile(heartdesk.Env("HEARTDESK_ICON"), "favicon.svg"),
		MonitorFaviconFile:   normalizeIconFile(heartdesk.Env("HEARTDESK_ICON_MONITOR_FAVICON"), "favicon_monitor.svg"),
		LoginPath:            prefix + "/login",
		LogoutPath:           prefix + "/logout",
		SettingsPasswordPath: prefix + "/settings/password",
		Settings2FAPath:      prefix + "/settings/2fa",
		Settings2FAResetPath: prefix + "/settings/2fa-reset",
		AdminAuditLogPath:    prefix + "/admin/audit-log",
		AdminUnlockPath:      prefix + "/admin/unlock",
		MonitorAPIBase:       prefix + "/api/monitor",
	}
}

func normalizeSlug(in string) string {
	s := strings.ToLower(strings.TrimSpace(in))
	s = slugCleaner.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 20 {
		s = s[:20]
	}
	return s
}

func normalizeIconFile(in, fallback string) string {
	s := strings.TrimSpace(in)
	if s == "" {
		return fallback
	}
	s = strings.ReplaceAll(s, "\\", "")
	s = strings.ReplaceAll(s, "/", "")
	s = iconFileCleaner.ReplaceAllString(s, "")
	if s == "" {
		return fallback
	}
	return s
}

func (c Config) IconPath() string {
	return c.StaticBase + "/img/" + c.IconFile
}

func (c Config) MonitorFaviconPath() string {
	return c.StaticBase + "/img/" + c.MonitorFaviconFile
}

func (c Config) MonitorHome() string {
	return c.MonitorBase + "/"
}

func (c Config) IsAPIPath(path string) bool {
	return strings.HasPrefix(path, c.MonitorAPIBase+"/")
}

func (c Config) SanitizeNext(raw string) string {
	next := strings.TrimSpace(raw)
	if next == "" {
		return c.MonitorHome()
	}
	if decoded, err := url.QueryUnescape(next); err == nil {
		next = decoded
	}
	if strings.Contains(next, "://") || strings.HasPrefix(next, "//") || !strings.HasPrefix(next, "/") {
		return c.MonitorHome()
	}

	if next == c.LoginPath || strings.HasPrefix(next, c.LoginPath+"?") {
		return c.MonitorHome()
	}

	allowed := []string{
		c.MonitorBase,
		c.SettingsPasswordPath,
		c.Settings2FAPath,
		c.Settings2FAResetPath,
		c.AdminAuditLogPath,
		c.AdminUnlockPath,
		c.MonitorAPIBase,
	}
	for _, p := range allowed {
		if next == p || strings.HasPrefix(next, p+"/") || strings.HasPrefix(next, p+"?") {
			return next
		}
	}

	return c.MonitorHome()
}
