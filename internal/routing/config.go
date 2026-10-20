package routing

import (
	"net/url"
	"regexp"
	"strings"
	"sync"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
)

type Config struct {
	RoutingMode string
	BaseHost    string
	TenantSlug  string
	PathPrefix  string

	MonitorBase          string
	VendorBase           string
	StaticBase           string
	SABIconFile          string
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

func load() Config {
	mode := strings.ToLower(strings.TrimSpace(sab.Env("SAB_ROUTING_MODE")))
	if mode != "path" && mode != "subdomain" {
		mode = "subdomain"
	}

	host := strings.TrimSpace(sab.Env("SAB_BASE_HOST"))
	if host == "" {
		host = ""
	}

	slug := normalizeSlug(sab.Env("SAB_TENANT_SLUG"))
	prefix := ""
	if mode == "path" {
		if slug == "" {
			slug = "sab"
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
		SABIconFile:          normalizeIconFile(sab.Env("SAB_ICON_SAB"), "favicon_sab.svg"),
		MonitorFaviconFile:   normalizeIconFile(sab.Env("SAB_ICON_MONITOR_FAVICON"), "favicon_sab_monitor.svg"),
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

func (c Config) SABIconPath() string {
	return c.StaticBase + "/img/" + c.SABIconFile
}

func (c Config) MonitorFaviconPath() string {
	return c.StaticBase + "/img/" + c.MonitorFaviconFile
}

func (c Config) MonitorHome() string {
	return c.MonitorBase + "/"
}

func (c Config) IsAPIPath(path string) bool {
	return strings.HasPrefix(path, c.MonitorAPIBase+"/") ||
		strings.HasPrefix(path, "/sab/api/") ||
		strings.HasPrefix(path, "/nab/api/")
}

func (c Config) LegacyToCanonical(path string) string {
	type legacy struct {
		from string
		to   string
	}
	m := []legacy{
		{from: "/sab/monitor", to: c.MonitorBase},
		{from: "/sab/admin", to: c.MonitorBase},
		{from: "/sab/user", to: c.MonitorBase}, // 旧 NC User（廃止）→ Monitor へ
		{from: "/sab/static", to: c.StaticBase},
		{from: "/sab/login", to: c.LoginPath},
		{from: "/sab/logout", to: c.LogoutPath},
		{from: "/sab/settings/password", to: c.SettingsPasswordPath},
		{from: "/sab/settings/2fa", to: c.Settings2FAPath},
		{from: "/sab/settings/2fa-reset", to: c.Settings2FAResetPath},
		{from: "/sab/admin/audit-log", to: c.AdminAuditLogPath},
		{from: "/sab/admin/unlock", to: c.AdminUnlockPath},
		{from: "/sab/api/monitor", to: c.MonitorAPIBase},
		{from: "/nab/monitor", to: c.MonitorBase},
		{from: "/nab/admin", to: c.MonitorBase},
		{from: "/nab/user", to: c.MonitorBase}, // 旧 NC User（廃止）→ Monitor へ
		{from: "/nab/api/monitor", to: c.MonitorAPIBase},
	}

	for _, e := range m {
		if path == e.from {
			return e.to
		}
		if strings.HasPrefix(path, e.from+"/") {
			return e.to + strings.TrimPrefix(path, e.from)
		}
	}
	return path
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

	next = c.LegacyToCanonical(next)
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
