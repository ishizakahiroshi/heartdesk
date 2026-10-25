package app

import (
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/core/monitor"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/authz"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
	"github.com/ishizakahiroshi/heartdesk/internal/scheduler"
)

type Extensions = monitor.Extensions
type Endpoint = monitor.Endpoint
type Card = monitor.CardExtension
type CardMeta = navmeta.MonitorCardMeta
type RequestContext = monitor.RequestContext
type AgentReport = monitor.AgentReport
type User = auth.User
type SessionManager = auth.SessionManager
type UserStore = auth.UserStore

func DefaultSessionManager() *SessionManager       { return auth.DefaultSessionManager() }
func DefaultStore() *UserStore                     { return auth.DefaultStore() }
func HashPassword(password string) (string, error) { return auth.HashPassword(password) }
func VerifyPassword(hash, password string) bool    { return auth.VerifyPassword(hash, password) }
func VerifyCSRF(r *http.Request) error             { return auth.VerifyCSRF(r) }
func TrustedClientIP(r *http.Request) string       { return auth.TrustedClientIP(r) }
func CanUseCard(session Session, cardID string) bool {
	cardID = authz.CanonicalCardID(cardID)
	modes := authz.CanonicalCardModes(session.CardModes)
	for _, id := range navmeta.AllCardIDs() {
		if id == cardID {
			return !strings.EqualFold(strings.TrimSpace(modes[id]), "hidden")
		}
	}
	return false
}

func Jobs() []Job {
	var jobs []Job
	for _, def := range scheduler.ListJobs() {
		jobs = append(jobs, *def)
	}
	return jobs
}

// Route uses either shared session-screen authentication or an explicit
// independent authenticator (for example a Bearer/IP gate). One is required.
type Route struct {
	Pattern, Screen, Component string
	Methods                    []string
	Authenticate               func(http.ResponseWriter, *http.Request) bool
	Handler                    http.Handler
}

func validateCardAliasTargets(aliases map[string]string, extensions Extensions) error {
	known := map[string]bool{}
	for _, id := range navmeta.AllCardIDs() {
		known[id] = true
	}
	for _, card := range extensions.Cards {
		known[card.Meta.ID] = true
	}
	normalized := map[string]string{}
	for key, target := range aliases {
		normalized[strings.TrimSpace(key)] = strings.TrimSpace(target)
	}
	for key, target := range normalized {
		if known[key] {
			return fmt.Errorf("app: card alias replaces an existing card identity")
		}
		for normalized[target] != "" {
			target = normalized[target]
		}
		if !known[target] {
			return fmt.Errorf("app: card alias target is not registered")
		}
	}
	return nil
}

func attachRoutes(mux *http.ServeMux, rt *Runtime, routes []Route) error {
	seen := map[string]bool{}
	for _, route := range routes {
		clean := path.Clean(route.Pattern)
		if route.Pattern == "" || !strings.HasPrefix(route.Pattern, "/") || strings.ContainsAny(route.Pattern, "?#{} ") || strings.TrimSuffix(route.Pattern, "/") != clean || route.Handler == nil || seen[route.Pattern] || route.Screen == "" && route.Authenticate == nil {
			return fmt.Errorf("app: invalid or duplicate route %q", route.Pattern)
		}
		seen[route.Pattern] = true
		for _, standard := range standardRoutePatterns(rt.routes) {
			if route.Pattern == standard || strings.HasSuffix(route.Pattern, "/") && strings.HasPrefix(standard, route.Pattern) || strings.HasSuffix(standard, "/") && strings.HasPrefix(route.Pattern, standard) {
				return fmt.Errorf("app: route overlaps standard route %q", route.Pattern)
			}
		}
		for pattern := range seen {
			if pattern != route.Pattern && (strings.HasSuffix(pattern, "/") && strings.HasPrefix(route.Pattern, pattern) || strings.HasSuffix(route.Pattern, "/") && strings.HasPrefix(pattern, route.Pattern)) {
				return fmt.Errorf("app: overlapping routes")
			}
		}
		request, _ := http.NewRequest(http.MethodGet, "http://example.com"+route.Pattern, nil)
		_, pattern := mux.Handler(request)
		fallback := rt.routes.PathPrefix != "" && pattern == rt.routes.PathPrefix+"/" && route.Pattern != rt.routes.PathPrefix && route.Pattern != rt.routes.PathPrefix+"/"
		if pattern != "" && !fallback {
			return fmt.Errorf("app: route shadows standard route %q", route.Pattern)
		}
	}
	for _, route := range routes {
		entry := route
		handler := entry.Handler
		if entry.Screen != "" {
			handler = middleware.RequireScreen(auth.Screen(entry.Screen))(handler)
		}
		final := handler
		mux.Handle(entry.Pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(entry.Methods) > 0 {
				allowed := false
				for _, method := range entry.Methods {
					allowed = allowed || r.Method == method
				}
				if !allowed {
					w.Header().Set("Allow", strings.Join(entry.Methods, ", "))
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
			}
			if entry.Component != "" && !rt.config.ComponentEnabled(entry.Component) {
				http.NotFound(w, r)
				return
			}
			if entry.Authenticate != nil && !entry.Authenticate(w, r) {
				return
			}
			final.ServeHTTP(w, r)
		}))
	}
	return nil
}

func standardRoutePatterns(c RoutingConfig) []string {
	return []string{c.StaticBase + "/", c.MonitorBase + "/", c.MonitorBase, c.MonitorAPIBase + "/services", "/healthz", "/api/agent/report", "/api/license/verify", "/api/license/heartbeat", c.LoginPath, c.LoginPath + "/nc", c.LogoutPath, c.SettingsPasswordPath, c.Settings2FAPath, c.Settings2FAResetPath, c.AdminAuditLogPath, c.AdminUnlockPath}
}

func SessionFromRequest(r *http.Request) (Session, bool) {
	return auth.DefaultSessionManager().SessionFromRequest(r)
}
func ActionAllowed(actions map[string]bool, role, key string) bool {
	return auth.ActionAllowed(actions, role, key)
}
func SessionActionAllowed(session Session, key string) bool {
	return auth.ActionAllowed(session.ActionPermissions, session.Role, key)
}

func (r *Runtime) Config() *Config       { return r.config }
func (r *Runtime) Routes() RoutingConfig { return r.routes }
func (r *Runtime) Context(rq *http.Request) *RequestContext {
	if r.monitor == nil {
		return &RequestContext{Config: r.config, Routes: r.routes}
	}
	return r.monitor.ExtensionContext(rq)
}

func cloneExtensions(original Extensions) Extensions {
	ext := original
	ext.Cards = append([]Card(nil), original.Cards...)
	for i := range ext.Cards {
		c := &ext.Cards[i]
		c.Screens = append([]string(nil), c.Screens...)
		c.Capabilities = append([]string(nil), c.Capabilities...)
		c.Exports = append([]string(nil), c.Exports...)
		c.AllActions = append([]string(nil), c.AllActions...)
		c.AnyActions = append([]string(nil), c.AnyActions...)
	}
	copyEndpoints := func(src []Endpoint) []Endpoint {
		dst := append([]Endpoint(nil), src...)
		for i := range dst {
			dst[i].AllActions = append([]string(nil), src[i].AllActions...)
			dst[i].AnyActions = append([]string(nil), src[i].AnyActions...)
		}
		return dst
	}
	ext.APIs = copyEndpoints(original.APIs)
	ext.Actions = copyEndpoints(original.Actions)
	ext.Exports = copyEndpoints(original.Exports)
	return ext
}
