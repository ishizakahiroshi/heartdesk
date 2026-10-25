package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
	"github.com/ishizakahiroshi/heartdesk/internal/scheduler"
)

// RequestContext exposes shared read-only runtime state to application hooks.
type RequestContext struct {
	Config              *config.AppConfig
	Routes              routing.Config
	SystemInfo          config.SystemInfoData
	Session             auth.Session
	AgentID, RawAgentID string
	Render              func(string, interface{}) (template.HTML, error)
}

// Endpoint is called after the shared screen/card/component/tenant/agent gates.
// AllActions and AnyActions add permission checks; they never replace the gates.
type Endpoint struct {
	Name, CardID, Screen, Component string
	ReadOnly                        bool
	AliasFor                        string
	AllActions, AnyActions          []string
	Authorize                       func(*http.Request, *RequestContext) bool
	Handler                         func(http.ResponseWriter, *http.Request, *RequestContext)
	kind                            string
}

type CardExtension struct {
	// ClientOnly keeps initial rendering as the standard empty card shell; Data
	// is evaluated by the authenticated card-refresh endpoint only.
	ClientOnly              bool
	Meta                    navmeta.MonitorCardMeta
	Label, Group, Component string
	Order                   int
	Screens, Capabilities   []string
	AllActions, AnyActions  []string
	Authorize               func(*http.Request, *RequestContext) bool
	Data                    func(*RequestContext) (interface{}, error)
	Exports                 []string
}

type Extensions struct {
	Cards                  []CardExtension
	APIs, Actions, Exports []Endpoint
}

var extensionRegistry Extensions
var extensionsConfigured bool

// ValidateExtensions rejects collisions before any registration is changed.
func ValidateExtensions(ext Extensions) error {
	cards := map[string]bool{}
	keys := map[string]bool{}
	apis := map[string]bool{}
	for _, id := range navmeta.AllCardIDs() {
		cards[id] = true
	}
	for key, id := range navmeta.MonitorCardIDs() {
		keys[key] = true
		_ = id
	}
	for _, api := range navmeta.MonitorAPIByCardID() {
		apis[api] = true
	}
	for _, c := range ext.Cards {
		if c.Meta.ID == "" || c.Meta.Key == "" || c.Meta.API == "" || cards[c.Meta.ID] || keys[c.Meta.Key] || apis[c.Meta.API] {
			return fmt.Errorf("invalid or duplicate card %q", c.Meta.ID)
		}
		if c.Meta.JSModule != "" && (!fs.ValidPath(c.Meta.JSModule) || strings.Contains(c.Meta.JSModule, "\\")) {
			return fmt.Errorf("invalid card module path")
		}
		if builtinAPICollision(c.Meta.API) {
			return fmt.Errorf("card API collision %q", c.Meta.API)
		}
		cards[c.Meta.ID] = true
		keys[c.Meta.Key] = true
		apis[c.Meta.API] = true
	}
	for kind, list := range map[string][]Endpoint{"API": ext.APIs, "action": ext.Actions, "export": ext.Exports} {
		seen := map[string]bool{}
		for _, e := range list {
			if e.Name == "" || (e.Handler == nil && e.AliasFor == "") || e.CardID == "" || !cards[e.CardID] || seen[e.Name] {
				return fmt.Errorf("invalid or duplicate %s %q", kind, e.Name)
			}
			seen[e.Name] = true
			if e.AliasFor != "" && (e.Handler != nil || !builtinAliasTarget(kind, e.AliasFor)) {
				return fmt.Errorf("invalid %s alias %q", kind, e.Name)
			}
			if kind == "API" {
				if builtinAPICollision(e.Name) {
					return fmt.Errorf("API collision %q", e.Name)
				}
			}
			if kind == "action" {
				_, schedulerAction := scheduler.ResolveOnDemandJobID(e.Name)
				if builtinActionNames[e.Name] || e.Name == "upload_avatar" || schedulerAction {
					return fmt.Errorf("action collision %q", e.Name)
				}
			}
			if kind == "export" && hasExportHandler(e.Name) {
				return fmt.Errorf("export collision %q", e.Name)
			}
		}
	}
	return nil
}

func builtinAPICollision(api string) bool {
	if _, known := navmeta.MonitorCardByAPIKey(api); known {
		return true
	}
	if isVendorAPI(api) {
		switch api {
		case "vendor_dashboard", "vendor_tenants", "vendor_agents", "vendor_license_audit", "vendor_licenses", "vendor_license_offline", "vendor_license_rotation", "vendor_nc_overview", "vendor_audit_log", "vendor_server_health":
			return true
		}
		return false
	}
	_, known := resolveCardIDForAPI(api)
	return known
}

func builtinAliasTarget(kind, name string) bool {
	switch kind {
	case "action":
		return builtinActionNames[name]
	case "export":
		_, ok := exportHandlers[name]
		return ok
	case "API":
		if monitorSimpleAPIByName[name] != nil || agentSimpleAPIByName[name] != nil || vendorOnlySimpleAPIByName[name] != nil {
			return true
		}
		// These are the concrete built-in switch cases, not the broader registry
		// namespace (which can also contain application extensions).
		switch name {
		case "agent_overview", "agent_memo", "nc_storage", "r2_metrics", "backups", "alert_rules", "disk", "services", "ssl", "agent_status", "resource_graph", "nginx_log", "nginx_url_detail", "ban_heatmap_cell", "honeypot_heatmap_cell", "honeypot_access", "honeypot_all", "nc4xx_access", "threat_score_history", "threat_event_history", "search_ip", "vendor_dashboard", "vendor_tenants", "vendor_agents", "vendor_license_audit", "vendor_licenses", "vendor_license_offline", "vendor_license_rotation", "vendor_nc_overview", "vendor_audit_log", "vendor_server_health":
			return true
		}
	}
	return false
}

func endpointsWithKind(input []Endpoint, kind string) []Endpoint {
	out := append([]Endpoint(nil), input...)
	for i := range out {
		out[i].kind = kind
	}
	return out
}

// ConfigureExtensions is a startup-only operation owned by app.New.
func ConfigureExtensions(ext Extensions) error {
	if extensionsConfigured {
		return fmt.Errorf("monitor extensions already configured")
	}
	if err := ValidateExtensions(ext); err != nil {
		return err
	}
	for _, c := range ext.Cards {
		navmeta.RegisterCard(c.Meta, c.Label, c.Group, c.Order, c.Screens, c.Capabilities, c.Component)
		if c.Data != nil && !c.ClientOnly {
			card := c
			ssrCardByID[c.Meta.ID] = apiCardRender{dataWithContext: func(ctx *RequestContext) (interface{}, error) { return card.Data(ctx) }}
		}
		if len(c.Exports) > 0 {
			monitorNavDefaultsByID[c.Meta.ID] = monitorNavDefault{Exports: append([]string(nil), c.Exports...)}
		}
	}
	for _, e := range ext.Actions {
		class := auth.ActionDestructive
		if e.ReadOnly {
			class = auth.ActionReadOnly
		}
		auth.RegisterActionClass(e.Name, class)
	}
	ext.APIs = endpointsWithKind(ext.APIs, "API")
	ext.Actions = endpointsWithKind(ext.Actions, "action")
	ext.Exports = endpointsWithKind(ext.Exports, "export")
	extensionRegistry = ext
	extensionsConfigured = true
	return nil
}

func endpointByName(entries []Endpoint, name string) (Endpoint, bool) {
	for _, e := range entries {
		if e.Name == name {
			return e, true
		}
	}
	return Endpoint{}, false
}

func cardEndpoint(id string) Endpoint {
	for _, c := range extensionRegistry.Cards {
		if c.Meta.ID == id {
			return Endpoint{CardID: id, Component: c.Component, AllActions: c.AllActions, AnyActions: c.AnyActions, Authorize: c.Authorize}
		}
	}
	return Endpoint{CardID: id}
}

type discardExtensionResponse struct{ header http.Header }

func (d discardExtensionResponse) Header() http.Header         { return d.header }
func (d discardExtensionResponse) Write(p []byte) (int, error) { return len(p), nil }
func (d discardExtensionResponse) WriteHeader(int)             {}

func (h *Handler) ExtensionContext(r *http.Request) *RequestContext { return h.extensionContext(r) }

func (h *Handler) extensionContext(r *http.Request) *RequestContext {
	ctx := &RequestContext{Config: h.appCfg, Routes: h.routes, SystemInfo: h.systemInfo}
	if r != nil {
		ctx.Session, _ = auth.DefaultSessionManager().SessionFromRequest(r)
		ctx.RawAgentID = strings.TrimSpace(r.URL.Query().Get("agent"))
		ctx.AgentID = ctx.RawAgentID
		if h.appCfg.IsLocalAgent(ctx.AgentID) {
			ctx.AgentID = ""
		}
	}
	ctx.Render = h.RenderTemplate
	return ctx
}

func (h *Handler) RenderTemplate(name string, data interface{}) (template.HTML, error) {
	var out bytes.Buffer
	if err := h.tmpl.ExecuteTemplate(&out, name, data); err != nil {
		return "", err
	}
	return template.HTML(out.String()), nil
}

func (h *Handler) authorizeExtension(w http.ResponseWriter, r *http.Request, e Endpoint) (*RequestContext, bool) {
	ctx := h.extensionContext(r)
	if _, ok := auth.DefaultSessionManager().SessionFromRequest(r); !ok {
		http.Error(w, "login required", http.StatusUnauthorized)
		return nil, false
	}
	if !navmeta.CardComponentEnabled(e.CardID, h.appCfg) || (e.Component != "" && !h.appCfg.ComponentEnabled(e.Component)) {
		http.NotFound(w, r)
		return nil, false
	}
	screen := e.Screen
	if screen == "" {
		screen = "monitor"
	}
	if !auth.ScreenAllowed(ctx.Session.AccessScreens, auth.Screen(screen)) || normalizeCardModes(ctx.Session.CardModes)[e.CardID] == "hidden" || !navmeta.IsCardVisible(e.CardID, ctx.RawAgentID, screen, h.appCfg) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}
	if ctx.RawAgentID != "" && (!isValidAgentID(ctx.RawAgentID) || !enforceAgentTenantBoundary(r, ctx.RawAgentID)) {
		http.Error(w, "forbidden agent", http.StatusForbidden)
		return nil, false
	}
	for _, key := range e.AllActions {
		if !isMonitorActionAllowed(r, ctx.Session, key) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return nil, false
		}
	}
	if len(e.AnyActions) > 0 {
		allowed := false
		for _, key := range e.AnyActions {
			allowed = allowed || isMonitorActionAllowed(r, ctx.Session, key)
		}
		if !allowed {
			http.Error(w, "forbidden", http.StatusForbidden)
			return nil, false
		}
	}
	if e.Authorize != nil && !e.Authorize(r, ctx) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return nil, false
	}
	return ctx, true
}

func (h *Handler) dispatchExtension(w http.ResponseWriter, r *http.Request, e Endpoint) {
	ctx, ok := h.authorizeExtension(w, r, e)
	if ok {
		if e.AliasFor != "" {
			switch e.kind {
			case "API":
				if r.Method != http.MethodGet && r.Method != http.MethodHead {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				targetScreen := auth.ScreenMonitor
				if isVendorAPI(e.AliasFor) {
					targetScreen = auth.ScreenVendor
				}
				if !auth.ScreenAllowed(ctx.Session.AccessScreens, targetScreen) {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				if targetID, _ := resolveCardIDForAPI(e.AliasFor); targetID != "" {
					target := cardEndpoint(targetID)
					target.Screen = string(targetScreen)
					if _, allowed := h.authorizeExtension(w, r, target); !allowed {
						return
					}
				}
				h.dispatchAPI(w, r, e.AliasFor)
			case "export":
				if targetID := exportCardIDByKey[e.AliasFor]; targetID != "" {
					if _, allowed := h.authorizeExtension(w, r, cardEndpoint(targetID)); !allowed {
						return
					}
				}
				dispatchExport(w, r, e.AliasFor)
			default:
				h.dispatchAction(w, r, e.AliasFor)
			}
		} else {
			e.Handler(w, r, ctx)
		}
	}
}

// AfterAgentReportSaved is invoked by the shared receiver only after successful
// authentication and persistence. Applications must not call it before saving.
var reportSavedHook func(*config.AppConfig, AgentReport)
var reportHookConfigured bool

func ConfigureReportObserver(hook func(*config.AppConfig, AgentReport)) error {
	if reportHookConfigured {
		return fmt.Errorf("report observer already configured")
	}
	reportSavedHook = hook
	reportHookConfigured = true
	return nil
}

func AfterAgentReportSaved(cfg *config.AppConfig, report AgentReport) {
	if reportSavedHook == nil {
		return
	}
	// The receiver may use a cached tenant configuration, including shared maps.
	// A hook receives its own snapshot so an accidental edit cannot affect later
	// authentication or another report. Keep signing material in memory only.
	data, err := json.Marshal(cfg)
	if err != nil {
		log.Print("agent report observer skipped: configuration snapshot failed")
		return
	}
	var snapshot *config.AppConfig
	if err := json.Unmarshal(data, &snapshot); err != nil {
		log.Print("agent report observer skipped: configuration snapshot failed")
		return
	}
	if report.Collectors != nil {
		collectors := make(map[string]json.RawMessage, len(report.Collectors))
		for key, payload := range report.Collectors {
			collectors[key] = bytes.Clone(payload)
		}
		report.Collectors = collectors
	}
	reportSavedHook(snapshot, report)
}

var builtinActionNames = map[string]bool{"save_alert_rules": true, "save_alert_recipients": true, "maintenance_on": true, "maintenance_off": true, "nc_repair": true, "restart_heartdesk": true, "reboot": true, "apt_update": true, "apt_upgrade": true, "apt_full_upgrade": true, "toggle_auto_update": true, "fail2ban_ban": true, "fail2ban_unban": true, "ip_add": true, "ip_remove": true, "ip_rename": true, "ip_changetype": true, "user_mgmt_create": true, "user_mgmt_save": true, "user_mgmt_reset": true, "user_mgmt_delete": true, "wl_add": true, "wl_remove": true, "update_profile_name": true, "update_password": true, "totp_generate": true, "totp_enable": true, "totp_disable": true, "highscore_dismiss": true, "highscore_ban": true, "bulk_ban": true, "agent_memo_save": true, "vendor_license_issue": true, "vendor_license_revoke": true, "vendor_license_offline_generate": true, "vendor_license_rotation_generate": true}
