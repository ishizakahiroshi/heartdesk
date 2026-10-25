package monitor

import (
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
)

// renderVendorConsole は ?view=vendor_console の Vendor Console 画面を返す。
// vendor_staff ロール専用。
func (h *Handler) renderVendorConsole(w http.ResponseWriter, r *http.Request) {
	if auth.Role(middleware.GetRole(r.Context())) != auth.RoleVendorStaff {
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	csrfToken := auth.EnsureCSRFCookie(w, r)
	user := middleware.GetUser(r.Context())
	cfg := h.appCfg
	if cfg == nil {
		cfg = &config.AppConfig{}
	}

	visibleCards := navmeta.VisibleCards("", "vendor", cfg)
	jsModules := navmeta.VisibleJSModules("", "vendor", cfg)

	cards := make(map[string]template.HTML, len(visibleCards))
	nav := make([]NavSection, 0)
	nav = append(nav, NavSection{NavGroup: "ベンダーコンソール"})
	for _, card := range visibleCards {
		cards[card.ID] = h.renderCard(navmeta.TemplateNameFromID(card.ID), nil)
		nav = append(nav, NavSection{NavItem: NavItem{ID: card.ID, Label: navmeta.LabelOrID(card.ID)}})
	}

	data := PageData{
		HeaderLinks:               h.buildHeaderLinks("monitor"),
		AppName:                   CurrentMonitorIdentity().AppName,
		Identity:                  CurrentMonitorIdentity(),
		CardAliases:               currentCardAliases(),
		PageTitle:                 "ベンダーコンソール | " + CurrentMonitorIdentity().AppName,
		AppBase:                   h.routes.MonitorBase,
		MonitorBase:               h.routes.MonitorBase,
		VendorBase:                h.routes.VendorBase,
		StaticBase:                h.routes.StaticBase,
		AssetVersion:              h.systemInfo.AssetVersion,
		IconPath:                  h.routes.IconPath(),
		MonitorFaviconPath:        h.routes.MonitorFaviconPath(),
		LogoutPath:                h.routes.LogoutPath,
		SettingsPasswordPath:      h.routes.SettingsPasswordPath,
		Settings2FAPath:           h.routes.Settings2FAPath,
		AdminAuditLogPath:         h.routes.AdminAuditLogPath,
		AdminUnlockPath:           h.routes.AdminUnlockPath,
		BaseHost:                  h.routes.BaseHost,
		CurrentUser:               user,
		CurrentUserName:           resolveDisplayName(user),
		CurrentUserInitial:        resolveInitial(user),
		CurrentRole:               middleware.GetRole(r.Context()),
		CurrentTOTPEnabled:        auth.DefaultTOTPManager().IsEnabled(user),
		CurrentAvatarURL:          AvatarURL(h.routes.MonitorBase, user),
		CSRFToken:                 csrfToken,
		Now:                       heartdesk.FormatDatetime(time.Now().In(heartdesk.JST())),
		IsMaint:                   GetMaintenanceMode(),
		CurrentAgentID:            "",
		ServerTree:                h.agentOverviewForRequest(r),
		Nav:                       nav,
		Cards:                     cards,
		JSVars:                    template.JS(GetIPMgmtJSVars(h.appCfg, "")),
		ResourceBarThresholds:     h.resourceBarThresholdsJS(),
		CardOptions:               template.JS(`{}`),
		CardIDs:                   monitorCardIDsJS(),
		CardAPIs:                  monitorCardAPIsJS(),
		CardViewModes:             template.JS(`{}`),
		ChildCardViewModes:        template.JS(`{}`),
		CardJSModules:             jsModules,
		SystemInfo:                h.systemInfo,
		ShowOverviewRefreshButton: false,
		ShowServerContext:         false,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	middleware.SetHTMLSecurityHeaders(w)
	if err := h.tmpl.ExecuteTemplate(w, "monitor", data); err != nil {
		log.Printf("ERROR: monitor: vendor-console template error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}
