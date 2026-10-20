package monitor

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/audit"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
)

type infraDocMeta struct {
	File  string
	Title string
}

var monitorInfraDocs = map[string]infraDocMeta{
	"server_doc": {
		File:  "サーバー設定書.md",
		Title: "サーバー設定書",
	},
	"security_doc": {
		File:  "セキュリティ設計書.md",
		Title: "セキュリティ設計書",
	},
}

// renderMarkdownHTML は infra-doc ビュー専用の Markdown レンダラ。
// docs/infra/*.md は
// 信頼境界の内側で書かれている前提だが、ファイル経由のインジェクション
// (Git コミット権限の悪用 / sab ユーザー権限でのファイル書き換え) を
// 一段防ぐため html.WithUnsafe() を外し、生 <script>/<iframe> 等は
// goldmark のデフォルト sanitizer でエスケープする。
func renderMarkdownHTML(src []byte) template.HTML {
	var buf bytes.Buffer
	md := goldmark.New(
		goldmark.WithExtensions(
			extension.GFM,
		),
		goldmark.WithParserOptions(
			parser.WithAutoHeadingID(),
		),
	)
	if err := md.Convert(src, &buf); err != nil {
		return template.HTML("<pre>" + template.HTMLEscapeString(string(src)) + "</pre>")
	}
	return template.HTML(buf.String())
}

func parseMonitorAuditLimit(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return 200
	}
	if n > 5000 {
		return 5000
	}
	return n
}

func parseMonitorAuditTime(raw string) *time.Time {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	t, err := sab.ParseTimestamp(s)
	if err != nil {
		return nil
	}
	return &t
}

func writeAuditCSV(w http.ResponseWriter, rows []audit.Event) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit_log.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "event", "user", "role", "ip", "method", "path", "query", "result", "message"})
	for _, rec := range rows {
		// 監査 CSV も他 export 同様に数式インジェクション対策する。
		_ = cw.Write([]string{
			csvSafe(rec.Time),
			csvSafe(rec.Event),
			csvSafe(rec.User),
			csvSafe(rec.Role),
			csvSafe(rec.IP),
			csvSafe(rec.Method),
			csvSafe(rec.Path),
			csvSafe(rec.Query),
			csvSafe(rec.Result),
			csvSafe(rec.Message),
		})
	}
	cw.Flush()
}

// ServeHTTP は Monitor パス配下のリクエストをディスパッチする (http.Handler 実装)
func (h *Handler) renderAuditLog(w http.ResponseWriter, r *http.Request) {
	// 監査ログの全件閲覧は vendor_staff のみ（auth.AdminAuditLog と同基準）。
	// ?view=audit_log は RequireScreen(ScreenMonitor) しか通らず、ScreenMonitor は
	// tenant_admin / tenant_user にも既定付与されるため、ここで role を再判定しないと
	// 非 vendor_staff が全ユーザー監査ログ（IP・ログイン履歴・実行アクション）を閲覧・CSV 取得できてしまう。
	if auth.Role(auth.NormalizeRole(middleware.GetRole(r.Context()))) != auth.RoleVendorStaff {
		http.Error(w, "403 Forbidden: vendor_staff 権限が必要です", http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	limit := parseMonitorAuditLimit(q.Get("limit"))
	from := parseMonitorAuditTime(q.Get("from"))
	to := parseMonitorAuditTime(q.Get("to"))

	rows, err := audit.List(audit.Filter{
		User:   q.Get("user"),
		Event:  q.Get("event"),
		Result: q.Get("result"),
		Query:  q.Get("q"),
		From:   from,
		To:     to,
		Limit:  limit,
	})
	if err != nil {
		log.Printf("ERROR: monitor: audit log read error: %v", err)
	}

	if strings.EqualFold(strings.TrimSpace(q.Get("audit_export")), "csv") {
		writeAuditCSV(w, rows)
		return
	}

	csrfToken := auth.EnsureCSRFCookie(w, r)
	user := middleware.GetUser(r.Context())
	var msgErr string
	if err != nil {
		msgErr = "監査ログの読み込みに失敗しました。"
	}
	filterUser := template.HTMLEscapeString(strings.TrimSpace(q.Get("user")))
	filterEvent := template.HTMLEscapeString(strings.TrimSpace(q.Get("event")))
	filterResult := strings.TrimSpace(q.Get("result"))
	filterQuery := template.HTMLEscapeString(strings.TrimSpace(q.Get("q")))
	filterFrom := template.HTMLEscapeString(strings.TrimSpace(q.Get("from")))
	filterTo := template.HTMLEscapeString(strings.TrimSpace(q.Get("to")))
	monitorAuditPath := h.routes.MonitorBase + "/?view=audit_log"
	var rowsHTML strings.Builder
	if len(rows) == 0 {
		rowsHTML.WriteString(`<tr><td colspan="7">該当する監査ログはありません。</td></tr>`)
	} else {
		for _, rec := range rows {
			rowsHTML.WriteString("<tr>")
			rowsHTML.WriteString(`<td class="mono">` + template.HTMLEscapeString(sab.FormatRawDatetime(rec.Time)) + `</td>`)
			rowsHTML.WriteString(`<td class="mono">` + template.HTMLEscapeString(rec.Event) + `</td>`)
			rowsHTML.WriteString(`<td class="mono">` + template.HTMLEscapeString(rec.User) + `</td>`)
			rowsHTML.WriteString(`<td class="mono">` + template.HTMLEscapeString(rec.IP) + `</td>`)
			rowsHTML.WriteString(`<td class="mono">` + template.HTMLEscapeString(rec.Result) + `</td>`)
			rowsHTML.WriteString(`<td>` + template.HTMLEscapeString(rec.Message) + `</td>`)
			pathText := rec.Method + " " + rec.Path
			if strings.TrimSpace(rec.Query) != "" {
				pathText += "?" + rec.Query
			}
			rowsHTML.WriteString(`<td class="mono">` + template.HTMLEscapeString(pathText) + `</td>`)
			rowsHTML.WriteString("</tr>")
		}
	}
	errHTML := ""
	if msgErr != "" {
		errHTML = `<div class="msg err">` + template.HTMLEscapeString(msgErr) + `</div>`
	}
	selectedAll := ``
	selectedSuccess := ``
	selectedFail := ``
	switch filterResult {
	case "success":
		selectedSuccess = ` selected`
	case "fail":
		selectedFail = ` selected`
	default:
		selectedAll = ` selected`
	}
	cardHTML := template.HTML(fmt.Sprintf(`
<section id="audit-log" class="card" data-card-no-refresh="1">
	<div class="card-header">
		<h2>監査ログ</h2>
		<div class="card-header-actions"></div>
	</div>
	<div class="card-body">
		<style>
		.audit-log-shell .msg { margin-bottom: 10px; padding: 8px 10px; border-radius: 7px; font-size: 0.88rem; }
		.audit-log-shell .msg.err { background: #3a1f26; border: 1px solid #8f3e4a; color: #ffbdc8; }
		.audit-log-shell .row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 10px; }
		.audit-log-shell label { display:block; margin-bottom:6px; font-size:0.8rem; color:var(--text-secondary); }
		.audit-log-shell input[type="text"],
		.audit-log-shell input[type="number"],
		.audit-log-shell select { width: 100%%; height: 34px; border-radius: 8px; border: 1px solid #33425d; background: #0e1420; color: #e6edf3; padding: 0 8px; }
		.audit-log-shell .table-wrap { overflow-x: auto; }
		.audit-log-shell table { width: 100%%; border-collapse: collapse; }
		.audit-log-shell th, .audit-log-shell td { border-bottom: 1px solid #233049; padding: 8px 6px; font-size: 0.8rem; text-align: left; vertical-align: top; }
		.audit-log-shell th { color: #9eb0d4; }
		.audit-log-shell .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
		.audit-log-shell .actions { display:flex; align-items:flex-end; gap:8px; }
		</style>
		<div class="audit-log-shell">
			%s
			<form method="get" action="%s" autocomplete="off">
				<input type="hidden" name="view" value="audit_log">
				<div class="row">
					<div style="flex:1 1 180px;">
						<label>ユーザー</label>
						<input type="text" name="user" value="%s" placeholder="admin">
					</div>
					<div style="flex:1 1 180px;">
						<label>イベント</label>
						<input type="text" name="event" value="%s" placeholder="ACTION_IP_ADD">
					</div>
					<div style="flex:1 1 140px;">
						<label>結果</label>
						<select name="result">
							<option value=""%s>すべて</option>
							<option value="success"%s>success</option>
							<option value="fail"%s>fail</option>
						</select>
					</div>
					<div style="flex:1 1 180px;">
						<label>開始（RFC3339/JST）</label>
						<input type="text" name="from" value="%s" placeholder="2026-04-18T00:00:00+09:00">
					</div>
					<div style="flex:1 1 180px;">
						<label>終了（RFC3339/JST）</label>
						<input type="text" name="to" value="%s" placeholder="2026-04-18T23:59:59+09:00">
					</div>
					<div style="flex:1 1 120px;">
						<label>表示件数</label>
						<input type="number" min="1" max="5000" name="limit" value="%d">
					</div>
				</div>
				<div class="row">
					<div style="flex:1 1 420px;">
						<label>検索（部分一致）</label>
						<input type="text" name="q" value="%s" placeholder="ip/add, login, 192.168...">
					</div>
					<div class="actions">
						<button type="submit" class="btn-primary btn-sm">絞り込み</button>
						<button type="submit" name="audit_export" value="csv" class="btn-primary btn-sm">CSV出力</button>
					</div>
				</div>
			</form>
			<div class="table-wrap" style="margin-top:16px;">
				<table>
					<thead>
						<tr>
							<th>時刻</th>
							<th>イベント</th>
							<th>ユーザー</th>
							<th>IP</th>
							<th>結果</th>
							<th>メッセージ</th>
							<th>パス</th>
						</tr>
					</thead>
					<tbody>%s</tbody>
				</table>
			</div>
		</div>
	</div>
</section>`, errHTML, monitorAuditPath, filterUser, filterEvent, selectedAll, selectedSuccess, selectedFail, filterFrom, filterTo, limit, filterQuery, rowsHTML.String()))

	data := PageData{
		HeaderLinks:          h.buildHeaderLinks("monitor"),
		AppName:              "heartdesk",
		PageTitle:            "監査ログ | heartdesk",
		AppBase:              h.routes.MonitorBase,
		MonitorBase:          h.routes.MonitorBase,
		VendorBase:           h.routes.VendorBase,
		StaticBase:           h.routes.StaticBase,
		AssetVersion:         h.systemInfo.AssetVersion,
		SABIconPath:          h.routes.SABIconPath(),
		MonitorFaviconPath:   h.routes.MonitorFaviconPath(),
		LogoutPath:           h.routes.LogoutPath,
		SettingsPasswordPath: h.routes.SettingsPasswordPath,
		Settings2FAPath:      h.routes.Settings2FAPath,
		AdminAuditLogPath:    h.routes.AdminAuditLogPath,
		AdminUnlockPath:      h.routes.AdminUnlockPath,
		BaseHost:             h.routes.BaseHost,
		CurrentUser:          user,
		CurrentUserName:      resolveDisplayName(user),
		CurrentUserInitial:   resolveInitial(user),
		CurrentRole:          middleware.GetRole(r.Context()),
		CurrentTOTPEnabled:   auth.DefaultTOTPManager().IsEnabled(user),
		CurrentAvatarURL:     AvatarURL(h.routes.MonitorBase, user),
		AgentID:              "",
		AgentType:            "",
		CSRFToken:            csrfToken,
		Now:                  sab.FormatDatetime(time.Now().In(sab.JST())),
		IsMaint:              GetMaintenanceMode(),
		CurrentAgentID:       "",
		ServerTree:           agentOverviewForRequest(r),
		Nav: []NavSection{
			{NavGroup: "管理"},
			{NavItem: NavItem{ID: "audit-log", Label: "🧾 監査ログ"}},
		},
		Cards: map[string]template.HTML{
			"audit-log": cardHTML,
		},
		JSVars:                    template.JS(GetIPMgmtJSVars(h.appCfg, "")),
		ResourceBarThresholds:     h.resourceBarThresholdsJS(),
		CardOptions:               template.JS(`{}`),
		CardIDs:                   template.JS(`{}`),
		CardAPIs:                  template.JS(`{}`),
		CardViewModes:             template.JS(`{}`),
		ChildCardViewModes:        template.JS(`{}`),
		CardJSModules:             nil,
		SystemInfo:                h.systemInfo,
		ShowOverviewRefreshButton: false,
		ShowServerContext:         false,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	middleware.SetHTMLSecurityHeaders(w)
	if err := h.tmpl.ExecuteTemplate(w, "monitor", data); err != nil {
		log.Printf("ERROR: monitor: audit log template error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (h *Handler) renderInfraDoc(w http.ResponseWriter, r *http.Request, view string) {
	// Markdown ビューアを vendor 以外のロールに開示しない。
	// docs/infra/サーバー設定書.md / セキュリティ設計書.md には SSH ポート・
	// sudoers 構成・fail2ban / geofilter ルール等の運用機密が記載されており、
	// vendor_staff (運用者) 以外には開示しない。ScreenMonitor は
	// tenant_admin / tenant_user にも既定付与されるため、ここで再判定する
	// 必要がある (renderAuditLog と同パターン)。
	if auth.Role(auth.NormalizeRole(middleware.GetRole(r.Context()))) != auth.RoleVendorStaff {
		http.Error(w, "403 Forbidden: vendor_staff 権限が必要です", http.StatusForbidden)
		return
	}

	doc, ok := monitorInfraDocs[view]
	if !ok {
		http.Error(w, "不明なドキュメント", http.StatusNotFound)
		return
	}

	mdPath := sab.SabPath("docs/infra/" + doc.File)
	mdRaw, err := os.ReadFile(mdPath)
	if err != nil {
		http.Error(w, "ファイルが見つかりません: "+doc.File, http.StatusNotFound)
		return
	}

	csrfToken := auth.EnsureCSRFCookie(w, r)
	user := middleware.GetUser(r.Context())
	docTitle := template.HTMLEscapeString(doc.Title)
	docBodyHTML := renderMarkdownHTML(mdRaw)
	serverDocItem := NavItem{ID: "infra-doc", Label: "サーバー設定書"}
	securityDocItem := NavItem{ID: "infra-security-doc", Label: "セキュリティ設計書"}
	if view == "server_doc" {
		securityDocItem.Href = h.routes.MonitorBase + "/?view=security_doc"
	} else {
		serverDocItem.Href = h.routes.MonitorBase + "/?view=server_doc"
		serverDocItem.ID = "infra-server-doc-link"
		securityDocItem.ID = "infra-doc"
	}
	docHTML := template.HTML(`
<section id="infra-doc" class="card" data-card-no-refresh="1">
	<div class="card-header">
		<h2>` + docTitle + `</h2>
		<div class="card-header-actions"></div>
	</div>
	<div class="card-body">
		<style>
		.infra-doc-markdown { font-size: 0.95rem; line-height: 1.8; color: var(--text-primary); }
		.infra-doc-markdown > *:first-child { margin-top: 0; }
		.infra-doc-markdown h1,
		.infra-doc-markdown h2,
		.infra-doc-markdown h3,
		.infra-doc-markdown h4 { color: var(--text-heading); line-height: 1.4; margin: 1.4em 0 0.6em; }
		.infra-doc-markdown h1 { font-size: 1.6rem; }
		.infra-doc-markdown h2 { font-size: 1.3rem; }
		.infra-doc-markdown h3 { font-size: 1.1rem; }
		.infra-doc-markdown p,
		.infra-doc-markdown ul,
		.infra-doc-markdown ol,
		.infra-doc-markdown blockquote,
		.infra-doc-markdown table,
		.infra-doc-markdown pre { margin: 0 0 1em; }
		.infra-doc-markdown ul,
		.infra-doc-markdown ol { padding-left: 1.5em; }
		.infra-doc-markdown li + li { margin-top: 0.25em; }
		.infra-doc-markdown a { color: #90caf9; }
		.infra-doc-markdown code {
			background: rgba(144, 202, 249, 0.12);
			border-radius: 4px;
			padding: 1px 5px;
			font-size: 0.88em;
		}
		.infra-doc-markdown pre {
			background: #111722;
			border: 1px solid #2d3a4f;
			border-radius: 8px;
			padding: 14px 16px;
			overflow-x: auto;
		}
		.infra-doc-markdown pre code {
			background: transparent;
			padding: 0;
			border-radius: 0;
		}
		.infra-doc-markdown blockquote {
			border-left: 4px solid #3b4e6a;
			padding-left: 14px;
			color: var(--text-secondary);
		}
		.infra-doc-markdown table {
			width: 100%;
			border-collapse: collapse;
			display: block;
			overflow-x: auto;
		}
		.infra-doc-markdown th,
		.infra-doc-markdown td {
			border: 1px solid #2d3a4f;
			padding: 8px 10px;
			text-align: left;
			vertical-align: top;
			white-space: nowrap;
		}
		.infra-doc-markdown th {
			background: #1b2332;
			color: var(--text-heading);
		}
		</style>
		<div class="infra-doc-markdown">` + string(docBodyHTML) + `</div>
	</div>
</section>`)
	data := ServerDetailPageData{
		PageTitle:                 doc.Title + " | heartdesk",
		HeaderLinks:               h.buildHeaderLinks("monitor"),
		AppName:                   "heartdesk",
		AppBase:                   h.routes.MonitorBase,
		MonitorBase:               h.routes.MonitorBase,
		VendorBase:                h.routes.VendorBase,
		StaticBase:                h.routes.StaticBase,
		AssetVersion:              h.systemInfo.AssetVersion,
		SABIconPath:               h.routes.SABIconPath(),
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
		ShowOverviewRefreshButton: false,
		AgentID:                   "",
		AgentType:                 "",
		CSRFToken:                 csrfToken,
		Now:                       sab.FormatDatetime(time.Now().In(sab.JST())),
		IsMaint:                   GetMaintenanceMode(),
		CurrentAgentID:            "",
		ServerTree:                agentOverviewForRequest(r),
		Nav: []NavSection{
			{NavGroup: "ドキュメント"},
			{NavItem: serverDocItem},
			{NavItem: securityDocItem},
		},
		Cards: map[string]template.HTML{
			"infra-doc": docHTML,
		},
		JSVars:                template.JS(GetIPMgmtJSVars(h.appCfg, "")),
		ResourceBarThresholds: h.resourceBarThresholdsJS(),
		CardOptions:           template.JS(`{}`),
		CardIDs:               template.JS(`{}`),
		CardAPIs:              template.JS(`{}`),
		CardViewModes:         template.JS(`{}`),
		ChildCardViewModes:    template.JS(`{}`),
		CardMeta:              template.JS(`{}`),
		CardJSModules:         nil,
		SystemInfo:            h.systemInfo,
		IsInfraDoc:            true,
		InfraDocTitle:         doc.Title,
		ShowServerContext:     false,
		PageContextIP:         "",
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	middleware.SetHTMLSecurityHeaders(w)
	if err := h.tmpl.ExecuteTemplate(w, "server-detail", data); err != nil {
		log.Printf("ERROR: monitor: infra-doc server-detail template error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// renderAgentsOverview は ?view=agents_overview の全サーバー概要画面を返す
func (h *Handler) renderAgentsOverview(w http.ResponseWriter, r *http.Request) {
	items := agentOverviewForRequest(r)
	csrfToken := auth.EnsureCSRFCookie(w, r)
	user := middleware.GetUser(r.Context())
	type agentOverviewCardData struct {
		MonitorBase string
		Items       []AgentOverviewItem
	}
	cardHTML := h.renderCard("card-agents-overview-shell", agentOverviewCardData{
		MonitorBase: h.routes.MonitorBase,
		Items:       items,
	})
	data := PageData{
		HeaderLinks:               h.buildHeaderLinks("monitor"),
		AppName:                   "heartdesk",
		PageTitle:                 "全サーバー概要 | heartdesk",
		AppBase:                   h.routes.MonitorBase,
		MonitorBase:               h.routes.MonitorBase,
		VendorBase:                h.routes.VendorBase,
		StaticBase:                h.routes.StaticBase,
		AssetVersion:              h.systemInfo.AssetVersion,
		SABIconPath:               h.routes.SABIconPath(),
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
		ShowOverviewRefreshButton: true,
		AgentID:                   "",
		AgentType:                 "",
		CSRFToken:                 csrfToken,
		Now:                       sab.FormatDatetime(time.Now().In(sab.JST())),
		IsMaint:                   GetMaintenanceMode(),
		CurrentAgentID:            "",
		ServerTree:                items,
		// agents_overview は左サイドの固定「サーバー > 全サーバー概要」と重複しやすいため、
		// 現状はページ内目次を出さない。将来カードが増えたら Nav を再追加する。
		Nav: nil,
		Cards: map[string]template.HTML{
			"agents-overview": cardHTML,
		},
		JSVars:                template.JS(GetIPMgmtJSVars(h.appCfg, "")),
		ResourceBarThresholds: h.resourceBarThresholdsJS(),
		CardOptions:           template.JS(`{}`),
		CardIDs:               template.JS(`{}`),
		CardAPIs:              template.JS(`{}`),
		CardViewModes:         template.JS(`{}`),
		ChildCardViewModes:    template.JS(`{}`),
		CardJSModules:         nil,
		SystemInfo:            h.systemInfo,
		ShowServerContext:     false,
		PageContextIP:         "",
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	middleware.SetHTMLSecurityHeaders(w)
	if err := h.tmpl.ExecuteTemplate(w, "monitor", data); err != nil {
		log.Printf("ERROR: monitor: agents-overview template error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// renderServerDetail は ?view=server_detail&agent=<agent_id> のハンドラ
func (h *Handler) renderServerDetail(w http.ResponseWriter, r *http.Request) {
	agentID := strings.TrimSpace(r.URL.Query().Get("agent"))
	if agentID == "" {
		http.Redirect(w, r, h.routes.MonitorBase+"/?view=agents_overview", http.StatusFound)
		return
	}
	// API と同ゲート。形式不正は 400、テナント越境は 403（黙って redirect しない）。
	if !isValidAgentID(agentID) {
		http.Error(w, "invalid agent", http.StatusBadRequest)
		return
	}
	if !enforceAgentTenantBoundary(r, agentID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	seen := GetAgentLastSeenByID(agentID)
	if seen == nil {
		http.Redirect(w, r, h.routes.MonitorBase+"/?view=agents_overview", http.StatusFound)
		return
	}

	agentType := seen.AgentType
	if agentType == "" {
		agentType = "vps"
	}
	role := middleware.GetRole(r.Context())
	cfg := h.appCfg
	if cfg == nil {
		cfg = &config.AppConfig{}
	}

	visibleCards := navmeta.VisibleCards(agentID, "monitor", cfg)

	csrfToken := auth.EnsureCSRFCookie(w, r)
	session, _ := auth.DefaultSessionManager().SessionFromRequest(r)
	cardModes := normalizeCardModes(session.CardModes)
	childCardModes := normalizeChildCardModes(session.ChildCardModes)

	// 表示可能カードのナビとカードHTMLを構築
	nav := buildServerDetailNav(visibleCards, cardModes, cfg)
	// default_agent（Monitor本体VPS）はローカル実行と同等なので agentID="" 扱いにする
	ssrAgentID := seen.AgentID
	if h.appCfg != nil && h.appCfg.UI.DefaultAgent == ssrAgentID {
		ssrAgentID = ""
	}
	cards := buildServerDetailCards(h, visibleCards, cardModes, ssrAgentID)

	data := ServerDetailPageData{
		PageTitle:                 "heartdesk",
		AppName:                   "heartdesk",
		AppBase:                   h.routes.MonitorBase,
		MonitorBase:               h.routes.MonitorBase,
		VendorBase:                h.routes.VendorBase,
		StaticBase:                h.routes.StaticBase,
		AssetVersion:              h.systemInfo.AssetVersion,
		SABIconPath:               h.routes.SABIconPath(),
		MonitorFaviconPath:        h.routes.MonitorFaviconPath(),
		LogoutPath:                h.routes.LogoutPath,
		SettingsPasswordPath:      h.routes.SettingsPasswordPath,
		Settings2FAPath:           h.routes.Settings2FAPath,
		AdminAuditLogPath:         h.routes.AdminAuditLogPath,
		AdminUnlockPath:           h.routes.AdminUnlockPath,
		BaseHost:                  h.routes.BaseHost,
		HeaderLinks:               h.buildHeaderLinks("monitor"),
		CurrentUser:               middleware.GetUser(r.Context()),
		CurrentUserName:           resolveDisplayName(middleware.GetUser(r.Context())),
		CurrentUserInitial:        resolveInitial(middleware.GetUser(r.Context())),
		CurrentRole:               role,
		CurrentTOTPEnabled:        auth.DefaultTOTPManager().IsEnabled(middleware.GetUser(r.Context())),
		CurrentAvatarURL:          AvatarURL(h.routes.MonitorBase, middleware.GetUser(r.Context())),
		ShowOverviewRefreshButton: false,
		CSRFToken:                 csrfToken,
		Now:                       sab.FormatDatetime(time.Now().In(sab.JST())),
		IsMaint:                   GetMaintenanceMode(),
		CurrentAgentID:            seen.AgentID,
		ServerTree:                agentOverviewForRequest(r),
		Nav:                       nav,
		Cards:                     cards,
		JSVars:                    template.JS(GetIPMgmtJSVars(h.appCfg, seen.AgentID)),
		ResourceBarThresholds:     h.resourceBarThresholdsJS(),
		CardOptions:               monitorCardOptionsJS(),
		CardIDs:                   monitorCardIDsJS(),
		CardAPIs:                  monitorCardAPIsJS(),
		CardViewModes:             jsonMapJS(cardModes),
		ChildCardViewModes:        jsonNestedMapJS(childCardModes),
		CardMeta:                  monitorCardMetaJS(cfg, visibleCards),
		CardJSModules:             navmeta.VisibleJSModules(agentID, "monitor", cfg),
		SystemInfo:                h.systemInfo,
		AgentID:                   seen.AgentID,
		AgentLabel:                seen.AgentLabel,
		AgentType:                 agentType,
		IsInfraDoc:                false,
		ShowServerContext:         true,
		PageContextTitle: func() string {
			if seen.AgentLabel != "" {
				return seen.AgentLabel
			}
			return seen.AgentID
		}(),
		PageContextType: agentType,
		PageContextID:   seen.AgentID,
		PageContextIP:   resolveAgentDisplayIP(cfg, seen.AgentID),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	middleware.SetHTMLSecurityHeaders(w)
	if err := h.tmpl.ExecuteTemplate(w, "server-detail", data); err != nil {
		log.Printf("ERROR: monitor: server-detail template error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

type monitorCardNavMeta struct {
	Group string `json:"group"`
	Order int    `json:"order"`
}

// effectiveMonitorCardNavMeta はカードのグループ/順序を返す。真実源は navmeta registry
// （navmeta.DefaultNavMeta / defaultCardNav）で、ここではテナント override
// （cfg.Cards.Meta）のみ重ねる。
func effectiveMonitorCardNavMeta(cfg *config.AppConfig, cardID string) monitorCardNavMeta {
	g, o := navmeta.DefaultNavMeta(cardID)
	meta := monitorCardNavMeta{Group: g, Order: o}
	if cfg != nil && cfg.Cards.Meta != nil {
		if override, ok := cfg.Cards.Meta[cardID]; ok {
			if override.Group != "" {
				meta.Group = override.Group
			}
			if override.Order > 0 {
				meta.Order = override.Order
			}
		}
	}
	if meta.Order <= 0 {
		meta.Order = 9999
	}
	return meta
}

func monitorCardMetaJS(cfg *config.AppConfig, visibleCards []navmeta.MonitorCardMeta) template.JS {
	metaByID := make(map[string]monitorCardNavMeta, len(visibleCards))
	for _, card := range visibleCards {
		metaByID[card.ID] = effectiveMonitorCardNavMeta(cfg, card.ID)
	}
	return template.JS(safeJSON(metaByID))
}

// buildServerDetailNav は表示可能カードからナビセクション一覧を構築する
func buildServerDetailNav(visibleCards []navmeta.MonitorCardMeta, cardModes map[string]string, cfg *config.AppConfig) []NavSection {
	items := make([]NavItem, 0, len(visibleCards))
	for _, card := range visibleCards {
		if cardModes[card.ID] == "hidden" {
			continue
		}
		meta := effectiveMonitorCardNavMeta(cfg, card.ID)
		item := NavItem{ID: card.ID, Label: navmeta.LabelOrID(card.ID), ParentGroup: meta.Group}
		// monitorNavDefaultsByID から既定値を補完
		if def, ok := monitorNavDefaultsByID[card.ID]; ok {
			item.Exports = append([]string(nil), def.Exports...)
			item.CountMode = def.CountMode
			item.DefaultLimit = def.DefaultLimit
			item.NoRefresh = def.NoRefresh
		}
		if item.DefaultLimit <= 0 && item.CountMode == CountModeRatio {
			item.DefaultLimit = monitorCardDefaultLimit
		}
		items = append(items, item)
	}

	sort.SliceStable(items, func(i, j int) bool {
		left := effectiveMonitorCardNavMeta(cfg, items[i].ID)
		right := effectiveMonitorCardNavMeta(cfg, items[j].ID)
		if left.Order != right.Order {
			return left.Order < right.Order
		}
		return items[i].Label < items[j].Label
	})

	sections := make([]NavSection, 0, len(items)+8)
	currentGroup := ""
	for _, item := range items {
		if item.ParentGroup != "" && item.ParentGroup != currentGroup {
			sections = append(sections, NavSection{NavGroup: item.ParentGroup})
			currentGroup = item.ParentGroup
		}
		sections = append(sections, NavSection{NavItem: item})
	}
	return sections
}
