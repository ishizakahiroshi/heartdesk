package monitor

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// <monitor_base>/card?card=xxx → card_refresh.js からのカードHTML返却
	if r.URL.Path == h.routes.MonitorBase+"/card" {
		h.APICard(w, r)
		return
	}
	// ?export=xxx → ファイルダウンロード
	if exportType := r.URL.Query().Get("export"); exportType != "" {
		if endpoint, ok := endpointByName(extensionRegistry.Exports, exportType); ok {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			h.dispatchExtension(w, r, endpoint)
			return
		}
		dispatchExport(w, r, exportType)
		return
	}
	// ?api=xxx → GET API
	if api := r.URL.Query().Get("api"); api != "" {
		if r.Method == http.MethodPost {
			h.dispatchAction(w, r, api)
		} else {
			h.dispatchAPI(w, r, api)
		}
		return
	}
	// ?r2_metrics=1 → PHP互換の旧エンドポイント（shared.js が ?r2_metrics=1 で呼び出す）
	// ?api=r2_metrics と同じ component/card/agent/tenant ゲート。
	if r.URL.Query().Has("r2_metrics") {
		if !h.requireAPIComponent(w, r, "r2_metrics") {
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if !h.requireAPICard(w, r, "r2_metrics") {
			return
		}
		agentID := strings.TrimSpace(r.URL.Query().Get("agent"))
		if agentID != "" && !isValidAgentID(agentID) {
			http.Error(w, `{"error":"invalid agent"}`, http.StatusBadRequest)
			return
		}
		if agentID != "" && !enforceAgentTenantBoundary(r, agentID) {
			http.Error(w, `{"error":"forbidden agent"}`, http.StatusForbidden)
			return
		}
		if h.appCfg.IsLocalAgent(agentID) {
			agentID = ""
		}
		if err := json.NewEncoder(w).Encode(GetR2Metrics(h.appCfg, agentID)); err != nil {
			log.Printf("ERROR: monitor: r2_metrics encode error: %v", err)
		}
		return
	}
	// ?view=agents_overview → 全サーバー概要画面
	// ?view=server_detail → サーバー詳細画面
	// ?view=server_doc|security_doc → docs/infra の設計書ビュー
	if view := r.URL.Query().Get("view"); view != "" {
		if view == "agents_overview" {
			h.renderAgentsOverview(w, r)
			return
		}
		if view == "audit_log" {
			h.renderAuditLog(w, r)
			return
		}
		if view == "vendor_console" {
			// Vendor Console 画面は
			// ScreenVendor を持つセッションのみ許可。認可判定を requireVendorScreen に集約。
			if !requireVendorScreen(w, r) {
				return
			}
			h.renderVendorConsole(w, r)
			return
		}
		if view == "server_detail" {
			h.renderServerDetail(w, r)
			return
		}
		h.renderInfraDoc(w, r, view)
		return
	}
	// /monitor/avatar/<username> → アバター画像配信
	if strings.HasPrefix(r.URL.Path, h.routes.MonitorBase+"/avatar/") {
		h.serveAvatar(w, r)
		return
	}
	// 通常ページ
	switch r.URL.Path {
	case h.routes.MonitorBase + "/", h.routes.MonitorBase:
		h.Monitor(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) Monitor(w http.ResponseWriter, r *http.Request) {
	if h.appCfg != nil && h.appCfg.UI.DefaultAgent != "" {
		http.Redirect(w, r, h.routes.MonitorBase+"/?view=server_detail&agent="+h.appCfg.UI.DefaultAgent, http.StatusFound)
		return
	}
	http.Redirect(w, r, h.routes.MonitorBase+"/?view=agents_overview", http.StatusFound)
}
