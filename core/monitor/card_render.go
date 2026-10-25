package monitor

import (
	"bytes"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
)

type apiCardRender struct {
	data            func(*config.AppConfig) interface{}
	dataWithContext func(*RequestContext) (interface{}, error)
}

// ssrCardByID は Card ID → SSR データ取得関数のマップ（server-detail 画面で使用）
var ssrCardByID = map[string]apiCardRender{
	navmeta.CardSecAgentStatus:       {data: func(cfg *config.AppConfig) interface{} { return GetAgentStatusForConfig(cfg) }},
	navmeta.CardSecUpdates:           {},
	navmeta.CardSecRealtimeMonitor:   {},
	navmeta.CardSecNotificationRules: {data: func(cfg *config.AppConfig) interface{} { return GetNotificationRulesCardData(cfg) }},
	navmeta.CardSecCronStatus:        {},
	navmeta.CardSecDatabase:          {data: func(_ *config.AppConfig) interface{} { return GetDatabaseData() }},
	navmeta.CardSecR2:                {},
	navmeta.CardSecStorageForecast:   {},
}

// buildServerDetailCards は表示可能カードのHTMLを構築する（SSRカードのみ）
func buildServerDetailCards(h *Handler, visibleCards []navmeta.MonitorCardMeta, cardModes map[string]string, agentID string, requests ...*http.Request) map[string]template.HTML {
	cards := map[string]template.HTML{}
	sfData := GetStorageForecast(agentID)
	for _, card := range visibleCards {
		if cardModes[card.ID] == "hidden" {
			continue
		}
		entry, ok := ssrCardByID[card.ID]
		if !ok {
			// SSRエントリがないカードは JS で動的ロードされるためスキップ
			continue
		}
		var data interface{}
		if entry.dataWithContext != nil {
			if len(requests) == 0 || requests[0] == nil {
				continue
			}
			probe := discardExtensionResponse{header: http.Header{}}
			if _, allowed := h.authorizeExtension(probe, requests[0], cardEndpoint(card.ID)); !allowed {
				continue
			}
			ctx := h.extensionContext(requests[0])
			ctx.AgentID = agentID
			value, err := entry.dataWithContext(ctx)
			if err != nil {
				continue
			}
			cards[card.ID] = h.renderCard(navmeta.TemplateNameFromID(card.ID), value)
			continue
		}
		switch card.ID {
		case navmeta.CardSecStorageForecast:
			data = sfData
		case navmeta.CardSecUpdates:
			data = GetUpdatesData(agentID)
		case navmeta.CardSecCronStatus:
			data = GetCronStatus(agentID)
		default:
			if entry.data != nil {
				data = entry.data(h.appCfg)
			}
		}
		cards[card.ID] = h.renderCard(navmeta.TemplateNameFromID(card.ID), data)
	}
	return cards
}

// renderCard はテンプレート名を指定してカードHTMLを生成し template.HTML を返す
func (h *Handler) renderCard(tmplName string, data interface{}) template.HTML {
	var buf bytes.Buffer
	if err := h.tmpl.ExecuteTemplate(&buf, tmplName, data); err != nil {
		log.Printf("ERROR: monitor: renderCard %s error: %v", tmplName, err)
		return template.HTML("<!-- error rendering " + template.HTMLEscapeString(tmplName) + " -->")
	}
	return template.HTML(buf.String())
}

// APICard は GET <monitor_base>/card?card=xxx のハンドラ
// card_refresh.js から呼ばれ、カードHTML文字列を返す。
func (h *Handler) APICard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	card := r.URL.Query().Get("card")
	cardMeta, ok := navmeta.MonitorCardByAPIKey(card)
	if !ok {
		http.Error(w, "unknown card", http.StatusNotFound)
		return
	}
	// セッションのCardModesで hidden なら返さない
	if sess, hasSess := auth.DefaultSessionManager().SessionFromRequest(r); hasSess {
		cardModes := normalizeCardModes(sess.CardModes)
		if cardModes[cardMeta.ID] == "hidden" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	var data interface{}
	agentID := strings.TrimSpace(r.URL.Query().Get("agent"))
	// APICard も dispatchAPI と同様に agent_id を厳格検証する。
	// 形式チェック → tenant 越境チェック → ローカル agent の同視化 の順で適用する。
	if agentID != "" && !isValidAgentID(agentID) {
		http.Error(w, "invalid agent", http.StatusBadRequest)
		return
	}
	if agentID != "" && !enforceAgentTenantBoundary(r, agentID) {
		http.Error(w, "forbidden agent", http.StatusForbidden)
		return
	}
	// heartdesk 自身のサーバー（is_primary = true の agent）はローカル実行と同等なので agentID="" 扱いにする
	if h.appCfg.IsLocalAgent(agentID) {
		agentID = ""
	}
	for _, extra := range extensionRegistry.Cards {
		if extra.Meta.ID == cardMeta.ID {
			if _, ok := h.authorizeExtension(w, r, cardEndpoint(extra.Meta.ID)); !ok {
				return
			}
			if extra.Data != nil {
				value, err := extra.Data(h.extensionContext(r))
				if err != nil {
					http.Error(w, "card failed", http.StatusInternalServerError)
					return
				}
				data = value
			}
			html, err := h.RenderTemplate(navmeta.TemplateNameFromID(cardMeta.ID), data)
			if err != nil {
				http.Error(w, "render failed", http.StatusInternalServerError)
				return
			}
			middleware.SetHTMLSecurityHeaders(w)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(html))
			return
		}
	}
	switch card {
	case "updates":
		data = GetUpdatesData(agentID)
	case "cron_status":
		data = GetCronStatus(agentID)
	case "storage_forecast":
		data = GetStorageForecast(agentID)
	default:
		if cardMeta.ID == navmeta.CardSecAgentStatus {
			data = GetAgentStatusForConfig(h.appCfg)
		} else if cardMeta.ID == navmeta.CardSecNotificationRules {
			data = GetNotificationRulesCardData(h.appCfg)
		} else if cardMeta.ID == navmeta.CardSecDatabase {
			data = GetDatabaseData()
		}
	}
	html := h.renderCard(navmeta.TemplateNameFromID(cardMeta.ID), data)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	middleware.SetHTMLSecurityHeaders(w)
	_, _ = w.Write([]byte(html))
}

// Monitor は GET /monitor/ のハンドラ。
// クエリパラメータなしの場合は default_agent または agents_overview へリダイレクトする。
