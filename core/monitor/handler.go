package monitor

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/url"
	"os"
	"sort"
	"strings"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
)

// Handler は Monitor の HTTP ハンドラをまとめる
type Handler struct {
	tmpl       *template.Template
	routes     routing.Config
	systemInfo config.SystemInfoData
	appCfg     *config.AppConfig
}

// NewHandler はテンプレートを受け取りハンドラを生成する
func NewHandler(tmpl *template.Template, routes routing.Config, systemInfo config.SystemInfoData, appCfg *config.AppConfig) *Handler {
	return &Handler{tmpl: tmpl, routes: routes, systemInfo: systemInfo, appCfg: appCfg}
}

func (h *Handler) resourceBarThresholdsJS() template.JS {
	warn := 60
	danger := 85
	if h.appCfg != nil {
		if h.appCfg.ResourceThresholds.BarWarning > 0 {
			warn = h.appCfg.ResourceThresholds.BarWarning
		}
		if h.appCfg.ResourceThresholds.BarDanger > 0 {
			danger = h.appCfg.ResourceThresholds.BarDanger
		}
	}
	if danger < warn {
		danger = warn
	}
	return template.JS(safeJSON(map[string]int{
		"warning": warn,
		"danger":  danger,
	}))
}

// 実レンダリングのグループ/順序は views.go の effectiveMonitorCardNavMeta が正で、
// navmeta registry から導出される。
// カードごとの既定値（Exports/CountMode/DefaultLimit/NoRefresh）は下の
// monitorNavDefaultsByID が現役で、init 検証（validateMonitorExportDefaults）に使われる。

const monitorCardDefaultLimit = 10

type monitorNavDefault struct {
	Exports      []string
	CountMode    CountMode
	DefaultLimit int
	NoRefresh    bool
}

type ipFilterOption struct {
	WL    bool `json:"wl"`
	WLM   bool `json:"wlm"`
	WLA   bool `json:"wla"`
	BAN   bool `json:"ban"`
	Known bool `json:"known"`
}

type cardClientOption struct {
	IPFilter *ipFilterOption `json:"ip_filter,omitempty"`
}

func cardOptionsFile() string { return sab.SabPath("data/json/card_options.json") }

// デフォルト設定（card_options.json が存在しない場合に使用）
var defaultCardOptions = map[string]cardClientOption{
	navmeta.CardSecNginxLog: {
		IPFilter: &ipFilterOption{WL: false, WLM: false, WLA: false, BAN: true, Known: true},
	},
	navmeta.CardSecGeoipCache: {
		IPFilter: &ipFilterOption{WL: true, WLM: true, WLA: true, BAN: true, Known: true},
	},
	navmeta.CardSecThreatScore: {
		IPFilter: &ipFilterOption{WL: false, WLM: false, WLA: false, BAN: false, Known: false},
	},
}

func loadCardOptions() map[string]cardClientOption {
	data, err := os.ReadFile(cardOptionsFile())
	if err != nil {
		return defaultCardOptions
	}
	var opts map[string]cardClientOption
	if err := json.Unmarshal(data, &opts); err != nil {
		log.Printf("ERROR: monitor: card_options.json parse error: %v", err)
		return defaultCardOptions
	}
	// デフォルトにファイルの値をマージ（ファイルにないカードはデフォルト値を使用）
	merged := make(map[string]cardClientOption, len(defaultCardOptions))
	for k, v := range defaultCardOptions {
		merged[k] = v
	}
	for k, v := range opts {
		merged[k] = v
	}
	return merged
}

func monitorCardOptionsJS() template.JS {
	return template.JS(safeJSON(loadCardOptions()))
}

func monitorCardIDsJS() template.JS {
	return template.JS(safeJSON(navmeta.MonitorCardIDs()))
}

func monitorCardAPIsJS() template.JS {
	return template.JS(safeJSON(navmeta.MonitorAPIByCardID()))
}

var monitorNavDefaultsByID = map[string]monitorNavDefault{
	navmeta.CardSecRealtimeMonitor: {NoRefresh: true},
	navmeta.CardSecIPMgmt:          {Exports: []string{exportKeySSHIP}, CountMode: CountModeTotal},
	navmeta.CardSecFail2ban:        {Exports: []string{exportKeyBan}},
	navmeta.CardSecHoneypotSummary: {Exports: []string{exportKeyHoneypot}},
	navmeta.CardSecHoneypotAccess:  {CountMode: CountModeRatio},
	navmeta.CardSecNc4xxAccess:     {CountMode: CountModeRatio},
	navmeta.CardSecNcHighScore:     {Exports: []string{exportKeyNCHighScore}, CountMode: CountModeRatio},
	navmeta.CardSecThreatScore:     {Exports: []string{exportKeyThreatScore}, CountMode: CountModeRatio},
	navmeta.CardSecSSHLoginHistory: {Exports: []string{exportKeySSHLogin}, CountMode: CountModeRatio},
	navmeta.CardSecNabLoginHistory: {Exports: []string{exportKeyNabLogin}, CountMode: CountModeRatio},
	navmeta.CardSecPhpmyadminLogin: {Exports: []string{exportKeyPhpMyAdmin}, CountMode: CountModeRatio},
	navmeta.CardSecNcLogin:         {Exports: []string{exportKeyNextcloud}, CountMode: CountModeRatio},
	navmeta.CardSecAuditAnomaly:    {Exports: []string{exportKeyAuditAnomaly}, CountMode: CountModeRatio},
	navmeta.CardSecNginxLog:        {Exports: []string{exportKeyNginx}, CountMode: CountModeRatio},
	navmeta.CardSecGeoipCache:      {Exports: []string{exportKeyGeoIPCache}, CountMode: CountModeTotal, DefaultLimit: monitorCardDefaultLimit},
	navmeta.CardSecCPUTop:          {DefaultLimit: 3},
	navmeta.CardSecMemTop:          {DefaultLimit: 3},
}

func init() {
	if err := validateMonitorExportDefaults(); err != nil {
		panic(err)
	}
}

func validateMonitorExportDefaults() error {
	var violations []string
	for cardID, def := range monitorNavDefaultsByID {
		for _, exportKey := range def.Exports {
			if !hasExportHandler(exportKey) {
				violations = append(violations, fmt.Sprintf("%s -> %s", cardID, exportKey))
			}
		}
	}
	if len(violations) == 0 {
		return nil
	}
	sort.Strings(violations)
	return fmt.Errorf("monitor export key mismatch: %s (known: %s)", strings.Join(violations, ", "), strings.Join(listExportKeys(), ", "))
}

// buildHeaderLinks は TOML の [ui.header_links.<app>] をテンプレート用 HeaderLink スライスに変換する。
// order 昇順にソートし、プレースホルダを解決して返す。
func (h *Handler) buildHeaderLinks(app string) []HeaderLink {
	if h.appCfg == nil || h.appCfg.UI.HeaderLinks == nil {
		return nil
	}
	entries := h.appCfg.UI.HeaderLinks[app]
	if len(entries) == 0 {
		return nil
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Order < entries[j].Order
	})
	links := make([]HeaderLink, 0, len(entries))
	for _, e := range entries {
		hl := HeaderLink{
			Order:     e.Order,
			Title:     e.Title,
			IconType:  e.IconType,
			IconEmoji: e.IconEmoji,
		}
		// URL プレースホルダ解決
		href := e.URL
		href = strings.ReplaceAll(href, "{AppBase}", h.routes.MonitorBase)
		href = strings.ReplaceAll(href, "{StaticBase}", h.routes.StaticBase)
		// 内部アクション
		switch e.Action {
		case "export_all":
			hl.Href = "?export=all"
			hl.IsAction = true
		default:
			hl.Href = href
			hl.NewTab = shouldOpenHeaderLinkInNewTab(href)
		}
		// アイコン src 解決
		switch e.IconType {
		case "svg":
			hl.IconSrc = h.routes.StaticBase + "/img/" + e.IconSVG
		case "url":
			hl.IconSrc = e.IconURL
		}
		links = append(links, hl)
	}
	return links
}

func shouldOpenHeaderLinkInNewTab(href string) bool {
	href = strings.TrimSpace(href)
	if href == "" {
		return false
	}
	u, err := url.Parse(href)
	if err != nil {
		return false
	}
	// http/https の絶対URLだけを新しいタブ扱いにする。
	// "/nextcloud/" や "?view=server_doc" のような内部リンクは同一タブで遷移する。
	return u.IsAbs() && (u.Scheme == "http" || u.Scheme == "https")
}
