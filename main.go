// heartdesk — エントリポイント（Monitor サーバー）
//
// 既定ではポート :8765 で起動し、以下のパスをルーティングする:
//
//	/monitor/                     → Monitor
//	/api/monitor/...              → Monitor API
//	/api/agent/report             → Agent レポート受信（HMAC 認証）
//	/api/license/...              → Agent ライセンス検証・heartbeat
//	/static/                      → 静的ファイル（CSS/JS）
//
// 起動方法の例（サーバー上。バイナリの置き場所は任意）:
//
//	/path/to/heartdesk
//
// クロスコンパイルの例（成果物を作るので、必要なときに手動で実行する）:
//
//	GOOS=linux GOARCH=amd64 go build -o bin/heartdesk-linux-amd64 .
package main

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ishizakahiroshi/heartdesk/core/monitor"
	sab "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/license"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc/store"
)

//go:embed web/templates/*.html
var templateFS embed.FS

//go:embed web/static
var staticFS embed.FS

const defaultListenAddr = ":8765"

// ビルド時に ldflags で注入する。未指定時は "dev" / ""。
// 例: -X main.version=v1.0.1 -X main.gitCommit=12f6a8
var version = "dev"
var gitCommit = ""
var buildID = "dev"

func buildVersionString() string {
	if version != "dev" && gitCommit != "" {
		return version + " / " + gitCommit
	}
	if version != "dev" {
		return version
	}
	if gitCommit != "" {
		return "dev / " + gitCommit
	}
	return "dev"
}

func assetVersionString() string {
	if buildID != "dev" {
		return buildID
	}
	// 開発時フォールバック（毎起動で変わる）
	return strconv.FormatInt(time.Now().Unix(), 10)
}

func main() {
	// TOML 設定読み込み（SAB_TENANT_ID 未設定時は config.DefaultTenantID を使用）
	// 既定値は config.DefaultTenantID に集約。
	envTenantID := strings.TrimSpace(os.Getenv("SAB_TENANT_ID"))
	if envTenantID == "" {
		log.Printf("INFO: SAB_TENANT_ID 未設定 → tenant=%s (defaulted)", config.DefaultTenantID)
	}
	cfg, err := config.LoadAppConfigForTenant(envTenantID)
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	// ライセンス検証
	if err := license.New().Verify(
		cfg.VendorLicense.TenantID+"-monitor",
		cfg.VendorLicense.LicenseKey,
	); err != nil {
		log.Fatalf("license verification failed: %v", err)
	}

	// 起動アドレス
	//
	// X-Forwarded-For 偽装対策: nginx などのリバースプロキシから 127.0.0.1:8765 へ
	// プロキシされる構成を推奨する。listen_addr を "127.0.0.1:8765" にすれば :8765 への
	// 外部直結自体を断てる（既定の ":8765" は全 interface bind のため、パケットフィルタ／
	// 直結時の trustedProxy 多層防御に依存する）。本番は 127.0.0.1 へ閉じること。
	addr := cfg.Server.ListenAddr
	if addr == "" {
		addr = defaultListenAddr
	}

	// X-Real-IP / X-Forwarded-For を信用してよいリバースプロキシ（nginx 等）を登録する。
	// 未設定時はループバックのみ信頼。
	auth.SetTrustedProxies(cfg.Security.TrustedProxies)

	// GeoIP 設定は env ブリッジ（os.Setenv）を使わず、AppConfig を geo.go へ直接渡す。SAB_IPINFO_TOKEN を process env に書き込まないことで
	// util.Run の子プロセス（bash -c 等）へのトークン露出を断つ。
	monitor.SetGeoConfig(cfg)

	// DB 初期化
	if dsn := cfg.Database.DSN; dsn != "" {
		if err := sab.InitDB(dsn); err != nil {
			log.Fatalf("DB 初期化失敗: %v", err)
		}
	}

	// テンプレート関数定義（リソース系カード用）
	resourceWarn := cfg.ResourceThresholds.BarWarning
	if resourceWarn <= 0 {
		resourceWarn = 60
	}
	resourceDanger := cfg.ResourceThresholds.BarDanger
	if resourceDanger <= 0 {
		resourceDanger = 85
	}
	if resourceDanger < resourceWarn {
		resourceDanger = resourceWarn
	}
	clampPct := func(v float64) int {
		if v < 0 {
			return 0
		}
		if v > 100 {
			return 100
		}
		return int(v)
	}
	barClassByPct := func(v float64) string {
		if v >= float64(resourceDanger) {
			return "bar-danger"
		}
		if v >= float64(resourceWarn) {
			return "bar-warn"
		}
		return "bar-ok"
	}
	metricClassByPct := func(v float64) string {
		if v >= float64(resourceDanger) {
			return "danger"
		}
		if v >= float64(resourceWarn) {
			return "warn"
		}
		return ""
	}
	parsePctString := func(raw string) float64 {
		s := strings.TrimSpace(strings.TrimSuffix(raw, "%"))
		if s == "" {
			return 0
		}
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0
		}
		return v
	}
	funcMap := template.FuncMap{
		// fval: *float64 → フォーマット文字列（nil なら "—"）
		"fval": func(v *float64, format string) string {
			if v == nil {
				return "—"
			}
			return fmt.Sprintf(format, *v)
		},
		// fpct: *float64 → バー高さ用 int（0-100 にクランプ、nil なら 0）
		"fpct": func(v *float64) int {
			if v == nil || *v < 0 {
				return 0
			}
			return clampPct(*v)
		},
		// barClass: 値に応じた CSS クラス名（nil なら "bar-empty"）
		"barClass": func(v *float64) string {
			if v == nil {
				return "bar-empty"
			}
			return barClassByPct(*v)
		},
		// pctClass: 使用率に応じたテキスト色クラス（"" / "warn" / "danger"）
		"pctClass": func(v float64) string {
			return metricClassByPct(v)
		},
		// pctBarClass: 使用率に応じたバー色クラス
		"pctBarClass": func(v float64) string {
			return barClassByPct(v)
		},
		// pctClassStr: "38%" 形式の文字列を使用率クラスへ変換
		"pctClassStr": func(v string) string {
			return metricClassByPct(parsePctString(v))
		},
		// pctWidth: 使用率を横バー幅（0-100）に変換
		"pctWidth": func(v float64) int {
			return clampPct(v)
		},
		// pctWidthStr: "38%" 形式の文字列を横バー幅（0-100）に変換
		"pctWidthStr": func(v string) int {
			return clampPct(parsePctString(v))
		},
		// pctBarClassStr: "38%" 形式の文字列をバー色クラスへ変換
		"pctBarClassStr": func(v string) string {
			return barClassByPct(parsePctString(v))
		},
		// cardLabel: カードIDから共有ラベルを取得（未登録時はIDを返す）
		"cardLabel": func(id string) string {
			return navmeta.LabelOrID(id)
		},
	}

	// テンプレート初期化（layout.html + monitor.html を同一セットで解析）
	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "web/templates/*.html"))
	routingCfg := routing.Current()

	tenantID := envTenantID
	if tenantID == "" {
		tenantID = config.DefaultTenantID
	}

	// env スラッグ（SAB_TENANT_SLUG）と tenants.toml の整合性を起動時に検証し fail-fast にする。slug が tenants.toml のいずれかに一致するのに
	// その tenant_id が起動テナント（SAB_TENANT_ID）と食い違う場合、「URL は自テナント・認可は
	// 別テナント ACL」という認可境界の取り違えを招くため起動を止める。
	if slug := routingCfg.TenantSlug; slug != "" {
		if t := routing.GetTenantBySlug(slug); t != nil && strings.TrimSpace(t.TenantID) != "" && t.TenantID != tenantID {
			log.Fatalf("tenant 整合性エラー: SAB_TENANT_SLUG=%q は tenants.toml で tenant_id=%q に対応するが、起動テナント(SAB_TENANT_ID)=%q と不一致。認可境界の取り違えを防ぐため起動を中止します",
				slug, t.TenantID, tenantID)
		}
	}

	// tenants.toml が自テナントに routing_mode="path" を宣言しているのに SAB_ROUTING_MODE /
	// SAB_TENANT_SLUG が未設定（= 実際は prefix 無しの subdomain モード）だと、入口 URL が
	// tenants.toml 上の想定パスから静かに外れて 404 になる。
	// 認可境界には関わらないため fail-fast にはせず、起動時ログで気づけるようにする。
	if tc := routing.GetTenantByID(tenantID); tc != nil && strings.EqualFold(tc.RoutingMode, "path") {
		switch {
		case routingCfg.RoutingMode != "path":
			log.Printf("WARN: tenants.toml は tenant_id=%q に routing_mode=\"path\"（tenant_slug=%q）を宣言していますが、"+
				"SAB_ROUTING_MODE が未設定または path 以外です。systemd unit の Environment を確認してください",
				tenantID, tc.TenantSlug)
		case !strings.EqualFold(tc.TenantSlug, routingCfg.TenantSlug):
			log.Printf("WARN: tenants.toml の tenant_slug=%q（tenant_id=%q）と SAB_TENANT_SLUG=%q が一致しません。"+
				"systemd unit の Environment を確認してください",
				tc.TenantSlug, tenantID, routingCfg.TenantSlug)
		}
	}
	sysInfo := config.BuildSystemInfo(cfg, buildVersionString(), assetVersionString(), sab.VendorName, tenantID, routingCfg.TenantSlug)
	monitorH := monitor.NewHandler(tmpl, routingCfg, sysInfo, cfg)
	authH := auth.NewHTTPHandler(tmpl, routingCfg, cfg.Cards, sysInfo)

	// 静的ファイル（/static/ → web/static/）
	staticContent, err := fs.Sub(staticFS, "web/static")
	if err != nil {
		log.Fatalf("static FS 初期化失敗: %v", err)
	}

	mux := http.NewServeMux()

	// --- 静的ファイル ---
	staticPattern := routingCfg.StaticBase + "/"
	staticHandler := http.StripPrefix(staticPattern, http.FileServer(http.FS(staticContent)))
	mux.Handle(staticPattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		staticHandler.ServeHTTP(w, r)
	}))

	// HTML レスポンス向け no-cache ミドルウェア。
	// avatar 配信エンドポイント（独自に Cache-Control: max-age=86400 を設定済み）は除外する。
	avatarPrefix := routingCfg.MonitorBase + "/avatar/"
	noCacheHTML := middleware.NoCacheHTML(avatarPrefix)

	// --- heartdesk ルート ---
	monitorPattern := routingCfg.MonitorBase + "/"
	mux.Handle(monitorPattern,
		noCacheHTML(middleware.RequireScreen(auth.ScreenMonitor)(monitorH)))
	mux.Handle(routingCfg.MonitorBase, noCacheHTML(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, routingCfg.MonitorHome(), http.StatusFound)
	})))

	// Monitor API（旧互換 endpoint）
	mux.Handle(routingCfg.MonitorAPIBase+"/services",
		middleware.RequireScreen(auth.ScreenMonitor)(http.HandlerFunc(monitorH.APIServices)))

	// managed_ips 台帳の fail2ban ignoreip 同期（SSH の IP 制限はホスティング側の
	// パケットフィルタへ一元化する前提のため、iptables SSH_ALLOW の再構築は行わない）。
	// skipNC=true で Nextcloud bruteforce whitelist 同期はスキップする（occ コマンドが重く起動時に不要）。
	if err := monitor.SyncIPManage(true); err != nil {
		log.Printf("SyncIPManage failed at startup: %v", err)
	}

	// Agent レポート受信 API（セッション認証なし・HMAC認証）
	monitor.RestoreAgentLastSeen()
	monitor.RestoreLicenseRevokeStore()
	monitor.RestoreLegacyTokenStore()
	// Agent 死活カードのメモ機能のストアを初期化（未初期化だと保存・読込が機能しない）
	monitor.InitAgentMemoStore()

	// 集約 SQLite（Vendor Console 監査ログ集約。enabled=true のテナントのみ）
	if err := monitor.InitAuditAggregated(cfg.AuditAggregated); err != nil {
		log.Printf("audit_aggregated init failed: %v", err)
	}

	// Agent レポート保持の正本 = SQLite。
	// vendorsvc.OpenDB で集約 DB を開き store.Stores を構築して
	// monitor.SetAgentReportStores に注入する。これにより AgentReportHandler は
	// SQLite（agent_reports_raw / agents）へ書き込む。注入されない場合のみ JSONL に
	// フォールバックする（読み取り互換・移行用）。DB を開けない場合は致命的にせず
	// JSONL フォールバックのまま起動を継続する（検証フェーズの可用性優先）。
	reportDBPath := sab.SabPath("data/vendor/vendor.db")
	if db, err := vendorsvc.OpenDB(reportDBPath); err != nil {
		log.Printf("WARN: agent report SQLite open failed (path=%s): %v — JSONL フォールバックで起動します", reportDBPath, err)
	} else {
		monitor.SetAgentReportStores(&store.Stores{
			Agent:  store.NewAgentStore(db),
			Report: store.NewReportStore(db),
			Ledger: store.NewLedgerStore(db),
		})
		log.Printf("INFO: agent report store = SQLite (path=%s)", reportDBPath)

		// 旧 JSON ライセンス台帳（vendor_license_ledger.json）を license_ledger へ一度だけ取り込む。
		// license_ledger に既存行があれば no-op（冪等）。元 JSON はバックアップとして残す。
		dataDir := os.Getenv("SAB_DATA_DIR")
		if dataDir == "" {
			dataDir = "/home/sab/data" // secrets-scan: allow
		}
		legacyLedgerPath := filepath.Join(dataDir, "vendor_license_ledger.json")
		if n, mErr := store.MigrateLedgerFromJSONFile(context.Background(), db, legacyLedgerPath); mErr != nil {
			log.Printf("WARN: license ledger migration failed: %v", mErr)
		} else if n > 0 {
			log.Printf("INFO: migrated %d license ledger entries from JSON to SQLite", n)
		}
	}

	mux.HandleFunc("/api/agent/report", monitor.AgentReportHandler)

	// Agent ライセンス検証 API（セッション認証なし・ライセンスキー認証）
	mux.HandleFunc("/api/license/verify", monitor.LicenseVerifyHandler)
	mux.HandleFunc("/api/license/heartbeat", monitor.LicenseHeartbeatHandler)

	// --- ログイン/ログアウト ---
	// 自己設定（パスワード変更/2FA）は Monitor のプロフィールモーダルから使う機能のため
	// monitor 画面権でガードする（nc_user 画面はスケルトンのまま廃止。Monitor に一本化）。
	mux.Handle(routingCfg.LoginPath, noCacheHTML(http.HandlerFunc(authH.Login)))
	// Nextcloud のログイン状態を使ったログイン。
	mux.Handle(routingCfg.LoginPath+"/nc", noCacheHTML(http.HandlerFunc(authH.LoginNC)))
	mux.Handle(routingCfg.LogoutPath, noCacheHTML(http.HandlerFunc(authH.Logout)))
	mux.Handle(routingCfg.SettingsPasswordPath,
		noCacheHTML(middleware.RequireScreen(auth.ScreenMonitor)(http.HandlerFunc(authH.SettingsPassword))))
	mux.Handle(routingCfg.Settings2FAPath,
		noCacheHTML(middleware.RequireScreen(auth.ScreenMonitor)(http.HandlerFunc(authH.Settings2FA))))
	// 管理3操作（2FAリセット/監査ログ/ロック解除）は Monitor UI から使う機能のため
	// monitor 画面権でルーティングし、実権限は各ハンドラ内の vendor_staff チェックが担保する
	// （nc_admin 画面は設けない）。
	mux.Handle(routingCfg.Settings2FAResetPath,
		noCacheHTML(middleware.RequireScreen(auth.ScreenMonitor)(http.HandlerFunc(authH.Settings2FAReset))))
	mux.Handle(routingCfg.AdminAuditLogPath,
		noCacheHTML(middleware.RequireScreen(auth.ScreenMonitor)(http.HandlerFunc(authH.AdminAuditLog))))
	mux.Handle(routingCfg.AdminUnlockPath,
		noCacheHTML(middleware.RequireScreen(auth.ScreenMonitor)(http.HandlerFunc(authH.AdminUnlock))))

	// --- パス方式時のテナントルート ---
	if routingCfg.PathPrefix != "" {
		mux.HandleFunc(routingCfg.PathPrefix, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, routingCfg.MonitorHome(), http.StatusFound)
		})
		mux.HandleFunc(routingCfg.PathPrefix+"/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, routingCfg.MonitorHome(), http.StatusFound)
		})
	}

	// --- 旧 /sab/*, /nab/* 互換リダイレクト ---
	// PathPrefix が "/sab" or "/nab" の path モードでは、上のテナントルート登録と
	// パターンが重複するため、該当 prefix だけスキップする（Go 1.22+ の ServeMux は
	// 同一パターンの再登録で panic する）。
	legacyRedirect := func(w http.ResponseWriter, r *http.Request) {
		target := routingCfg.LegacyToCanonical(r.URL.Path)
		if target == r.URL.Path || target == "/sab" || target == "/nab" {
			target = routingCfg.MonitorHome()
		}
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusFound)
	}
	if routingCfg.PathPrefix != "/sab" {
		mux.HandleFunc("/sab/", legacyRedirect)
		mux.HandleFunc("/sab", legacyRedirect)
	}
	if routingCfg.PathPrefix != "/nab" {
		mux.HandleFunc("/nab/", legacyRedirect)
		mux.HandleFunc("/nab", legacyRedirect)
	}

	// http.Server（ReadHeaderTimeout / IdleTimeout 付き）で待ち受け、SIGINT/SIGTERM で
	// graceful shutdown する。WriteTimeout は SSE / 長時間処理（realtime / on-demand job）が
	// あるため設定しない（必要なら per-handler timeout で個別に絞る）。
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// SIGINT/SIGTERM で graceful shutdown、SIGHUP で設定キャッシュをリロードする。
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// SIGHUP: 設定ファイル変更を反映（設定キャッシュの破棄）。
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	go func() {
		for range hupCh {
			config.ReloadConfigCache()
			log.Printf("INFO: SIGHUP 受信 → 設定キャッシュをリロードしました")
		}
	}()

	go func() {
		log.Printf("SAB 起動: %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe failed: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("INFO: シャットダウンシグナル受信 → graceful shutdown 開始")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("WARN: graceful shutdown 失敗: %v", err)
	}
	log.Printf("INFO: SAB 停止")
}
