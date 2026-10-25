package app

import (
	"fmt"
	"github.com/ishizakahiroshi/heartdesk/web"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/core/monitor"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
)

func bootstrap(opts Options, cfg *Config) (runtime *Runtime, err error) {
	runtime = &Runtime{}
	defer func() {
		if rec := recover(); rec != nil {
			if runtime.reportDB != nil {
				_ = runtime.reportDB.Close()
			}
			runtime = nil
			err = fmt.Errorf("app initialization failed: %v", rec)
		}
	}()
	envTenantID := opts.TenantID

	// users.toml の起動時検証（fail-fast）。旧スキーマのフィールドや無効な role を
	// 1 件でも検出したら、ここで分かりやすいエラーを出して起動を止める。
	// 実行時（ログイン等）は不正な行を黙ってスキップするだけなので、起動時に一度だけ呼ぶ。
	// users.toml が無い構成は警告のみで継続する。
	if err := auth.DefaultStore().ValidateAll(); err != nil {
		return nil, err
	}

	// 起動アドレス
	//
	// X-Forwarded-For 偽装対策: nginx などのリバースプロキシから 127.0.0.1:8765 へ
	// プロキシされる構成を推奨する。listen_addr を "127.0.0.1:8765" にすれば :8765 への
	// 外部直結自体を断てる（既定の ":8765" は全 interface bind のため、パケットフィルタ／
	// 直結時の trustedProxy 多層防御に依存する）。本番は 127.0.0.1 へ閉じること。
	addr := cfg.Server.ListenAddr
	if addr == "" {
		addr = ":8765"
	}

	// X-Real-IP / X-Forwarded-For を信用してよいリバースプロキシ（nginx 等）を登録する。
	// 未設定時はループバックのみ信頼。
	auth.SetTrustedProxies(cfg.Security.TrustedProxies)

	// GeoIP 設定は env ブリッジ（os.Setenv）を使わず、AppConfig を geo.go へ直接渡す。HEARTDESK_IPINFO_TOKEN を process env に書き込まないことで
	// util.Run の子プロセス（bash -c 等）へのトークン露出を断つ。
	monitor.SetGeoConfig(cfg)

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
	tmpl, err := parseTemplates(web.Templates(), opts.TemplateFS, funcMap)
	if err != nil {
		return nil, err
	}
	routingCfg := routing.Current()

	tenantID := envTenantID
	if tenantID == "" {
		tenantID = config.DefaultTenantID
	}

	// env スラッグ（HEARTDESK_TENANT_SLUG）と tenants.toml の整合性を起動時に検証し fail-fast にする。slug が tenants.toml のいずれかに一致するのに
	// その tenant_id が起動テナント（HEARTDESK_TENANT_ID）と食い違う場合、「URL は自テナント・認可は
	// 別テナント ACL」という認可境界の取り違えを招くため起動を止める。
	if slug := routingCfg.TenantSlug; slug != "" {
		if t := routing.GetTenantBySlug(slug); t != nil && strings.TrimSpace(t.TenantID) != "" && t.TenantID != tenantID {
			return nil, fmt.Errorf("routing tenant %q does not match startup tenant %q", t.TenantID, tenantID)
		}
	}

	// tenants.toml が自テナントに routing_mode="path" を宣言しているのに HEARTDESK_ROUTING_MODE /
	// HEARTDESK_TENANT_SLUG が未設定（= 実際は prefix 無しの subdomain モード）だと、入口 URL が
	// tenants.toml 上の想定パスから静かに外れて 404 になる。
	// 認可境界には関わらないため fail-fast にはせず、起動時ログで気づけるようにする。
	if tc := routing.GetTenantByID(tenantID); tc != nil && strings.EqualFold(tc.RoutingMode, "path") {
		switch {
		case routingCfg.RoutingMode != "path":
			log.Printf("WARN: tenants.toml は tenant_id=%q に routing_mode=\"path\"（tenant_slug=%q）を宣言していますが、"+
				"HEARTDESK_ROUTING_MODE が未設定または path 以外です。systemd unit の Environment を確認してください",
				tenantID, tc.TenantSlug)
		case !strings.EqualFold(tc.TenantSlug, routingCfg.TenantSlug):
			log.Printf("WARN: tenants.toml の tenant_slug=%q（tenant_id=%q）と HEARTDESK_TENANT_SLUG=%q が一致しません。"+
				"systemd unit の Environment を確認してください",
				tc.TenantSlug, tenantID, routingCfg.TenantSlug)
		}
	}
	sysInfo := config.BuildSystemInfo(cfg, opts.Version, opts.AssetVersion, opts.Brand, tenantID, routingCfg.TenantSlug)
	monitorH := monitor.NewHandler(tmpl, routingCfg, sysInfo, cfg)
	authH := auth.NewHTTPHandler(tmpl, routingCfg, cfg.Cards, sysInfo)

	// 静的ファイル（/static/ → web/static/）
	staticContent, err := combineStatic(web.Static(), opts.StaticFS)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()

	// --- 静的ファイル ---
	staticPattern := routingCfg.StaticBase + "/"
	staticHandler := http.StripPrefix(staticPattern, http.FileServer(noListFileSystem{http.FS(staticContent)}))
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

	// 死活確認（認証なし・最小の JSON のみ）。セッション認証のミドルウェアを通さず、
	// ルート直下に置く（/api/ や /monitor/ の配下にしない）。
	mux.HandleFunc("/healthz", monitor.HealthzHandler)

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

	runtime.handler = mux
	runtime.addr = addr
	runtime.config = cfg
	runtime.monitor = monitorH
	runtime.routes = routingCfg
	if err := attachRoutes(mux, runtime, opts.Routes); err != nil {
		if runtime.reportDB != nil {
			_ = runtime.reportDB.Close()
		}
		return nil, err
	}
	return runtime, nil
}
