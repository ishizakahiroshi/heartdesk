package auth

// Role はユーザー属性軸のロールを表す。
type Role string

const (
	RoleVendorStaff Role = "vendor_staff" // ベンダー運用者
	RoleTenantAdmin Role = "tenant_admin" // 顧客テナント管理者
	RoleTenantUser  Role = "tenant_user"  // 顧客テナント一般利用者
)

// validRoles は有効なロール集合。
var validRoles = map[Role]struct{}{
	RoleVendorStaff: {},
	RoleTenantAdmin: {},
	RoleTenantUser:  {},
}

// Screen は画面アクセス軸の画面IDを表す。
type Screen string

const (
	ScreenMonitor Screen = "monitor"
	// ScreenVendor は Vendor Console 専用の画面（C3 monitor-god-package /
	// vendor-role-check-duplication）。Vendor Console を Monitor から screen レベルの
	// 認可境界で分離するために追加する。既定で vendor_staff のみに付与する。
	ScreenVendor Screen = "vendor"
)

// validScreens は有効な画面ID集合。
var validScreens = map[Screen]struct{}{
	ScreenMonitor: {},
	ScreenVendor:  {},
}

// defaultAccessScreens は role ごとの既定 access_screens。
// C3（monitor-god-package）: ScreenVendor は vendor_staff のみに既定付与する。
// nc_admin / nc_user 画面は廃止済み（Monitor に一本化）。全ロールの既定は monitor を含む。
var defaultAccessScreens = map[Role][]Screen{
	RoleVendorStaff: {ScreenMonitor, ScreenVendor},
	RoleTenantAdmin: {ScreenMonitor},
	RoleTenantUser:  {ScreenMonitor},
}

// AllowsVendor は access_screens に Vendor Console 画面が含まれるかを返す。
// Vendor 系ハンドラの認可判定を 1 箇所に集約するためのヘルパ（C3
// vendor-role-check-duplication）。従来は 17 箇所で手書きしていた。
func AllowsVendor(accessScreens []string) bool {
	return ScreenAllowed(accessScreens, ScreenVendor)
}

// ActionClass は policy.actions キーの分類。
type ActionClass int

const (
	ActionDestructive ActionClass = iota // 破壊的アクション（vendor_staff のみ既定許可）
	ActionReadOnly                       // 読み取り系アクション（全ロール既定許可）
)

// actionClasses は各アクションの分類テーブル。
var actionClasses = map[string]ActionClass{
	// 破壊的アクション
	"reboot":                ActionDestructive,
	"restart_sab":           ActionDestructive,
	"maintenance_on":        ActionDestructive,
	"maintenance_off":       ActionDestructive,
	"nc_repair":             ActionDestructive,
	"apt_update":            ActionDestructive,
	"apt_upgrade":           ActionDestructive,
	"apt_full_upgrade":      ActionDestructive,
	"toggle_auto_update":    ActionDestructive,
	"fail2ban_ban":          ActionDestructive,
	"fail2ban_unban":        ActionDestructive,
	"ip_add":                ActionDestructive,
	"ip_remove":             ActionDestructive,
	"ip_rename":             ActionDestructive,
	"ip_changetype":         ActionDestructive,
	"highscore_dismiss":     ActionDestructive,
	"highscore_ban":         ActionDestructive,
	"bulk_ban":              ActionDestructive,
	"backup_run":            ActionDestructive,
	"save_alert_rules":      ActionDestructive,
	"save_alert_recipients": ActionDestructive,
	// 自己操作（全ロール許可）
	"update_profile_name": ActionReadOnly,
	"update_password":     ActionReadOnly,
	"upload_avatar":       ActionReadOnly,
	"totp_generate":       ActionReadOnly,
	"totp_enable":         ActionReadOnly,
	"totp_disable":        ActionReadOnly,
	// 読み取り系アクション
	"nginx_log":             ActionReadOnly,
	"nginx_url_detail":      ActionReadOnly,
	"ban_heatmap_cell":      ActionReadOnly,
	"honeypot_heatmap_cell": ActionReadOnly,
	"honeypot_access":       ActionReadOnly,
	"honeypot_all":          ActionReadOnly,
	"threat_score_history":  ActionReadOnly,
	"threat_event_history":  ActionReadOnly,
	"search_ip":             ActionReadOnly,
}

// NormalizeRole は有効なロール値のみ返す。無効値は空文字を返す。
func NormalizeRole(raw string) string {
	r := Role(raw)
	if _, ok := validRoles[r]; ok {
		return string(r)
	}
	return ""
}

// NormalizeScreen は有効な画面IDのみ返す。無効値は空文字を返す。
func NormalizeScreen(raw string) string {
	s := Screen(raw)
	if _, ok := validScreens[s]; ok {
		return string(s)
	}
	return ""
}

// DefaultAccessScreens は role の既定 access_screens を返す。
// 用途は UI での「新規ユーザー作成時のヒント値」のみ。認証・認可の判定では一切使わない。
// users.toml の access_screens は明示指定が唯一の真実で、省略/空配列はどちらも「全画面不可」。
func DefaultAccessScreens(role string) []string {
	screens, ok := defaultAccessScreens[Role(role)]
	if !ok {
		return nil
	}
	out := make([]string, len(screens))
	for i, s := range screens {
		out[i] = string(s)
	}
	return out
}

// DefaultActionAllowed は role と action の組み合わせで既定許可を返す。
func DefaultActionAllowed(role, action string) bool {
	class, known := actionClasses[action]
	if !known {
		// 未登録アクションは vendor_staff のみ許可
		return Role(role) == RoleVendorStaff
	}
	if class == ActionReadOnly {
		return true // 全ロール既定許可
	}
	return Role(role) == RoleVendorStaff
}

// ScreenAllowed はセッションの access_screens に指定画面が含まれるかを返す。
func ScreenAllowed(accessScreens []string, screen Screen) bool {
	target := string(screen)
	for _, s := range accessScreens {
		if s == target {
			return true
		}
	}
	return false
}

// ActionAllowed は policy.actions と role の既定値を組み合わせてアクション可否を返す。
func ActionAllowed(policyActions map[string]bool, role, action string) bool {
	if v, ok := policyActions[action]; ok {
		return v
	}
	return DefaultActionAllowed(role, action)
}
