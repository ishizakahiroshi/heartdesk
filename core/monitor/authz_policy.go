package monitor

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/authz"
	"github.com/ishizakahiroshi/heartdesk/internal/navmeta"
)

type authzCatalogResponse struct {
	Roles      []authzRoleEntry    `json:"roles"`
	Screens    []authzScreenEntry  `json:"screens"`
	Cards      []string            `json:"cards"`
	ChildCards map[string][]string `json:"child_cards"`
	Actions    []authzActionEntry  `json:"actions"`
}

type authzRoleEntry struct {
	ID             string   `json:"id"`
	DefaultScreens []string `json:"default_screens"`
}

type authzScreenEntry struct {
	ID string `json:"id"`
}

type authzActionEntry struct {
	ID              string   `json:"id"`
	Destructive     bool     `json:"destructive"`
	Label           string   `json:"label,omitempty"`
	Feature         string   `json:"feature,omitempty"`
	CardLabels      []string `json:"card_labels,omitempty"`
	ChildCardLabels []string `json:"child_card_labels,omitempty"`
}

type authzActionMeta struct {
	Label        string
	Feature      string
	CardIDs      []string
	ChildCardIDs []string
}

var authzActionMetaByID = map[string]authzActionMeta{
	"reboot":                {Label: "サーバー再起動", Feature: "サービス操作", CardIDs: []string{navmeta.CardSecServices}},
	"restart_heartdesk":     {Label: "heartdesk再起動", Feature: "サービス操作", CardIDs: []string{navmeta.CardSecServices}},
	"maintenance_on":        {Label: "メンテナンスON", Feature: "メンテナンス切替", CardIDs: []string{navmeta.CardSecServices}},
	"maintenance_off":       {Label: "メンテナンスOFF", Feature: "メンテナンス切替", CardIDs: []string{navmeta.CardSecServices}},
	"nc_repair":             {Label: "Nextcloud 修復", Feature: "保守実行", CardIDs: []string{navmeta.CardSecServices}},
	"apt_update":            {Label: "apt-get update", Feature: "パッケージ更新情報取得", CardIDs: []string{navmeta.CardSecUpdates}},
	"apt_upgrade":           {Label: "apt upgrade", Feature: "通常アップグレード", CardIDs: []string{navmeta.CardSecUpdates}},
	"apt_full_upgrade":      {Label: "apt full-upgrade", Feature: "フルアップグレード", CardIDs: []string{navmeta.CardSecUpdates}},
	"toggle_auto_update":    {Label: "自動更新トグル", Feature: "自動更新設定変更", CardIDs: []string{navmeta.CardSecUpdates}},
	"fail2ban_ban":          {Label: "BAN追加", Feature: "fail2ban 手動BAN", CardIDs: []string{navmeta.CardSecFail2ban, navmeta.CardSecBanHeatmap, navmeta.CardSecThreatScore, navmeta.CardSecNcHighScore, navmeta.CardSecIPMgmt}},
	"fail2ban_unban":        {Label: "BAN解除", Feature: "fail2ban 手動解除", CardIDs: []string{navmeta.CardSecFail2ban, navmeta.CardSecThreatScore, navmeta.CardSecIPMgmt}},
	"ip_add":                {Label: "IP追加", Feature: "SSH許可IP管理", CardIDs: []string{navmeta.CardSecIPMgmt}},
	"ip_remove":             {Label: "IP削除", Feature: "SSH許可IP管理", CardIDs: []string{navmeta.CardSecIPMgmt}},
	"ip_rename":             {Label: "IP名変更", Feature: "SSH許可IP管理", CardIDs: []string{navmeta.CardSecIPMgmt}},
	"ip_changetype":         {Label: "IP種別変更", Feature: "SSH許可IP管理", CardIDs: []string{navmeta.CardSecIPMgmt}},
	"highscore_dismiss":     {Label: "24h無視", Feature: "要確認IPの一時除外", CardIDs: []string{navmeta.CardSecThreatScore, navmeta.CardSecNcHighScore}},
	"highscore_ban":         {Label: "要確認IPをBAN", Feature: "高スコアIP対処", CardIDs: []string{navmeta.CardSecThreatScore, navmeta.CardSecNcHighScore}},
	"bulk_ban":              {Label: "一括BAN", Feature: "選択IPの一括対処", CardIDs: []string{navmeta.CardSecThreatScore, navmeta.CardSecNcHighScore, navmeta.CardSecNc4xxAccess, navmeta.CardSecHoneypotAccess}},
	"backup_run":            {Label: "バックアップ実行", Feature: "手動バックアップ", CardIDs: []string{navmeta.CardSecDatabase}},
	"save_alert_rules":      {Label: "通知ルール保存", Feature: "通知条件設定", CardIDs: []string{navmeta.CardSecNotificationRules}},
	"save_alert_recipients": {Label: "通知宛先保存", Feature: "通知先設定", CardIDs: []string{navmeta.CardSecNotificationRules}},
	"nginx_log":             {Label: "Nginxログ取得", Feature: "アクセスログ表示", CardIDs: []string{navmeta.CardSecNginxLog}},
	"nginx_url_detail":      {Label: "URL詳細表示", Feature: "URL別アクセス詳細", CardIDs: []string{navmeta.CardSecNginxLog}},
	"ban_heatmap_cell":      {Label: "BANセル詳細", Feature: "ヒートマップ詳細表示", CardIDs: []string{navmeta.CardSecBanHeatmap}},
	"honeypot_heatmap_cell": {Label: "HPセル詳細", Feature: "ヒートマップ詳細表示", CardIDs: []string{navmeta.CardSecHoneypotSummary}, ChildCardIDs: []string{navmeta.CardSecHoneypotHeatmap}},
	"honeypot_access":       {Label: "不審アクセス取得", Feature: "ハニーポットアクセス一覧", CardIDs: []string{navmeta.CardSecHoneypotSummary}, ChildCardIDs: []string{navmeta.CardSecHoneypotAccess}},
	"honeypot_all":          {Label: "ハニーポット統合取得", Feature: "概要/ヒートマップ/一覧を一括取得", CardIDs: []string{navmeta.CardSecHoneypotSummary}, ChildCardIDs: []string{navmeta.CardSecHoneypotHeatmap, navmeta.CardSecHoneypotAccess}},
	"threat_score_history":  {Label: "脅威スコア履歴", Feature: "IP別スコア推移表示", CardIDs: []string{navmeta.CardSecThreatScore}},
	"threat_event_history":  {Label: "脅威イベント履歴", Feature: "IP別イベント詳細表示", CardIDs: []string{navmeta.CardSecThreatScore}},
	"search_ip":             {Label: "IP横断検索", Feature: "IP詳細モーダル表示", CardIDs: []string{navmeta.CardSecIPMgmt, navmeta.CardSecThreatScore, navmeta.CardSecNcHighScore, navmeta.CardSecNginxLog, navmeta.CardSecHoneypotAccess, navmeta.CardSecNc4xxAccess}},
}

func GetAuthzCatalog() authzCatalogResponse {
	roles := []authzRoleEntry{
		{ID: string(auth.RoleVendorStaff), DefaultScreens: auth.DefaultAccessScreens(string(auth.RoleVendorStaff))},
		{ID: string(auth.RoleTenantAdmin), DefaultScreens: auth.DefaultAccessScreens(string(auth.RoleTenantAdmin))},
		{ID: string(auth.RoleTenantUser), DefaultScreens: auth.DefaultAccessScreens(string(auth.RoleTenantUser))},
	}
	screens := []authzScreenEntry{
		{ID: string(auth.ScreenMonitor)},
	}

	cardIDMap := navmeta.MonitorCardIDs()
	seen := map[string]struct{}{}
	cards := make([]string, 0, len(cardIDMap))
	for _, id := range cardIDMap {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		cards = append(cards, id)
	}
	sort.Strings(cards)

	return authzCatalogResponse{
		Roles:      roles,
		Screens:    screens,
		Cards:      cards,
		ChildCards: map[string][]string{},
		Actions:    authzActionList(),
	}
}

func authzActionList() []authzActionEntry {
	destructive := []string{
		"reboot", "restart_heartdesk", "maintenance_on", "maintenance_off", "nc_repair",
		"apt_update", "apt_upgrade", "apt_full_upgrade",
		"toggle_auto_update", "fail2ban_ban", "fail2ban_unban",
		"ip_add", "ip_remove", "ip_rename", "ip_changetype",
		"highscore_dismiss", "highscore_ban", "bulk_ban",
		"backup_run", "save_alert_rules", "save_alert_recipients",
	}
	readonly := []string{
		"nginx_log", "nginx_url_detail", "ban_heatmap_cell", "honeypot_heatmap_cell",
		"honeypot_access", "honeypot_all", "threat_score_history", "threat_event_history", "search_ip",
	}
	entries := make([]authzActionEntry, 0, len(destructive)+len(readonly))
	for _, id := range destructive {
		entries = append(entries, authzActionEntry{
			ID:              id,
			Destructive:     true,
			Label:           authzActionLabel(id),
			Feature:         authzActionFeature(id),
			CardLabels:      authzActionCardLabels(id),
			ChildCardLabels: authzActionChildCardLabels(id),
		})
	}
	for _, id := range readonly {
		entries = append(entries, authzActionEntry{
			ID:              id,
			Destructive:     false,
			Label:           authzActionLabel(id),
			Feature:         authzActionFeature(id),
			CardLabels:      authzActionCardLabels(id),
			ChildCardLabels: authzActionChildCardLabels(id),
		})
	}
	return entries
}

func authzActionLabel(id string) string {
	if meta, ok := authzActionMetaByID[id]; ok && strings.TrimSpace(meta.Label) != "" {
		return meta.Label
	}
	return id
}

func authzActionFeature(id string) string {
	if meta, ok := authzActionMetaByID[id]; ok {
		return strings.TrimSpace(meta.Feature)
	}
	return ""
}

func authzActionCardLabels(id string) []string {
	meta, ok := authzActionMetaByID[id]
	if !ok || len(meta.CardIDs) == 0 {
		return nil
	}
	return authzCardLabels(meta.CardIDs)
}

func authzActionChildCardLabels(id string) []string {
	meta, ok := authzActionMetaByID[id]
	if !ok || len(meta.ChildCardIDs) == 0 {
		return nil
	}
	return authzCardLabels(meta.ChildCardIDs)
}

func authzCardLabels(cardIDs []string) []string {
	if len(cardIDs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(cardIDs))
	labels := make([]string, 0, len(cardIDs))
	for _, cardID := range cardIDs {
		id := strings.TrimSpace(cardID)
		if id == "" {
			continue
		}
		label := navmeta.LabelOrID(id)
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		labels = append(labels, label)
	}
	return labels
}

// authzUserPolicy は UI 向けに返すユーザー単位ポリシー。
// cards_user.toml / actions_user.toml に対応する。
type authzUserPolicy struct {
	// Deny は actions_user.toml の [users.<username>].deny（追加禁止アクションID）。
	Deny []string `json:"deny"`
	// HideCards は cards_user.toml の [users.<username>].hide_cards（追加非表示カードID）。
	HideCards []string `json:"hide_cards"`
	// HideChildCards は cards_user.toml の [users.<username>].hide_child_cards。
	HideChildCards map[string][]string `json:"hide_child_cards"`
}

type authzUserEntry struct {
	Username      string           `json:"username"`
	Name          string           `json:"name"`
	Role          string           `json:"role"`
	Disabled      bool             `json:"disabled"`
	AccessScreens []string         `json:"access_screens"`
	Policy        authzUserPolicy  `json:"policy"`
	AuthnStatus   authzAuthnStatus `json:"authn_status"`
}

type authzAuthnStatus struct {
	TOTPEnabled bool `json:"totp_enabled"`
	Locked      bool `json:"locked"`
}

type authzUsersResponse struct {
	Users []authzUserEntry `json:"users"`
}

func GetAuthzPolicyUsers() authzUsersResponse {
	store := auth.DefaultStore()
	totp := auth.DefaultTOTPManager()
	lockout := auth.DefaultLockoutManager()
	now := time.Now()

	actionsUser := authz.ActionsUser()
	cardsUser := authz.CardsUser()

	users := store.ListUsers()
	entries := make([]authzUserEntry, 0, len(users))
	for _, u := range users {
		// access_screens は users.toml の明示値のみ返す（role 既定値フォールバックなし）。
		// 空配列は「全画面不可」状態として UI に見せる。
		screens := append([]string(nil), u.AccessScreens...)
		policy := authzUserPolicy{}
		if au, ok := actionsUser.Users[u.Username]; ok {
			policy.Deny = append([]string(nil), au.Deny...)
		}
		if cu, ok := cardsUser.Users[u.Username]; ok {
			policy.HideCards = append([]string(nil), cu.HideCards...)
			if len(cu.HideChildCards) > 0 {
				policy.HideChildCards = make(map[string][]string, len(cu.HideChildCards))
				for parent, ids := range cu.HideChildCards {
					policy.HideChildCards[parent] = append([]string(nil), ids...)
				}
			}
		}
		entries = append(entries, authzUserEntry{
			Username:      u.Username,
			Name:          u.Name,
			Role:          u.Role,
			Disabled:      u.Disabled,
			AccessScreens: screens,
			Policy:        policy,
			AuthnStatus: authzAuthnStatus{
				TOTPEnabled: totp.IsEnabled(u.Username),
				Locked:      lockout.IsLocked(u.Username, "", now),
			},
		})
	}
	return authzUsersResponse{Users: entries}
}

type authzCreateRequest struct {
	Username      string   `json:"username"`
	Name          string   `json:"name"`
	Role          string   `json:"role"`
	Password      string   `json:"password"`
	AccessScreens []string `json:"access_screens"`
}

func CreateUser(w http.ResponseWriter, r *http.Request) {
	if requireVendorStaff(w, r) {
		return
	}
	var req authzCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeActionError(w, "リクエスト解析失敗: "+err.Error(), http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		writeActionError(w, "username が指定されていません", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Password) == "" {
		writeActionError(w, "パスワードが指定されていません", http.StatusBadRequest)
		return
	}
	newRole := auth.NormalizeRole(req.Role)
	if newRole == "" {
		writeActionError(w, "無効なロール値です: "+req.Role, http.StatusBadRequest)
		return
	}
	store := auth.DefaultStore()
	if err := store.AddUser(username, req.Name, string(newRole), req.Password); err != nil {
		writeActionError(w, "ユーザー作成に失敗しました: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if len(req.AccessScreens) > 0 {
		if err := store.UpdateAccessScreens(username, req.AccessScreens); err != nil {
			writeActionError(w, "アクセス画面設定の更新に失敗しました: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeActionOK(w, username+" を作成しました")
}

type authzSaveRequest struct {
	Username      string          `json:"username"`
	Role          string          `json:"role"`
	AccessScreens []string        `json:"access_screens"`
	Policy        authzUserPolicy `json:"policy"`
}

func SaveAuthzPolicy(w http.ResponseWriter, r *http.Request) {
	if requireVendorStaff(w, r) {
		return
	}
	var req authzSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeActionError(w, "リクエスト解析失敗: "+err.Error(), http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		writeActionError(w, "username が指定されていません", http.StatusBadRequest)
		return
	}
	store := auth.DefaultStore()
	currentUser, ok := store.GetUser(username)
	if !ok {
		writeActionError(w, "ユーザーが見つかりません: "+username, http.StatusNotFound)
		return
	}
	newRole := auth.NormalizeRole(req.Role)
	if newRole == "" {
		writeActionError(w, "無効なロール値です: "+req.Role, http.StatusBadRequest)
		return
	}
	if newRole != currentUser.Role {
		if err := store.UpdateUserRole(username, newRole); err != nil {
			writeActionError(w, "ロール更新に失敗しました: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := store.UpdateAccessScreens(username, req.AccessScreens); err != nil {
		writeActionError(w, "アクセス画面設定の更新に失敗しました: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := authz.SetUserDenyActions(username, req.Policy.Deny); err != nil {
		writeActionError(w, "actions_user.toml の更新に失敗しました: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := authz.SetUserHideCards(username, req.Policy.HideCards, req.Policy.HideChildCards); err != nil {
		writeActionError(w, "cards_user.toml の更新に失敗しました: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// role / access_screens / actions deny / cards hide が変わったら
	// 既存セッションに焼き込まれたキャッシュ（Session.Role / AccessScreens /
	// ActionPermissions / CardModes / ChildCardModes）が古いまま使われ続けるため、
	// 対象ユーザーの全セッションを無効化して次回ログインで再評価させる。
	auth.DefaultSessionManager().DeleteByUsername(username, "")
	writeActionOK(w, username+" のポリシーを保存しました")
}

type authzResetRequest struct {
	Username string `json:"username"`
}

type authzDeleteRequest struct {
	Username string `json:"username"`
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	if requireVendorStaff(w, r) {
		return
	}
	var req authzDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeActionError(w, "リクエスト解析失敗: "+err.Error(), http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		writeActionError(w, "username が指定されていません", http.StatusBadRequest)
		return
	}
	store := auth.DefaultStore()
	if err := store.DeleteUser(username); err != nil {
		writeActionError(w, "ユーザー削除に失敗しました: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// user 層の TOML エントリも連動削除（ファイル未存在や未登録ユーザーは no-op）
	if err := authz.DeleteUserEntries(username); err != nil {
		writeActionError(w, "user ポリシーファイルの削除に失敗しました: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// 削除されたユーザーの既存セッションを全消し（exceptID="" ）。
	// SessionManager.Get は次回アクセス時に UserStore で再評価して落とすが、
	// 即時切断が望ましい削除フローでは明示的に bulk-delete する。
	auth.DefaultSessionManager().DeleteByUsername(username, "")
	writeActionOK(w, username+" を削除しました")
}

func ResetAuthzPolicy(w http.ResponseWriter, r *http.Request) {
	if requireVendorStaff(w, r) {
		return
	}
	var req authzResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeActionError(w, "リクエスト解析失敗: "+err.Error(), http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		writeActionError(w, "username が指定されていません", http.StatusBadRequest)
		return
	}
	store := auth.DefaultStore()
	if _, ok := store.GetUser(username); !ok {
		writeActionError(w, "ユーザーが見つかりません: "+username, http.StatusNotFound)
		return
	}
	if err := store.ResetAccessScreens(username); err != nil {
		writeActionError(w, "access_screens のリセットに失敗しました: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := authz.DeleteUserEntries(username); err != nil {
		writeActionError(w, "user ポリシーファイルのリセットに失敗しました: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// ポリシーリセットも SaveAuthzPolicy 同様にセッション側の
	// 焼き込みキャッシュが古くなるため、対象ユーザーの全セッションを無効化する。
	auth.DefaultSessionManager().DeleteByUsername(username, "")
	writeActionOK(w, username+" のポリシーを既定値にリセットしました")
}
