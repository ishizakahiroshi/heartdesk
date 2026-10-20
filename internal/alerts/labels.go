package alerts

// ruleLabels は rule ID → 画面と同じ日本語ラベル。
//
// 正典は core/monitor の AlertRuleDefs だが、**internal/alerts から core/monitor は
// 参照しない**（依存の向きが逆になる。判定ロジックを共有したときも internal/nclog を
// 挟んだ）。ここは表示名だけの写しなので小さな重複を許し、ズレは
// core/monitor 側の parity テストで検出する。
var ruleLabels = map[string]string{
	"memory_high":           "メモリ高騰",
	"disk_high":             "ディスク逼迫",
	"service_down_nginx":    "サービス停止 (nginx)",
	"service_down_mariadb":  "サービス停止 (mariadb)",
	"threat_score_critical": "脅威スコア100到達",
	"nc_user_created":       "Nextcloud 新規ユーザー作成",
	"nc_user_first_login":   "Nextcloud 新規ユーザー初回ログイン",
	"nc_mass_access":        "Nextcloud 大量取得",
	"nc_folder_sweep":       "Nextcloud 多数フォルダ巡回",
	"nc_new_ip_access":      "Nextcloud 初めての接続元からの取得",
	"nc_off_hours_access":   "Nextcloud 夜間・土日の取得",
	"nc_public_link_burst":  "Nextcloud 公開リンクへの集中アクセス",
	"nc_service_new_ip":     "Nextcloud 連携アカウントの見知らぬ接続元",
	"nc_service_volume":     "Nextcloud 連携アカウントの大量取得",
}

// NotifyRuleLabels は通知の見出しに使うラベル表の写しを返す。
//
// **照合専用**（core/monitor 側のテストが画面のラベルとのズレを見る）。
// internal/alerts から core/monitor は参照できない（core/monitor →
// internal/scheduler/daemon → internal/alerts の循環になる）ので、
// 突き合わせは参照できる側から行う。
func NotifyRuleLabels() map[string]string {
	out := make(map[string]string, len(ruleLabels))
	for k, v := range ruleLabels {
		out[k] = v
	}
	return out
}

// RuleLabel は通知の見出しに載せる件名を返す。未知の rule ID は ID をそのまま出す
// （知らないルールが来たときに件名が空になるより、ID が見えるほうが追える）。
// 追加の通知経路（RegisterNotifier）が見出しを作るときにも使う。
func RuleLabel(ruleID string) string {
	if label, ok := ruleLabels[ruleID]; ok {
		return label
	}
	return ruleID
}
