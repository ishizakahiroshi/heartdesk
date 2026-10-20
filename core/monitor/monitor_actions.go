package monitor

import (
	"encoding/json"
	"log"
	"mime"
	"net/http"
	"strings"
	"time"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/middleware"
	"github.com/ishizakahiroshi/heartdesk/internal/scheduler"
)

// pinLockKey は PIN ロックの単位キーを返す。
// セッションの username を優先し、取れない場合のみ trustedProxy 経由の実クライアント IP をフォールバックに使う。
// 生の X-Real-IP ヘッダは使わない（直結時の偽装でロックを回避させない）。
func pinLockKey(r *http.Request) string {
	if u := strings.TrimSpace(middleware.GetUser(r.Context())); u != "" {
		return "user:" + strings.ToLower(u)
	}
	return "ip:" + auth.TrustedClientIP(r)
}

// actionFormMaxMemory は multipart 解析でメモリに載せる上限。
// action 系の POST はテキストの key/value だけで、ファイルは送られない
// （ファイル添付があるのは avatar.go の別経路）。
const actionFormMaxMemory = 1 << 20 // 1MB

// parseActionForm は action POST の body を解析して r.Form を埋める。
//
// **net/http の ParseForm は body を読まない場合がある。** 読むのは content-type が
// application/x-www-form-urlencoded のときだけで、multipart/form-data のときは
// エラーも返さずに r.PostForm を空のまま返す。画面側の JS は FormData を
// fetch の body に渡す（= multipart/form-data で送る）ので、ParseForm だけで
// 受けると値が 1 つも届かない。
//
// 通知設定カードでは実際に、全ルールが「しきい値が不正です」で弾かれ、
// alert_rules.json が作られないままになったことがある。
//
// r.FormValue は内部で ParseMultipartForm を呼ぶので単体では問題ないが、
// 先に ParseForm が呼ばれて r.Form が非 nil になっていると再解析されない。
// r.Form / r.PostForm を直接読む handler は必ずこの関数を通すこと。
func parseActionForm(r *http.Request) error {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && mt == "multipart/form-data" {
		// ParseMultipartForm は内部で ParseForm も呼び、multipart の値を
		// r.PostForm と r.Form の両方へ積む。
		return r.ParseMultipartForm(actionFormMaxMemory)
	}
	return r.ParseForm()
}

func (h *Handler) actionFail2banBan(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	if err := BanIP(ip); err != nil {
		writeActionError(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeActionOK(w, ip+" を BAN しました")
}

func (h *Handler) actionFail2banUnban(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	jail := strings.TrimSpace(r.FormValue("jail"))
	if err := UnbanIP(ip, jail); err != nil {
		writeActionError(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeActionOK(w, ip+" を UNBAN しました")
}

func (h *Handler) actionBulkBan(w http.ResponseWriter, r *http.Request) {
	if err := parseActionForm(r); err != nil {
		writeActionError(w, "フォームの解析に失敗しました", http.StatusBadRequest)
		return
	}
	ips := r.Form["ban_ips[]"]
	if len(ips) == 0 {
		writeActionError(w, "BANするIPが指定されていません", http.StatusBadRequest)
		return
	}
	var banned []string
	var failed []string
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if err := BanIP(ip); err != nil {
			failed = append(failed, ip+": "+err.Error())
		} else {
			banned = append(banned, ip)
		}
	}
	var parts []string
	if len(banned) > 0 {
		parts = append(parts, strings.Join(banned, ", ")+" をBANしました")
	}
	if len(failed) > 0 {
		parts = append(parts, "失敗: "+strings.Join(failed, ", "))
	}
	writeActionOK(w, strings.Join(parts, "\n"))
}

// ---- IP 管理アクション（WLM 操作は PIN 検証必須）----

func (h *Handler) actionIPAdd(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	name := strings.TrimSpace(r.FormValue("name"))
	ipType := strings.TrimSpace(r.FormValue("type"))
	user := middleware.GetUser(r.Context())
	pin := strings.TrimSpace(r.FormValue("pin"))

	if ipType == "wlm" {
		if err := VerifyPIN(h.appCfg, pin, pinLockKey(r)); err != nil {
			writeActionError(w, err.Error(), http.StatusForbidden)
			return
		}
	}
	if err := AddIP(ip, name, ipType, user); err != nil {
		writeActionError(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeActionOK(w, ip+" を追加しました")
}

func (h *Handler) actionIPRemove(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	pin := strings.TrimSpace(r.FormValue("pin"))

	// WLM 削除のみ PIN 検証必須（実際の type をサーバー側 JSON から取得）
	if GetIPType(ip) == "wlm" {
		if err := VerifyPIN(h.appCfg, pin, pinLockKey(r)); err != nil {
			writeActionError(w, err.Error(), http.StatusForbidden)
			return
		}
	}
	if err := RemoveIP(ip); err != nil {
		writeActionError(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeActionOK(w, ip+" を削除しました")
}

func (h *Handler) actionIPRename(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	name := strings.TrimSpace(r.FormValue("name"))
	user := middleware.GetUser(r.Context())
	if err := RenameIP(ip, name, user); err != nil {
		writeActionError(w, err.Error(), http.StatusBadRequest)
		return
	}
	now := time.Now().In(sab.JST())
	nowRaw := now.Format("2006-01-02 15:04:05")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ActionResponse{
		OK:               true,
		Message:          ip + " の名称を変更しました",
		UpdatedBy:        user,
		UpdatedAt:        nowRaw,
		UpdatedAtDisplay: sab.FormatDatetime(now),
	})
}

func (h *Handler) actionIPChangeType(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	ipType := strings.TrimSpace(r.FormValue("type"))
	user := middleware.GetUser(r.Context())
	pin := strings.TrimSpace(r.FormValue("pin"))

	if ipType == "wlm" {
		if err := VerifyPIN(h.appCfg, pin, pinLockKey(r)); err != nil {
			writeActionError(w, err.Error(), http.StatusForbidden)
			return
		}
	}
	if err := ChangeTypeIP(ip, ipType, user); err != nil {
		writeActionError(w, err.Error(), http.StatusBadRequest)
		return
	}
	now := time.Now().In(sab.JST())
	nowRaw := now.Format("2006-01-02 15:04:05")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ActionResponse{
		OK:               true,
		Message:          ip + " の種別を変更しました",
		UpdatedBy:        user,
		UpdatedAt:        nowRaw,
		UpdatedAtDisplay: sab.FormatDatetime(now),
	})
}

func (h *Handler) actionWLAdd(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	name := strings.TrimSpace(r.FormValue("name"))
	user := middleware.GetUser(r.Context())
	if err := AddIP(ip, name, "wl", user); err != nil {
		writeActionError(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeActionOK(w, ip+" をWLに追加しました")
}

func (h *Handler) actionWLRemove(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	if err := RemoveIP(ip); err != nil {
		writeActionError(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeActionOK(w, ip+" をWLから削除しました")
}

// ---- セキュリティ系アクション ----

func (h *Handler) actionHighScoreDismiss(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	if !isValidIP(ip) {
		writeActionError(w, "不正な IP アドレスです", http.StatusBadRequest)
		return
	}
	if err := DismissHighScore(ip); err != nil {
		writeActionError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeActionOK(w, ip+" を 24 時間無視リストに追加しました")
}

func (h *Handler) actionHighScoreBan(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	if !isValidIP(ip) {
		writeActionError(w, "不正な IP アドレスです", http.StatusBadRequest)
		return
	}
	if err := BanHighScore(ip); err != nil {
		writeActionError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeActionOK(w, ip+" を recidive jail に BAN しました")
}

// isValidIP は fail2ban.go で定義済み

// ---- コアカード Phase2 アクション ----

func (h *Handler) actionSaveAlertRules(w http.ResponseWriter, r *http.Request) {
	if err := parseActionForm(r); err != nil {
		writeActionError(w, "リクエスト解析失敗", http.StatusBadRequest)
		return
	}
	// alert_rules[rule_id][field] 形式をネストマップに変換
	payload := map[string]map[string]string{}
	for key, vals := range r.Form {
		if !strings.HasPrefix(key, "alert_rules[") {
			continue
		}
		trimmed := strings.TrimPrefix(key, "alert_rules[")
		parts := strings.SplitN(trimmed, "][", 2)
		if len(parts) != 2 {
			continue
		}
		ruleID := parts[0]
		field := strings.TrimSuffix(parts[1], "]")
		if payload[ruleID] == nil {
			payload[ruleID] = map[string]string{}
		}
		if len(vals) > 0 {
			payload[ruleID][field] = vals[0]
		}
	}
	ok, errs := SaveAlertRules(h.appCfg, payload)
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": ok, "errors": errs})
}

func (h *Handler) actionSaveAlertRecipients(w http.ResponseWriter, r *http.Request) {
	if err := parseActionForm(r); err != nil {
		writeActionError(w, "リクエスト解析失敗", http.StatusBadRequest)
		return
	}
	// recipients[][field] 形式をスライスに変換
	// まずインデックスの最大値を把握する
	maxIdx := -1
	for key := range r.Form {
		if !strings.HasPrefix(key, "recipients[") {
			continue
		}
		trimmed := strings.TrimPrefix(key, "recipients[")
		idxEnd := strings.Index(trimmed, "]")
		if idxEnd < 0 {
			continue
		}
		idx := parseIntParam(trimmed[:idxEnd], -1)
		if idx > maxIdx {
			maxIdx = idx
		}
	}
	recipients := make([]AlertRecipient, maxIdx+1)
	for key, vals := range r.Form {
		if !strings.HasPrefix(key, "recipients[") || len(vals) == 0 {
			continue
		}
		trimmed := strings.TrimPrefix(key, "recipients[")
		parts := strings.SplitN(trimmed, "][", 2)
		if len(parts) != 2 {
			continue
		}
		idx := parseIntParam(parts[0], -1)
		if idx < 0 || idx > maxIdx {
			continue
		}
		field := strings.TrimSuffix(parts[1], "]")
		val := vals[0]
		switch field {
		case "id":
			recipients[idx].ID = val
		case "name":
			recipients[idx].Name = val
		case "email":
			recipients[idx].Email = val
		case "enabled":
			recipients[idx].Enabled = val == "1"
		}
	}
	// 空エントリ（name/email 両方空）を除去
	var filtered []AlertRecipient
	for _, rec := range recipients {
		if strings.TrimSpace(rec.Name) != "" || strings.TrimSpace(rec.Email) != "" {
			filtered = append(filtered, rec)
		}
	}
	ok, errs := SaveAlertRecipients(h.appCfg, filtered)
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": ok, "errors": errs})
}

func (h *Handler) actionRunSchedulerJob(w http.ResponseWriter, r *http.Request, api, jobID string) {
	cfg, err := config.TryLoadSchedulerConfig()
	if err != nil {
		log.Printf("WARN: monitor: scheduler config not fully loaded (fallback defaults): %v", err)
	}
	s := scheduler.NewScheduler(cfg, log.Default())
	if err := s.RunJob(r.Context(), jobID); err != nil {
		writeActionError(w, "ジョブ実行に失敗しました ("+api+" -> "+jobID+"): "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeActionOK(w, "ジョブを実行しました ("+api+" -> "+jobID+")")
}

// ---- APIServices は旧エンドポイント（main.go 経由）との互換用 ----

// APIServices は GET /nab/api/monitor/services のハンドラ
func (h *Handler) APIServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(GetServices(h.appCfg)); err != nil {
		log.Printf("ERROR: monitor: api/services encode error: %v", err)
	}
}

// actionUpdateProfileName は自分自身の表示名を更新する
func (h *Handler) actionUpdateProfileName(w http.ResponseWriter, r *http.Request) {
	username := middleware.GetUser(r.Context())
	if username == "" {
		writeActionError(w, "未認証", http.StatusUnauthorized)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || len([]rune(name)) > 50 {
		writeActionError(w, "名前が無効です（1〜50文字）", http.StatusBadRequest)
		return
	}
	if err := auth.DefaultStore().UpdateName(username, name); err != nil {
		writeActionError(w, "更新に失敗しました: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"message": "表示名を更新しました",
		"name":    name,
		"initial": resolveInitialFromName(name),
	})
}

func (h *Handler) actionUpdatePassword(w http.ResponseWriter, r *http.Request) {
	username := middleware.GetUser(r.Context())
	if username == "" {
		writeActionError(w, "未認証", http.StatusUnauthorized)
		return
	}
	current := strings.TrimSpace(r.FormValue("current_password"))
	next := strings.TrimSpace(r.FormValue("new_password"))
	confirm := strings.TrimSpace(r.FormValue("confirm_password"))
	if len(next) < 8 {
		writeActionError(w, "新しいパスワードは8文字以上で入力してください", http.StatusBadRequest)
		return
	}
	if next != confirm {
		writeActionError(w, "確認用パスワードが一致しません", http.StatusBadRequest)
		return
	}
	if _, err := auth.DefaultStore().Authenticate(username, current); err != nil {
		writeActionError(w, "現在のパスワードが正しくありません", http.StatusBadRequest)
		return
	}
	if err := auth.DefaultStore().UpdatePassword(username, next); err != nil {
		writeActionError(w, "パスワード更新に失敗しました: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// パスワード変更時は、他端末・他ブラウザの既存セッションを強制無効化する。自端末（現セッション）は
	// exceptID で残し、操作中ユーザーをログアウトさせない。現セッション ID は
	// Cookie から直接取り、middleware を介さない（middleware は username しか露出しない）。
	exceptID := ""
	if sess, ok := auth.DefaultSessionManager().SessionFromRequest(r); ok {
		exceptID = sess.ID
	}
	auth.DefaultSessionManager().DeleteByUsername(username, exceptID)
	writeActionOK(w, "パスワードを更新しました")
}

func (h *Handler) actionTOTPGenerate(w http.ResponseWriter, r *http.Request) {
	username := middleware.GetUser(r.Context())
	if username == "" {
		writeActionError(w, "未認証", http.StatusUnauthorized)
		return
	}
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		writeActionError(w, "秘密鍵の生成に失敗しました", http.StatusInternalServerError)
		return
	}
	auth.DefaultTOTPManager().SetSecret(username, secret, false)
	uri := auth.TOTPProvisioningURI("SAB", username, secret)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":     true,
		"secret": secret,
		"uri":    uri,
	})
}

func (h *Handler) actionTOTPEnable(w http.ResponseWriter, r *http.Request) {
	username := middleware.GetUser(r.Context())
	if username == "" {
		writeActionError(w, "未認証", http.StatusUnauthorized)
		return
	}
	mgr := auth.DefaultTOTPManager()
	secret, enabled, ok := mgr.Get(username)
	if !ok || secret == "" {
		writeActionError(w, "先に秘密鍵を生成してください", http.StatusBadRequest)
		return
	}
	if enabled {
		writeActionOK(w, "2FAはすでに有効です")
		return
	}
	code := strings.TrimSpace(r.FormValue("totp_code"))
	// 検証＋有効化を TOTPManager に一本化し、
	// 消費カウンタを LastCounter へ記録する（有効化コードの直後ログイン再利用を防ぐ）。
	if !mgr.EnableAfterVerify(username, code, time.Now()) {
		writeActionError(w, "認証コードが正しくありません", http.StatusBadRequest)
		return
	}
	writeActionOK(w, "2FAを有効化しました")
}

func (h *Handler) actionTOTPDisable(w http.ResponseWriter, r *http.Request) {
	username := middleware.GetUser(r.Context())
	if username == "" {
		writeActionError(w, "未認証", http.StatusUnauthorized)
		return
	}
	auth.DefaultTOTPManager().Disable(username)
	writeActionOK(w, "2FAを無効化しました")
}

// resolveInitialFromName は名前文字列の先頭1文字を返す
func (h *Handler) actionSetMaintenance(w http.ResponseWriter, r *http.Request, on bool) {
	out, err := SetMaintenanceMode(on)
	if err != nil {
		msg := "メンテナンスモード変更に失敗しました"
		if out != "" {
			msg += ": " + out
		}
		writeActionError(w, msg, http.StatusInternalServerError)
		return
	}
	label := "OFF"
	if on {
		label = "ON"
	}
	writeActionOK(w, "メンテナンスモードを "+label+" にしました\n"+out)
}

func (h *Handler) actionNCRepair(w http.ResponseWriter, r *http.Request) {
	out, err := RunNCRepair()
	if err != nil {
		msg := "Nextcloud修復に失敗しました"
		if out != "" {
			msg += ": " + out
		}
		writeActionError(w, msg, http.StatusInternalServerError)
		return
	}
	writeActionOK(w, "Nextcloud修復が完了しました\n"+out)
}

func (h *Handler) actionRestartSab(w http.ResponseWriter, r *http.Request) {
	RestartSab()
	writeActionOK(w, "sabサービスの再起動を開始しました")
}

func (h *Handler) actionReboot(w http.ResponseWriter, r *http.Request) {
	Reboot()
	writeActionOK(w, "サーバー再起動を開始しました")
}

// ---- Updates アクション（P5） ----

func (h *Handler) actionAptUpdate(w http.ResponseWriter, r *http.Request) {
	RunAptUpdate()
	writeActionOK(w, "apt-get update をバックグラウンドで開始しました")
}

func (h *Handler) actionAptUpgrade(w http.ResponseWriter, r *http.Request) {
	RunAptUpgrade()
	writeActionOK(w, "apt-get upgrade をバックグラウンドで開始しました")
}

func (h *Handler) actionAptFullUpgrade(w http.ResponseWriter, r *http.Request) {
	RunAptFullUpgrade()
	writeActionOK(w, "apt-get full-upgrade をバックグラウンドで開始しました")
}

func (h *Handler) actionToggleAutoUpdate(w http.ResponseWriter, r *http.Request) {
	mode := strings.TrimSpace(r.FormValue("mode"))
	enable := mode == "enable"
	if err := ToggleAutoUpdate(enable); err != nil {
		writeActionError(w, "自動更新設定の変更に失敗しました: "+err.Error(), http.StatusInternalServerError)
		return
	}
	label := "無効"
	if enable {
		label = "有効"
	}
	writeActionOK(w, "自動更新を"+label+"にしました")
}
