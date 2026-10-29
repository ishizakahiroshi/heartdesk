// Package alerts はリソース／サービス停止／脅威スコア／アカウントロックアウトの
// アラート評価と、設定された SMTP 経由のメール通知を行う。
//
// 従来 cmd/alerts が別プロセス（exec.Command）で起動していた評価ロジックを
// パッケージとして抽出し、scheduler の daemon ジョブ（alerts）から in-process で
// 呼べるようにする。
//
// JSON スキーマは UI（web/notification_rules.go の AlertRulesFile）が書き出す
// alert_rules.json と完全一致させる（rules マップ + recipients + smtp）。これにより
// UI で編集したルール・受信者・SMTP 設定がそのまま反映される。パスは config 駆動
// （cfg.Alerts.* / cfg.Scheduler.*）で、未設定時は notification_rules.go と同じ
// data/json / data/csv 配下に解決する。
package alerts

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// AlertRule は 1 つのアラートルール（UI で編集する単位）。
// web/notification_rules.go の AlertRule と同一スキーマ。
type AlertRule struct {
	Enabled        bool    `json:"enabled"`
	Threshold      float64 `json:"threshold"`
	Recovery       float64 `json:"recovery"`
	SustainSec     int     `json:"sustain_sec"`
	CooldownSec    int     `json:"cooldown_sec"`
	NotifyRecovery bool    `json:"notify_recovery"`
}

// Recipient は通知先。画面（core/monitor の AlertRecipient）の enabled / rules と同じ意味を持つ。
//   - Enabled: false の宛先には送らない。キーが無い（nil）古い alert_rules.json は有効として扱う。
//   - Rules:   空でなければ、値が true のルールだけを受け取る。空なら全ルールを受け取る。
type Recipient struct {
	Name    string          `json:"name"`
	Email   string          `json:"email"`
	Enabled *bool           `json:"enabled,omitempty"`
	Rules   map[string]bool `json:"rules,omitempty"`
}

// wants は、この宛先が ruleID のメールを受け取るかを返す。
func (r Recipient) wants(ruleID string) bool {
	if r.Enabled != nil && !*r.Enabled {
		return false
	}
	if len(r.Rules) > 0 {
		return r.Rules[ruleID]
	}
	return true
}

// AlertRules は alert_rules.json のスキーマ（UI 保存・alerts 読込で共有）。
// web/notification_rules.go の AlertRulesFile と同一。
type AlertRules struct {
	Rules      map[string]AlertRule `json:"rules"`
	Recipients []Recipient          `json:"recipients"`
	SMTP       map[string]string    `json:"smtp"`
}

// AlertState はアラート状態の永続化。
//   - Active:         ルールごとの「現在発報中か」（recovery 通知の判定に使う）
//   - LastAlertTime:  ルールごとの最終発報時刻（cooldown 判定に使う）
//   - FirstBreach:    ルールごとの閾値超過開始時刻（sustainSec 判定に使う）
//   - Offsets:        ログファイルごとの読み取り済みバイトオフセット（tail 再開用）
//   - PendingNCUsers: Nextcloud 新規ユーザー作成を検出済みだが初回ログイン未検出の
//     uid（キーは "<スコープ>|<uid>"、値は作成検出時刻）。evaluateNCUserEvents 専用。
//     ncPendingUserTTL を超えたエントリは古いものとして破棄する。
type AlertState struct {
	Active         map[string]bool      `json:"active"`
	LastAlertTime  map[string]time.Time `json:"last_alert_time"`
	FirstBreach    map[string]time.Time `json:"first_breach"`
	Offsets        map[string]int64     `json:"offsets"`
	PendingNCUsers map[string]time.Time `json:"pending_nc_users"`
	// IntegrationHTTP: integration_http_error の未送信・送信済みの控え（キーはルール ID + 対象のハッシュ）。
	IntegrationHTTP map[string]*IntegrationHTTPItem `json:"integration_http,omitempty"`
}

// nowFn は現在時刻取得（テストで差し替え可能）。
var nowFn = time.Now

// sender はアラート発報の実体（テストで差し替え可能）。本番では sendAlert。
// 戻り値は「届けられたか」。メール送信を試みた全宛先で失敗したときだけ false
// （送信先が無い・SMTP 未設定で試みなかった場合は true）。
var sender = sendAlert

// rulesPath は alert ルールファイルのパスを config 駆動で解決する。
// notification_rules.go の解決方式に合わせ、未設定時は data/json 配下。
func rulesPath(cfg *config.AppConfig) string {
	if cfg != nil && cfg.Alerts.RulesFile != "" {
		return cfg.Alerts.RulesFile
	}
	return heartdesk.Path("data/json/alert_rules.json")
}

// statePath は alert state ファイルのパスを config 駆動で解決する。
// 旧 /tmp/heartdesk_alert_state.json をやめ、data/json 配下（reboot で消えない）に置く。
func statePath(cfg *config.AppConfig) string {
	return StatePath(cfg)
}

// StatePath は alert state ファイルのパスを返す。スケジューラ（Run）と、状態を画面に出す
// core/monitor が同じ関数でパスを決めるために公開している。cfg.Alerts.StateFile があればそれ、
// 無ければ HEARTDESK_BASE_DIR 基準の data/json/alert_state.json（BASE_DIR 未設定でも止まらない）。
func StatePath(cfg *config.AppConfig) string {
	if cfg != nil {
		if p := strings.TrimSpace(cfg.Alerts.StateFile); p != "" {
			return p
		}
	}
	return heartdesk.PathOrDefault("data/json/alert_state.json")
}

// ReadState は state ファイルを読んで返す（画面表示用）。ファイルが無い・壊れている・
// 旧形式（ルール ID をキーにした形）で読めない場合は、落とさずに空の state を返す。
func ReadState(path string) *AlertState {
	st, err := loadAlertState(path)
	if err != nil || st == nil {
		return newAlertState()
	}
	return st
}

// resourceLogPath は resource CSV のパスを config 駆動で解決する。
// collect.go が書き込む cfg.Scheduler.ResourceLogPath（未設定時は
// data/csv/resource_log.csv）を読む。collect_resources daemon ジョブが書く実ファイルと同一を参照する。
func resourceLogPath(cfg *config.AppConfig) string {
	if cfg != nil && cfg.Scheduler.ResourceLogPath != "" {
		return cfg.Scheduler.ResourceLogPath
	}
	return heartdesk.Path("data/csv/resource_log.csv")
}

// scoreCSVPath は脅威スコア CSV のパスを config 駆動で解決する。
// cfg.Scheduler.ScoreCSVPath（score_engine daemon ジョブが書く実ファイルと同一）
// → Path の順でフォールバックする。
func scoreCSVPath(cfg *config.AppConfig) string {
	if cfg != nil && cfg.Scheduler.ScoreCSVPath != "" {
		return cfg.Scheduler.ScoreCSVPath
	}
	return heartdesk.Path("data/csv/threat_score.csv")
}

// sshIPListPath は managed_ips.toml のパスを config 駆動で解決する。
// cfg.Scheduler.SSHIPListPath（score_engine と共有）→ Path の順でフォールバックする。
func sshIPListPath(cfg *config.AppConfig) string {
	if cfg != nil && cfg.Scheduler.SSHIPListPath != "" {
		return cfg.Scheduler.SSHIPListPath
	}
	return heartdesk.Path("config/managed_ips.toml")
}

// Run はアラート評価を 1 回実行し、発報したアラート文言を返す。
// scheduler の daemon ジョブ（alerts）と cmd/alerts CLI の双方から使う。
//
// rules/state の読み込みに失敗した場合（ファイル欠如を除く本物の parse error）は
// error を返す。呼び出し側（CLI）はそれを stderr + 非ゼロ終了に変換する。
// SMTP/recipients が未設定でも crash せず、評価とログだけ行いメール送信はスキップする。
func Run(cfg *config.AppConfig) ([]string, error) {
	prepareNotifiers(cfg)

	rules, err := loadAlertRules(rulesPath(cfg))
	if err != nil {
		return nil, fmt.Errorf("load alert rules: %w", err)
	}
	state, err := loadAlertState(statePath(cfg))
	if err != nil {
		return nil, fmt.Errorf("load alert state: %w", err)
	}

	var fired []string
	// 1. メモリ / ディスク
	fired = append(fired, evaluateResourceAlerts(resourceLogPath(cfg), rules, state)...)
	// 2. サービス停止（nginx / mariadb）
	fired = append(fired, evaluateServiceAlerts(rules, state)...)
	// 3. 脅威スコア
	fired = append(fired, evaluateThreatScore(scoreCSVPath(cfg), sshIPListPath(cfg), rules, state)...)
	// 4. アカウントロックアウト
	fired = append(fired, evaluateAccountLockout(lockoutLogPath(cfg), rules, state)...)
	// 5. Nextcloud 新規ユーザー作成・初回ログイン
	fired = append(fired, evaluateNCUserEvents(cfg, rules, state)...)
	// 6. Nextcloud のファイル大量取得（audit.log を直接読む。集計は nc_file_access_state.json）
	fired = append(fired, evaluateNCFileAccess(cfg, rules, state)...)
	// 7. 連携アプリ自身の HTTP エラー（受領書と突き合わせた結果。既定は無効）
	fired = append(fired, evaluateIntegrationHTTPError(cfg, rules, state)...)

	if err := saveAlertState(statePath(cfg), state); err != nil {
		// state 保存失敗は致命ではない（次回ログから再評価できる）が記録する。
		log.Printf("alerts: save state: %v", err)
	}
	return fired, nil
}

// loadAlertRules はルールファイルを読む。
// ファイルが存在しない場合は空ルール（error なし）。parse 失敗は error。
func loadAlertRules(path string) (AlertRules, error) {
	rules := AlertRules{Rules: map[string]AlertRule{}, Recipients: []Recipient{}, SMTP: map[string]string{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("alerts: rules file not found, using empty ruleset: %s", path)
			return rules, nil
		}
		return rules, err
	}
	if err := json.Unmarshal(data, &rules); err != nil {
		log.Printf("alerts: rules unmarshal error: %v", err)
		return rules, err
	}
	if rules.Rules == nil {
		rules.Rules = map[string]AlertRule{}
	}
	if rules.Recipients == nil {
		rules.Recipients = []Recipient{}
	}
	if rules.SMTP == nil {
		rules.SMTP = map[string]string{}
	}
	return rules, nil
}

// loadAlertState は状態ファイルを読む。
// ファイルが存在しない場合は初期 state（error なし）。parse 失敗は error。
func loadAlertState(path string) (*AlertState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return newAlertState(), nil
		}
		return nil, err
	}
	var st AlertState
	if err := json.Unmarshal(data, &st); err != nil {
		log.Printf("alerts: state unmarshal error: %v", err)
		return nil, err
	}
	st.ensureMaps()
	return &st, nil
}

// newAlertState は初期化済みの空 state を返す。
func newAlertState() *AlertState {
	st := &AlertState{}
	st.ensureMaps()
	return st
}

func (st *AlertState) ensureMaps() {
	if st.Active == nil {
		st.Active = map[string]bool{}
	}
	if st.LastAlertTime == nil {
		st.LastAlertTime = map[string]time.Time{}
	}
	if st.FirstBreach == nil {
		st.FirstBreach = map[string]time.Time{}
	}
	if st.Offsets == nil {
		st.Offsets = map[string]int64{}
	}
	if st.PendingNCUsers == nil {
		st.PendingNCUsers = map[string]time.Time{}
	}
	if st.IntegrationHTTP == nil {
		st.IntegrationHTTP = map[string]*IntegrationHTTPItem{}
	}
}

// saveAlertState は状態ファイルを書く。
func saveAlertState(path string, st *AlertState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// shouldAlert は cooldown + sustainSec を考慮して発報すべきか判定する。
// key は cooldown／sustain の集約キー（ルール ID など）。発報が許可されると
// FirstBreach をクリアし、LastAlertTime を now に更新して true を返す。
func shouldAlert(key string, sustainSec, cooldownSec int, state *AlertState, now time.Time) bool {
	// sustainSec: 閾値超過が sustainSec 秒間継続して初めて発報する。
	if sustainSec > 0 {
		first, ok := state.FirstBreach[key]
		if !ok {
			state.FirstBreach[key] = now
			return false
		}
		if now.Sub(first) < time.Duration(sustainSec)*time.Second {
			return false
		}
	}
	// cooldown: 直近発報から cooldownSec 秒は再発報しない。
	if cooldownSec > 0 {
		last, ok := state.LastAlertTime[key]
		if ok && now.Sub(last) < time.Duration(cooldownSec)*time.Second {
			return false
		}
	}
	delete(state.FirstBreach, key)
	state.LastAlertTime[key] = now
	return true
}

// clearBreach は閾値内に戻ったルールの sustain 開始時刻をリセットする。
func clearBreach(key string, state *AlertState) {
	delete(state.FirstBreach, key)
}

// fire は 1 件のアラートを記録し、設定があればメール送信する。
// 戻り値はログ／一覧表示用の文言。
func fire(rules AlertRules, ruleID, message string) string {
	sender(rules, ruleID, message)
	return message
}

// fireDelivered は fire と同じく 1 件を発報し、メールが届けられたかも返す。
// 呼び出し側は false のとき「発報済み」の状態を残さず、次回の評価で再試行する。
func fireDelivered(rules AlertRules, ruleID, message string) (string, bool) {
	return message, sender(rules, ruleID, message)
}

// alertKeyState は 1 つのルールキーについて shouldAlert が書き換える値の控え。
// 送信に失敗したとき、shouldAlert を呼ぶ前の状態へ戻して次回の評価で再試行できるようにする。
type alertKeyState struct {
	first    time.Time
	hasFirst bool
	last     time.Time
	hasLast  bool
}

func snapshotAlertKey(key string, state *AlertState) alertKeyState {
	var s alertKeyState
	s.first, s.hasFirst = state.FirstBreach[key]
	s.last, s.hasLast = state.LastAlertTime[key]
	return s
}

func (s alertKeyState) restore(key string, state *AlertState) {
	if s.hasFirst {
		state.FirstBreach[key] = s.first
	} else {
		delete(state.FirstBreach, key)
	}
	if s.hasLast {
		state.LastAlertTime[key] = s.last
	} else {
		delete(state.LastAlertTime, key)
	}
}

// fireTracked は shouldAlert が true を返した後の発報を行う。メールが全宛先で失敗したときは
// shouldAlert が進めた FirstBreach / LastAlertTime を snap の時点へ戻し、false を返す
// （呼び出し側は Active を立てない）。再試行は評価ごと（Run 1 回につき 1 回）で、
// 無限ループにはならない。
func fireTracked(rules AlertRules, ruleID, key string, state *AlertState, snap alertKeyState, message string) (string, bool) {
	msg, delivered := fireDelivered(rules, ruleID, message)
	if !delivered {
		snap.restore(key, state)
		log.Printf("alerts: delivery failed for %s (mail to every recipient failed); state not updated, will retry on next evaluation", ruleID)
	}
	return msg, delivered
}
