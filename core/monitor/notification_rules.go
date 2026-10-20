package monitor

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/alerts"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

func alertRulesPath(cfg *config.AppConfig) string {
	if cfg != nil && strings.TrimSpace(cfg.Alerts.RulesFile) != "" {
		return strings.TrimSpace(cfg.Alerts.RulesFile)
	}
	return heartdesk.Path("data/json/alert_rules.json")
}

func alertStatePath(cfg *config.AppConfig) string {
	if cfg != nil && strings.TrimSpace(cfg.Alerts.StateFile) != "" {
		return strings.TrimSpace(cfg.Alerts.StateFile)
	}
	return "/tmp/heartdesk_alert_state.json"
}

var alertRulesMu sync.RWMutex

// AlertRuleDefOrder はルール定義の表示順
var AlertRuleDefOrder = []string{
	"memory_high",
	"disk_high",
	"service_down_nginx",
	"service_down_mariadb",
	"threat_score_critical",
	"nc_user_created",
	"nc_user_first_login",
	"nc_mass_access",
	"nc_folder_sweep",
	"nc_new_ip_access",
	"nc_off_hours_access",
	"nc_public_link_burst",
	"nc_service_new_ip",
	"nc_service_volume",
}

// ncCountThresholdMax は Nextcloud の取得ルール（件数で判定する）のしきい値の上限。
const ncCountThresholdMax = 100000

// AlertRuleDefs はアラートルールの静的定義
var AlertRuleDefs = map[string]AlertRuleDef{
	"memory_high": {
		Label: "メモリ高騰", Desc: "使用量/合計メモリ", HasThreshold: true, HasRecovery: true, HasSustain: true,
	},
	"disk_high": {
		Label: "ディスク逼迫", Desc: "使用量/合計ディスク (/)", HasThreshold: true, HasRecovery: true, HasSustain: true,
	},
	"service_down_nginx": {
		Label: "サービス停止 (nginx)", Desc: "nginx稼働状態", HasSustain: true,
	},
	"service_down_mariadb": {
		Label: "サービス停止 (mariadb)", Desc: "mariadb稼働状態", HasSustain: true,
	},
	"threat_score_critical": {
		Label: "脅威スコア100到達", Desc: "最大脅威スコア値", HasThreshold: true, HasRecovery: true,
	},
	"nc_user_created": {
		Label: "Nextcloud 新規ユーザー作成", Desc: "audit.log の User created",
	},
	"nc_user_first_login": {
		Label: "Nextcloud 新規ユーザー初回ログイン", Desc: "作成後最初の Login successful",
	},
	// 以下は audit.log の取得記録を 1 時間の窓で数えるルール（internal/alerts/nc_file_access.go）。
	// 既定値は internal/alerts の ncFADefaults と同じ値にしておく。
	// しきい値は 1 以上の整数（nc_service_volume だけは 0＝判定しない も可）。
	"nc_mass_access": {
		Label: "Nextcloud 大量取得", Desc: "1人の直近60分の取得件数",
		HasThreshold: true, ThresholdMin: 1, ThresholdMax: ncCountThresholdMax, IntegerThreshold: true,
		DefaultThreshold: 300, DefaultCooldownSec: 10800,
	},
	"nc_folder_sweep": {
		// 数えられるフォルダは 1 人 1 窓あたり alerts 側の上限まで。それより大きいしきい値は届かない。
		Label: "Nextcloud 多数フォルダ巡回", Desc: "1人の直近60分に取得したフォルダ数",
		HasThreshold: true, ThresholdMin: 1, ThresholdMax: alerts.NCFileAccessMaxFoldersPerUser, IntegerThreshold: true,
		DefaultThreshold: 50, DefaultCooldownSec: 10800,
	},
	"nc_new_ip_access": {
		Label: "Nextcloud 初めての接続元からの取得", Desc: "過去30日に使っていない接続元からの直近60分の取得件数・集計開始から3日は判定しない",
		HasThreshold: true, ThresholdMin: 1, ThresholdMax: ncCountThresholdMax, IntegerThreshold: true,
		DefaultThreshold: 50, DefaultCooldownSec: 10800,
	},
	"nc_off_hours_access": {
		Label: "Nextcloud 夜間・土日の取得", Desc: "直近60分のうち JST 22:00〜06:00・土日の取得件数",
		HasThreshold: true, ThresholdMin: 1, ThresholdMax: ncCountThresholdMax, IntegerThreshold: true,
		DefaultThreshold: 100, DefaultCooldownSec: 86400,
	},
	"nc_public_link_burst": {
		Label: "Nextcloud 公開リンクへの集中アクセス", Desc: "公開リンク1本への直近60分のアクセス数",
		HasThreshold: true, ThresholdMin: 1, ThresholdMax: ncCountThresholdMax, IntegerThreshold: true,
		DefaultThreshold: 50, DefaultCooldownSec: 10800,
	},
	"nc_service_new_ip": {
		Label: "Nextcloud 連携アカウントの見知らぬ接続元", Desc: "連携アカウントが過去30日に使っていない接続元からの直近60分の記録数・集計開始から3日は判定しない",
		HasThreshold: true, ThresholdMin: 1, ThresholdMax: ncCountThresholdMax, IntegerThreshold: true,
		DefaultThreshold: 1, DefaultCooldownSec: 86400,
	},
	"nc_service_volume": {
		Label: "Nextcloud 連携アカウントの大量取得", Desc: "連携アカウントの直近60分の取得件数・0 は判定しない",
		HasThreshold: true, ThresholdMin: 0, ThresholdMax: ncCountThresholdMax, IntegerThreshold: true,
		DefaultThreshold: 0, DefaultCooldownSec: 10800,
	},
}

// LoadAlertRules は alert_rules.json を読み込む
func LoadAlertRules(cfg *config.AppConfig) AlertRulesFile {
	alertRulesMu.RLock()
	defer alertRulesMu.RUnlock()

	raw, err := os.ReadFile(alertRulesPath(cfg))
	if err != nil {
		return AlertRulesFile{
			Rules:      map[string]AlertRuleConfig{},
			Recipients: []AlertRecipient{},
		}
	}
	var f AlertRulesFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return AlertRulesFile{
			Rules:      map[string]AlertRuleConfig{},
			Recipients: []AlertRecipient{},
		}
	}
	if f.Rules == nil {
		f.Rules = map[string]AlertRuleConfig{}
	}
	if f.Recipients == nil {
		f.Recipients = []AlertRecipient{}
	}
	return f
}

// saveAlertRulesFile は alert_rules.json に書き込む（書き込みロック済みで呼ぶこと）
func saveAlertRulesFile(cfg *config.AppConfig, f AlertRulesFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(alertRulesPath(cfg), data, 0644)
}

// SaveAlertRules はアラートルール設定を保存する
func SaveAlertRules(cfg *config.AppConfig, payload map[string]map[string]string) (ok bool, errors []string) {
	alertRulesMu.Lock()
	defer alertRulesMu.Unlock()

	raw, _ := os.ReadFile(alertRulesPath(cfg))
	var f AlertRulesFile
	if raw != nil {
		json.Unmarshal(raw, &f)
	}
	if f.Rules == nil {
		f.Rules = map[string]AlertRuleConfig{}
	}

	newRules := map[string]AlertRuleConfig{}
	for _, ruleID := range AlertRuleDefOrder {
		def := AlertRuleDefs[ruleID]
		vals, sent := payload[ruleID]
		cfg, saved := f.Rules[ruleID]

		if !sent {
			// フォームにこのルールの項目が無い（ルールを足す前に開いた画面から保存した等）。
			// エラーにせず、保存済みの値を残す。保存済みでなければ既定値・無効にする。
			if !saved {
				cfg = AlertRuleConfig{Threshold: def.DefaultThreshold, CooldownSec: def.DefaultCooldownSec}
			}
			newRules[ruleID] = cfg
			continue
		}

		if def.HasThreshold {
			maxTh := 100.0
			if def.ThresholdMax > 0 {
				maxTh = def.ThresholdMax
			}
			th, err := strconv.ParseFloat(vals["threshold"], 64)
			if err != nil || th < def.ThresholdMin || th > maxTh || (def.IntegerThreshold && th != math.Trunc(th)) {
				errors = append(errors, fmt.Sprintf("%s: しきい値が不正です", ruleID))
				continue
			}
			cfg.Threshold = th
		}
		if def.HasRecovery {
			rv, err := strconv.ParseFloat(vals["recovery"], 64)
			if err != nil || rv < 0 || rv > 100 {
				errors = append(errors, fmt.Sprintf("%s: 復旧値が不正です", ruleID))
				continue
			}
			cfg.Recovery = rv
		}
		if def.HasSustain {
			ss, err := strconv.Atoi(vals["sustain_sec"])
			if err != nil || ss < 0 || ss > 86400 {
				errors = append(errors, fmt.Sprintf("%s: 継続秒が不正です", ruleID))
				continue
			}
			cfg.SustainSec = ss
		}
		cd, err := strconv.Atoi(vals["cooldown_sec"])
		if err != nil || cd < 0 || cd > 86400 {
			errors = append(errors, fmt.Sprintf("%s: クールダウン秒が不正です", ruleID))
			continue
		}
		cfg.CooldownSec = cd
		cfg.Enabled = vals["enabled"] == "1"
		cfg.NotifyRecovery = vals["notify_recovery"] == "1"
		newRules[ruleID] = cfg
	}

	if len(errors) > 0 {
		return false, errors
	}

	f.Rules = newRules
	if err := saveAlertRulesFile(cfg, f); err != nil {
		return false, []string{"保存に失敗しました: " + err.Error()}
	}
	return true, nil
}

// SaveAlertRecipients は通知先一覧を保存する
func SaveAlertRecipients(cfg *config.AppConfig, recipients []AlertRecipient) (ok bool, errors []string) {
	alertRulesMu.Lock()
	defer alertRulesMu.Unlock()

	raw, _ := os.ReadFile(alertRulesPath(cfg))
	var f AlertRulesFile
	if raw != nil {
		json.Unmarshal(raw, &f)
	}

	reEmail := regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	now := time.Now().In(heartdesk.JST()).Format("2006-01-02 15:04:05")

	for i, r := range recipients {
		if strings.TrimSpace(r.Name) == "" {
			errors = append(errors, fmt.Sprintf("%d行目: 名前は必須です", i+1))
			continue
		}
		if !reEmail.MatchString(r.Email) {
			errors = append(errors, fmt.Sprintf("%d行目: メールアドレスが不正です", i+1))
			continue
		}
		if r.ID == "" {
			recipients[i].ID = fmt.Sprintf("%d", time.Now().UnixNano())
		}
		recipients[i].UpdatedAt = now
	}
	if len(errors) > 0 {
		return false, errors
	}

	f.Recipients = recipients
	if err := saveAlertRulesFile(cfg, f); err != nil {
		return false, []string{"保存に失敗しました: " + err.Error()}
	}
	return true, nil
}

// bytesToHuman はバイト数を人間可読文字列に変換する
func bytesToHuman(b float64) string {
	if b >= 1073741824 {
		return fmt.Sprintf("%.1fGB", b/1073741824)
	}
	return fmt.Sprintf("%.0fMB", b/1048576)
}

// kbToHuman はKB単位を人間可読文字列に変換する
func kbToHuman(kb float64) string {
	if kb >= 1048576 {
		return fmt.Sprintf("%.1fGB", kb/1048576)
	}
	return fmt.Sprintf("%.0fMB", kb/1024)
}

// GetNotificationRulesAPIData はライブデータとルール設定をマージして返す
// PHP api/notification_rules.php api_notification_rules() 相当
func GetNotificationRulesAPIData(cfg *config.AppConfig) NotificationRulesAPIData {
	f := LoadAlertRules(cfg)

	// アラート状態ファイルを読む
	runtime := map[string]AlertRuleRuntime{}
	if stateRaw, err := os.ReadFile(alertStatePath(cfg)); err == nil {
		var stateData map[string]map[string]interface{}
		if json.Unmarshal(stateRaw, &stateData) == nil {
			for ruleID, st := range stateData {
				rt := AlertRuleRuntime{}
				if v, ok := st["active"].(bool); ok {
					rt.Active = v
					rt.Evaluated = true
				}
				runtime[ruleID] = rt
			}
		}
	}

	// メモリ
	memRaw := heartdesk.Run("free -b 2>/dev/null")
	if memRaw != "" {
		if m := regexp.MustCompile(`Mem:\s+(\d+)\s+(\d+)`).FindStringSubmatch(memRaw); m != nil {
			total, _ := strconv.ParseFloat(m[1], 64)
			used, _ := strconv.ParseFloat(m[2], 64)
			if total > 0 {
				memPct := math.Round(used/total*1000) / 10
				label := fmt.Sprintf("%s / %s (%.1f%%)", bytesToHuman(used), bytesToHuman(total), memPct)
				rt := runtime["memory_high"]
				rt.LastValue = label
				rt.Evaluated = true
				if !rt.Active {
					th := 90.0
					if r, ok := f.Rules["memory_high"]; ok && r.Threshold > 0 {
						th = r.Threshold
					}
					rt.Active = memPct >= th
				}
				runtime["memory_high"] = rt
			}
		}
	}

	// ディスク
	diskRaw := heartdesk.Run("df -P / 2>/dev/null | tail -1")
	if diskRaw != "" {
		// Filesystem 1024-blocks Used Available Capacity% Mounted
		if m := regexp.MustCompile(`\s+(\d+)\s+(\d+)\s+\d+\s+(\d+)%\s`).FindStringSubmatch(" " + diskRaw); m != nil {
			totalKB, _ := strconv.ParseFloat(m[1], 64)
			usedKB, _ := strconv.ParseFloat(m[2], 64)
			diskPct, _ := strconv.ParseFloat(m[3], 64)
			if totalKB > 0 {
				label := fmt.Sprintf("%s / %s (%d%%)", kbToHuman(usedKB), kbToHuman(totalKB), int(diskPct))
				rt := runtime["disk_high"]
				rt.LastValue = label
				rt.Evaluated = true
				if !rt.Active {
					th := 92.0
					if r, ok := f.Rules["disk_high"]; ok && r.Threshold > 0 {
						th = r.Threshold
					}
					rt.Active = diskPct >= th
				}
				runtime["disk_high"] = rt
			}
		}
	}

	// サービス状態
	svcOut := heartdesk.Run("systemctl is-active nginx mariadb 2>/dev/null")
	svcLines := strings.Split(strings.TrimSpace(svcOut), "\n")
	svcs := []string{"nginx", "mariadb"}
	for i, svc := range svcs {
		ruleID := "service_down_" + svc
		status := "unknown"
		if i < len(svcLines) {
			status = strings.TrimSpace(svcLines[i])
		}
		rt := runtime[ruleID]
		rt.LastValue = status
		if status != "" && status != "unknown" {
			rt.Evaluated = true
			if !rt.Active {
				rt.Active = status != "active"
			}
		}
		rt.ValueType = "service"
		runtime[ruleID] = rt
	}

	// 脅威スコア最大値
	scoreCSV := heartdesk.Path("data/csv/threat_score.csv")
	if lines, err := os.ReadFile(scoreCSV); err == nil {
		maxScore := 0
		for i, line := range strings.Split(string(lines), "\n") {
			if i == 0 || strings.TrimSpace(line) == "" {
				continue
			}
			parts := strings.SplitN(line, ",", 4)
			if len(parts) >= 3 {
				if s, err := strconv.Atoi(strings.TrimSpace(parts[2])); err == nil && s > maxScore {
					maxScore = s
				}
			}
		}
		rt := runtime["threat_score_critical"]
		rt.LastValue = strconv.Itoa(maxScore)
		rt.Evaluated = true
		if !rt.Active {
			th := 100
			if r, ok := f.Rules["threat_score_critical"]; ok && r.Threshold > 0 {
				th = int(r.Threshold)
			}
			rt.Active = maxScore >= th
		}
		runtime["threat_score_critical"] = rt
	}

	return NotificationRulesAPIData{
		Rules:   f.Rules,
		Runtime: runtime,
	}
}

// GetNotificationRulesCardData はカードテンプレート用データを返す
func GetNotificationRulesCardData(cfg *config.AppConfig) NotificationRulesCardData {
	f := LoadAlertRules(cfg)
	enabled := 0
	for _, r := range f.Recipients {
		if r.Enabled {
			enabled++
		}
	}
	return NotificationRulesCardData{
		DefOrder:     AlertRuleDefOrder,
		Defs:         AlertRuleDefs,
		Rules:        f.Rules,
		Recipients:   f.Recipients,
		EnabledCount: enabled,
	}
}
