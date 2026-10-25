package monitor

import (
	"github.com/ishizakahiroshi/heartdesk/internal"
	"sort"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/nclog"
)

// =============================================================================
// 監査ログ異常検知（audit_anomaly カード）
// =============================================================================

// AuditAnomalyLogLevels はログレベル別件数
type AuditAnomalyLogLevels struct {
	Recent map[string]int `json:"recent"` // {"warning":n,"error":n,"fatal":n}
	Prev   map[string]int `json:"prev"`
}

// AuditAnomalySummary は全体サマリ
type AuditAnomalySummary struct {
	WindowMin             int                   `json:"window_min"`
	TotalRecent           int                   `json:"total_recent"`
	TotalPrev             int                   `json:"total_prev"`
	ExcludedAppTrusted    int                   `json:"excluded_app_trusted"`
	ExcludedInternalNoise int                   `json:"excluded_internal_noise"`
	ExcludedLexiconNoise  int                   `json:"excluded_lexicon_noise"`
	LogLevels             AuditAnomalyLogLevels `json:"log_levels"`
}

// AuditAnomalyEntry は1件の異常イベント
type AuditAnomalyEntry struct {
	Event      string   `json:"event"`
	Recent     int      `json:"recent"`
	Prev       int      `json:"prev"`
	Ratio      *float64 `json:"ratio"`
	LastTime   string   `json:"last_time"`
	SampleUser string   `json:"sample_user"`
	SampleIP   string   `json:"sample_ip"`
}

// AuditAnomalyResponse は /api/monitor/audit_anomaly のレスポンス
type AuditAnomalyResponse struct {
	Summary   AuditAnomalySummary `json:"summary"`
	Anomalies []AuditAnomalyEntry `json:"anomalies"`
}

// auditLogRecord はaudit.logの1行
type auditLogRecord struct {
	Time       string `json:"time"`
	Event      string `json:"event"`
	EventType  string `json:"eventType"`
	EventTypel string `json:"eventtype"`
	Message    string `json:"message"`
	User       string `json:"user"`
	RemoteAddr string `json:"remoteAddr"`
	Level      *int   `json:"level"`
}

func (r *auditLogRecord) getEvent() string {
	if r.Event != "" {
		return r.Event
	}
	if r.EventType != "" {
		return r.EventType
	}
	if r.EventTypel != "" {
		return r.EventTypel
	}
	return r.Message
}

// auditAnomalyTrustedIPs はホワイトリスト + SSHAllowed の信頼済みIPを返す
func auditAnomalyTrustedIPs() map[string]bool {
	m := map[string]bool{}
	for _, ip := range strings.Split(heartdesk.Env("HEARTDESK_WHITELIST_IPS"), ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			m[ip] = true
		}
	}
	for ip := range loadSSHAllowedIPsMap() {
		m[ip] = true
	}
	return m
}

// auditAnomalyIsAppTrustedLogin は heartdesk_app ユーザーの信頼済みログインかを判定する
func auditAnomalyIsAppTrustedLogin(rec *auditLogRecord, trustedIPs map[string]bool) bool {
	user := strings.TrimSpace(rec.User)
	event := rec.getEvent()
	if event == "" {
		return false
	}
	principal := heartdesk.OperationalIdentity().TrustedAuditDBUser
	userIsApp := user == principal ||
		strings.Contains(event, `"`+principal+`"`) ||
		strings.Contains(event, `'`+principal+`'`)
	if !userIsApp {
		return false
	}
	ip := strings.TrimSpace(rec.RemoteAddr)
	if ip == "" || !trustedIPs[ip] {
		return false
	}
	eventLower := strings.ToLower(event)
	return strings.Contains(eventLower, "login attempt:") ||
		nclog.ExtractLoginResult(event) != ""
}

// auditAnomalyIsInternalNoise は内部ノイズかを判定する
func auditAnomalyIsInternalNoise(rec *auditLogRecord) bool {
	event := rec.getEvent()
	return strings.Contains(event, "Console command executed: status --output=json")
}

// auditAnomalyIsLexiconNoise は lexicon エラーノイズかを判定する
func auditAnomalyIsLexiconNoise(event string) bool {
	return strings.Contains(event, "not defined in the config lexicon")
}

// ncEventToAuditRecord は NCEvent を auditLogRecord に変換する
func ncEventToAuditRecord(ev NCEvent) auditLogRecord {
	return auditLogRecord{
		Time:       ev.TS,
		Event:      ev.Msg,
		Message:    ev.Msg,
		User:       ev.User,
		RemoteAddr: ev.IP,
	}
}

// GetAuditAnomaly は監査ログの異常検知結果を返す（api_audit_anomaly()相当）
func GetAuditAnomaly(agentID ...string) AuditAnomalyResponse {
	const windowMin = 60
	now := time.Now()
	cutRecent := now.Add(-time.Duration(windowMin) * time.Minute)
	cutPrev := cutRecent.Add(-time.Duration(windowMin) * time.Minute)

	trustedIPs := auditAnomalyTrustedIPs()

	// ローカル nextcloud.jsonl または Agent の audit.jsonl から読む
	ncEvents, _ := TailJSONL[NCEvent](ncAuditJSONLPath(agentID...), 5000)

	type eventAccumulator struct {
		recent     int
		prev       int
		lastTime   string
		sampleUser string
		sampleIP   string
	}
	events := map[string]*eventAccumulator{}
	totalRecent, totalPrev := 0, 0
	excludedAppTrusted, excludedInternalNoise, excludedLexiconNoise := 0, 0, 0

	for _, ev := range ncEvents {
		if ev.Source != "" && ev.Source != "audit" {
			continue
		}
		rec := ncEventToAuditRecord(ev)
		ts, ok := nclog.ParseTime(rec.Time)
		if !ok || ts.Before(cutPrev) {
			continue
		}

		if auditAnomalyIsAppTrustedLogin(&rec, trustedIPs) {
			excludedAppTrusted++
			continue
		}
		if auditAnomalyIsInternalNoise(&rec) {
			excludedInternalNoise++
			continue
		}

		event := strings.TrimSpace(rec.getEvent())
		if event == "" {
			event = "unknown"
		}
		eventRunes := []rune(event)
		if len(eventRunes) > 140 {
			event = string(eventRunes[:140])
		}

		if auditAnomalyIsLexiconNoise(event) {
			excludedLexiconNoise++
			continue
		}

		acc, exists := events[event]
		if !exists {
			acc = &eventAccumulator{}
			events[event] = acc
		}

		if ts.After(cutRecent) {
			acc.recent++
			totalRecent++
			acc.lastTime = rec.Time
			if acc.sampleUser == "" && rec.User != "" {
				acc.sampleUser = rec.User
			}
			if acc.sampleIP == "" && rec.RemoteAddr != "" {
				acc.sampleIP = rec.RemoteAddr
			}
		} else {
			acc.prev++
			totalPrev++
		}
	}

	// ログレベル集計（logs/nextcloud.jsonl の level フィールドから）
	logLevels := AuditAnomalyLogLevels{
		Recent: map[string]int{"warning": 0, "error": 0, "fatal": 0},
		Prev:   map[string]int{"warning": 0, "error": 0, "fatal": 0},
	}
	for _, ev := range ncEvents {
		if ev.TS == "" {
			continue
		}
		ts, ok := nclog.ParseTime(ev.TS)
		if !ok || ts.Before(cutPrev) {
			continue
		}
		label := ""
		switch ev.Level {
		case "warning":
			label = "warning"
		case "error":
			label = "error"
		case "fatal":
			label = "fatal"
		}
		if label == "" {
			continue
		}
		if ts.After(cutRecent) {
			logLevels.Recent[label]++
		} else {
			logLevels.Prev[label]++
		}
	}

	// 異常イベント抽出（直近5件以上 かつ 前期比2倍以上 or 前期0）
	var anomalies []AuditAnomalyEntry
	for event, acc := range events {
		if acc.recent < 5 {
			continue
		}
		if acc.prev > 0 && float64(acc.recent) < float64(acc.prev)*2 {
			continue
		}
		entry := AuditAnomalyEntry{
			Event:      event,
			Recent:     acc.recent,
			Prev:       acc.prev,
			LastTime:   acc.lastTime,
			SampleUser: acc.sampleUser,
			SampleIP:   acc.sampleIP,
		}
		if acc.prev > 0 {
			ratio := float64(acc.recent) / float64(acc.prev)
			entry.Ratio = &ratio
		}
		anomalies = append(anomalies, entry)
	}
	sort.Slice(anomalies, func(i, j int) bool {
		return anomalies[i].Recent > anomalies[j].Recent
	})
	if len(anomalies) > 20 {
		anomalies = anomalies[:20]
	}
	if anomalies == nil {
		anomalies = []AuditAnomalyEntry{}
	}

	return AuditAnomalyResponse{
		Summary: AuditAnomalySummary{
			WindowMin:             windowMin,
			TotalRecent:           totalRecent,
			TotalPrev:             totalPrev,
			ExcludedAppTrusted:    excludedAppTrusted,
			ExcludedInternalNoise: excludedInternalNoise,
			ExcludedLexiconNoise:  excludedLexiconNoise,
			LogLevels:             logLevels,
		},
		Anomalies: anomalies,
	}
}
