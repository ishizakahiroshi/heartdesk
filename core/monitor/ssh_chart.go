package monitor

import (
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

// SSHAttackEntry は1IPのSSH攻撃集計
type SSHAttackEntry struct {
	Count   int    `json:"count"`
	First   string `json:"first"`
	Last    string `json:"last"`
	Port    string `json:"port"`     // 送信元ポート（auth.log の port フィールド）
	DstPort string `json:"dst_port"` // 攻撃先ポート（syslog の SSH BLOCKED DPT フィールド）
}

// SSHChartResponse は /api/monitor/ssh_chart のレスポンス
type SSHChartResponse struct {
	SSHAttacks      map[string]*SSHAttackEntry `json:"ssh_attacks"`
	HourlyAttacks   []int                      `json:"hourly_attacks"`    // 直近24時間の時間帯別集計
	HourlyAttacks7d []int                      `json:"hourly_attacks_7d"` // 直近7日間の時間帯別集計
	HourlyMax       int                        `json:"hourly_max"`
	Flags           map[string]string          `json:"flags"`
	UpdatedAt       string                     `json:"updated_at"`
}

// =============================================================================
// 共通ヘルパー
// =============================================================================

// parsedSSHData は parseSSHAttacks() の内部結果
type parsedSSHData struct {
	Attacks   map[string]*SSHAttackEntry
	Hourly24h [24]int
	Hourly7d  [24]int
	Total     int
	Flags     map[string]string
	UpdatedAt string
}

// parseSSHAttacks は logs/ssh.jsonl を読み、SSH 攻撃データをまとめて返す共通ヘルパー。
// Agent が生成した JSONL を利用し、auth.log への直接アクセスは行わない。
func parseSSHAttacks(agentID ...string) parsedSSHData {
	jst := heartdesk.JST()
	now := time.Now().In(jst)
	cutoff24h := now.Add(-24 * time.Hour)
	cutoff7d := now.AddDate(0, 0, -7)

	jsonlPath := sshJSONLPath(agentID...)
	evs, _ := TailJSONL[SSHLogEvent](jsonlPath, 50000)

	wl := loadSSHAllowedIPsMap()
	attacks := make(map[string]*SSHAttackEntry)
	var hourly24h [24]int
	var hourly7d [24]int
	total := 0

	for _, ev := range evs {
		if ev.Event != "failed" && ev.Event != "invalid_user" {
			continue
		}
		if ev.IP == "" || wl[ev.IP] {
			continue
		}

		t, err := time.Parse(time.RFC3339, ev.TS)
		if err != nil {
			continue
		}
		t = t.In(jst)

		hour := t.Hour()
		dt := heartdesk.FormatDatetime(t)

		if e, ok := attacks[ev.IP]; ok {
			e.Count++
			if dt != "" && (e.First == "" || dt < e.First) {
				e.First = dt
			}
			if dt != "" && dt > e.Last {
				e.Last = dt
			}
		} else {
			attacks[ev.IP] = &SSHAttackEntry{Count: 1, First: dt, Last: dt, Port: ev.Port}
		}
		total++

		if !t.Before(cutoff7d) {
			hourly7d[hour]++
		}
		if !t.Before(cutoff24h) {
			hourly24h[hour]++
		}
	}

	ips := make([]string, 0, len(attacks))
	for ip := range attacks {
		ips = append(ips, ip)
	}
	flags := GetCountryFlags(ips)

	return parsedSSHData{
		Attacks:   attacks,
		Hourly24h: hourly24h,
		Hourly7d:  hourly7d,
		Total:     total,
		Flags:     flags,
		UpdatedAt: heartdesk.FormatDatetime(now),
	}
}

// loadSSHAllowedIPsMap は managed_ips 台帳からホワイトリスト IP セットを返す
func loadSSHAllowedIPsMap() map[string]bool {
	m := map[string]bool{"127.0.0.1": true}
	entries, err := loadManagedIPs()
	if err != nil {
		return m
	}
	for _, e := range entries {
		m[e.IP] = true
	}
	return m
}

// =============================================================================
// API
// =============================================================================

// GetSSHChart は auth.log を解析して SSH 攻撃時間帯別データを返す
func GetSSHChart(agentID ...string) SSHChartResponse {
	parsed := parseSSHAttacks(agentID...)

	// hourly_max（24h ベース）
	maxVal := 0
	for _, v := range parsed.Hourly24h {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal < 1 {
		maxVal = 1
	}

	return SSHChartResponse{
		SSHAttacks:      parsed.Attacks,
		HourlyAttacks:   parsed.Hourly24h[:],
		HourlyAttacks7d: parsed.Hourly7d[:],
		HourlyMax:       maxVal,
		Flags:           parsed.Flags,
		UpdatedAt:       parsed.UpdatedAt,
	}
}
