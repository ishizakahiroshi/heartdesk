package monitor

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
)

var knownJails = []string{"nextcloud", "nginx-suspicious", "nginx-basic-auth", "recidive"}

const banHeatmapDays = 30

// BanHist は1件の BAN/Unban 履歴
type BanHist struct {
	IP         string `json:"ip"`
	BannedAt   string `json:"banned_at"`
	UnbannedAt string `json:"unbanned_at,omitempty"`
	Active     bool   `json:"active"`
}

// BanHeatmapJailSummary は jail 別の集計情報
type BanHeatmapJailSummary struct {
	Count   int       `json:"count"`
	Current int       `json:"current"`
	History []BanHist `json:"history"`
}

// BanHeatmapResponse は /nab/api/monitor/ban_heatmap のレスポンス
type BanHeatmapResponse struct {
	Jails           map[string]*BanHeatmapJailSummary `json:"jails"`
	TotalBanned     int                               `json:"total_banned"`
	BanHeatmap      map[string][][]int                `json:"ban_heatmap"`       // [jail][dow=0-6][hour=0-23]
	BanHeatmapTotal [][]int                           `json:"ban_heatmap_total"` // [dow=0-6][hour=0-23]
	HeatmapMax      int                               `json:"heatmap_max"`
	Flags           map[string]string                 `json:"flags"`
}

// newHeatmap は 7×24 のゼロ埋めヒートマップを生成する
func newHeatmap() [][]int {
	h := make([][]int, 7)
	for i := range h {
		h[i] = make([]int, 24)
	}
	return h
}

// GetBanHeatmap は logs/fail2ban.jsonl を読んで BAN ヒートマップを返す
func GetBanHeatmap(agentID ...string) BanHeatmapResponse {
	jst := sab.JST()
	now := time.Now().In(jst)
	cutoff := now.AddDate(0, 0, -(banHeatmapDays - 1)).Truncate(24 * time.Hour)

	events, _ := TailJSONL[F2BEvent](f2bJSONLPath(agentID...), 8000)
	currentByJail := currentBannedByJail(agentID...)

	resp := BanHeatmapResponse{
		Jails:           make(map[string]*BanHeatmapJailSummary),
		BanHeatmap:      make(map[string][][]int),
		BanHeatmapTotal: newHeatmap(),
	}
	for _, j := range knownJails {
		resp.Jails[j] = &BanHeatmapJailSummary{}
		resp.BanHeatmap[j] = newHeatmap()
	}

	// Ban → Unban ペアリング用
	type banEvt struct {
		jail string
		ip   string
		ts   time.Time
		act  string // "ban" / "unban"
	}
	var evts []banEvt
	hmSeen := make(map[string]bool)

	for _, ev := range events {
		action := f2bEffectiveAction(ev.Event)
		if action == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, ev.TS)
		if err != nil {
			continue
		}
		t = t.In(jst)
		evts = append(evts, banEvt{jail: ev.Jail, ip: ev.IP, ts: t, act: action})

		// ヒートマップ（直近30日・ban/restore イベント）
		if f2bIsBanLike(ev.Event) && !t.Before(cutoff) {
			hour := t.Hour()
			key := ev.TS[:10] + "|" + fmt.Sprintf("%02d", hour) + "|" + ev.Jail + "|" + ev.IP
			if !hmSeen[key] {
				hmSeen[key] = true
				dow := int(t.Weekday()+6) % 7 // 0=月..6=日
				if resp.BanHeatmap[ev.Jail] == nil {
					resp.BanHeatmap[ev.Jail] = newHeatmap()
				}
				resp.BanHeatmap[ev.Jail][dow][hour]++
				resp.BanHeatmapTotal[dow][hour]++
				if resp.BanHeatmap[ev.Jail][dow][hour] > resp.HeatmapMax {
					resp.HeatmapMax = resp.BanHeatmap[ev.Jail][dow][hour]
				}
				if resp.BanHeatmapTotal[dow][hour] > resp.HeatmapMax {
					resp.HeatmapMax = resp.BanHeatmapTotal[dow][hour]
				}
			}
		}
	}

	// 時刻順ソートしてペアリング
	sort.Slice(evts, func(i, j int) bool { return evts[i].ts.Before(evts[j].ts) })

	pendingBans := make(map[string]map[string][]time.Time) // jail -> ip -> []banTime
	for _, j := range knownJails {
		pendingBans[j] = make(map[string][]time.Time)
	}

	for _, ev := range evts {
		if pendingBans[ev.jail] == nil {
			pendingBans[ev.jail] = make(map[string][]time.Time)
		}
		jailSummary := resp.Jails[ev.jail]
		if jailSummary == nil {
			resp.Jails[ev.jail] = &BanHeatmapJailSummary{}
			jailSummary = resp.Jails[ev.jail]
		}

		if ev.act == "ban" {
			pendingBans[ev.jail][ev.ip] = append(pendingBans[ev.jail][ev.ip], ev.ts)
			jailSummary.Count++
		} else {
			if times := pendingBans[ev.jail][ev.ip]; len(times) > 0 {
				banTime := times[0]
				pendingBans[ev.jail][ev.ip] = times[1:]
				jailSummary.History = append(jailSummary.History, BanHist{
					IP:         ev.ip,
					BannedAt:   sab.FormatDatetime(banTime),
					UnbannedAt: sab.FormatDatetime(ev.ts),
					Active:     false,
				})
			}
		}
	}

	// 未解除（アクティブ）を履歴に追加
	for jail, ipMap := range pendingBans {
		jailSummary := resp.Jails[jail]
		if jailSummary == nil {
			continue
		}
		for ip, times := range ipMap {
			for _, banTime := range times {
				jailSummary.History = append(jailSummary.History, BanHist{
					IP:       ip,
					BannedAt: sab.FormatDatetime(banTime),
					Active:   true,
				})
				jailSummary.Current++
				resp.TotalBanned++
			}
		}
	}
	for jail, ips := range currentByJail {
		jailSummary := resp.Jails[jail]
		if jailSummary == nil {
			resp.Jails[jail] = &BanHeatmapJailSummary{}
			jailSummary = resp.Jails[jail]
		}
		existing := make(map[string]bool)
		for _, h := range jailSummary.History {
			if h.Active {
				existing[h.IP] = true
			}
		}
		for _, ip := range ips {
			if existing[ip] {
				continue
			}
			jailSummary.History = append(jailSummary.History, BanHist{
				IP:     ip,
				Active: true,
			})
			jailSummary.Current++
			resp.TotalBanned++
			existing[ip] = true
		}
	}

	// 履歴を BAN日時降順でソート
	for _, jailSummary := range resp.Jails {
		sort.Slice(jailSummary.History, func(i, j int) bool {
			return jailSummary.History[i].BannedAt > jailSummary.History[j].BannedAt
		})
	}

	// 国旗取得
	ipSet := make(map[string]bool)
	for _, jailSummary := range resp.Jails {
		for _, h := range jailSummary.History {
			ipSet[h.IP] = true
		}
	}
	var allIPs []string
	for ip := range ipSet {
		allIPs = append(allIPs, ip)
	}
	resp.Flags = GetCountryFlags(allIPs)

	return resp
}

// BanHeatmapCellEntry はヒートマップセル詳細の1件
type BanHeatmapCellEntry struct {
	Time     string `json:"time"`
	IP       string `json:"ip"`
	Jail     string `json:"jail"`
	IsBanned bool   `json:"is_banned"`
}

// BanHeatmapCellResponse は ban_heatmap_cell API のレスポンス
type BanHeatmapCellResponse struct {
	Jail    string                `json:"jail"`
	Dow     int                   `json:"dow"`
	Hour    int                   `json:"hour"`
	Total   int                   `json:"total"`
	Entries []BanHeatmapCellEntry `json:"entries"`
	Flags   map[string]string     `json:"flags"`
}

// GetBanHeatmapCell は特定の jail/曜日/時間帯の BAN 一覧を返す
func GetBanHeatmapCell(jail string, dow, hour int, agentID ...string) interface{} {
	if dow < 0 || dow > 6 || hour < 0 || hour > 23 {
		return map[string]string{"error": "invalid dow/hour"}
	}
	isAll := jail == "all"
	if !isAll {
		valid := false
		for _, j := range knownJails {
			if j == jail {
				valid = true
				break
			}
		}
		if !valid {
			return map[string]string{"error": "invalid jail"}
		}
	}

	jst := sab.JST()
	now := time.Now().In(jst)
	cutoff := now.AddDate(0, 0, -(banHeatmapDays - 1)).Truncate(24 * time.Hour)

	events, _ := TailJSONL[F2BEvent](f2bJSONLPath(agentID...), 8000)

	// アクティブ BAN セットを先に構築
	activeBanned := f2bActiveBannedIPs(events)

	var entries []BanHeatmapCellEntry
	seen := make(map[string]int) // key -> index in entries

	for _, ev := range events {
		if !f2bIsBanLike(ev.Event) {
			continue
		}
		if !isAll && ev.Jail != jail {
			continue
		}
		t, err := time.Parse(time.RFC3339, ev.TS)
		if err != nil {
			continue
		}
		t = t.In(jst)
		if t.Before(cutoff) {
			continue
		}
		if t.Hour() != hour {
			continue
		}
		lineDow := int(t.Weekday()+6) % 7
		if lineDow != dow {
			continue
		}

		date := ev.TS[:10]
		key := fmt.Sprintf("%s|%02d|%s|%s", date, hour, ev.Jail, ev.IP)
		timeStr := t.Format("2006-01-02 15:04:05")

		if idx, ok := seen[key]; ok {
			if timeStr > entries[idx].Time {
				entries[idx].Time = timeStr
			}
			continue
		}
		seen[key] = len(entries)
		entries = append(entries, BanHeatmapCellEntry{
			Time:     timeStr,
			IP:       ev.IP,
			Jail:     ev.Jail,
			IsBanned: activeBanned[ev.IP],
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Time > entries[j].Time
	})
	if len(entries) > 300 {
		entries = entries[:300]
	}

	ipSet := make(map[string]bool)
	for _, e := range entries {
		if !strings.HasPrefix(e.IP, "127.") {
			ipSet[e.IP] = true
		}
	}
	var ips []string
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	return BanHeatmapCellResponse{
		Jail:    jail,
		Dow:     dow,
		Hour:    hour,
		Total:   len(entries),
		Entries: entries,
		Flags:   GetCountryFlags(ips),
	}
}

// f2bActiveBannedIPs は F2BEvent リストから現在アクティブな BAN IP セットを返す
func f2bActiveBannedIPs(events []F2BEvent) map[string]bool {
	jst := sab.JST()

	type banEvt struct {
		jail string
		ip   string
		ts   time.Time
		act  string
	}
	var evts []banEvt
	for _, ev := range events {
		action := f2bEffectiveAction(ev.Event)
		if action == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, ev.TS)
		if err != nil {
			continue
		}
		evts = append(evts, banEvt{jail: ev.Jail, ip: ev.IP, ts: t.In(jst), act: action})
	}
	sort.Slice(evts, func(i, j int) bool { return evts[i].ts.Before(evts[j].ts) })

	pending := make(map[string]map[string]int) // jail -> ip -> count
	for _, j := range knownJails {
		pending[j] = make(map[string]int)
	}
	for _, ev := range evts {
		if pending[ev.jail] == nil {
			pending[ev.jail] = make(map[string]int)
		}
		if ev.act == "ban" {
			pending[ev.jail][ev.ip]++
		} else if pending[ev.jail][ev.ip] > 0 {
			pending[ev.jail][ev.ip]--
		}
	}
	active := make(map[string]bool)
	for _, ipMap := range pending {
		for ip, cnt := range ipMap {
			if cnt > 0 {
				active[ip] = true
			}
		}
	}
	return active
}

// f2bActiveBannedIPsWithJail は F2BEvent リストから現在アクティブな BAN IP と jail 名の map を返す
func f2bActiveBannedIPsWithJail(events []F2BEvent) map[string]string {
	jst := sab.JST()

	type banEvt struct {
		jail string
		ip   string
		ts   time.Time
		act  string
	}
	var evts []banEvt
	for _, ev := range events {
		action := f2bEffectiveAction(ev.Event)
		if action == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, ev.TS)
		if err != nil {
			continue
		}
		evts = append(evts, banEvt{jail: ev.Jail, ip: ev.IP, ts: t.In(jst), act: action})
	}
	sort.Slice(evts, func(i, j int) bool { return evts[i].ts.Before(evts[j].ts) })

	pending := make(map[string]map[string]int)
	jailOf := make(map[string]string)
	for _, j := range knownJails {
		pending[j] = make(map[string]int)
	}
	for _, ev := range evts {
		if pending[ev.jail] == nil {
			pending[ev.jail] = make(map[string]int)
		}
		if ev.act == "ban" {
			pending[ev.jail][ev.ip]++
			jailOf[ev.ip] = ev.jail
		} else if pending[ev.jail][ev.ip] > 0 {
			pending[ev.jail][ev.ip]--
		}
	}
	active := make(map[string]string)
	for jail, ipMap := range pending {
		for ip, cnt := range ipMap {
			if cnt > 0 {
				if j, ok := jailOf[ip]; ok {
					active[ip] = j
				} else {
					active[ip] = jail
				}
			}
		}
	}
	return active
}

func currentBannedByJail(agentID ...string) map[string][]string {
	id := normalizeAgentID(agentID)
	result := make(map[string][]string)
	if id != "" {
		raw := loadCollectorRaw(id, "fail2ban")
		var snap fail2banCollectorSnapshot
		_ = json.Unmarshal(raw, &snap)
		for _, jail := range snap.Jails {
			if len(jail.BannedIPs) > 0 {
				result[jail.Name] = append(result[jail.Name], jail.BannedIPs...)
			}
		}
		return result
	}
	for _, jail := range knownJails {
		js := getJailStatus(jail)
		if len(js.BannedIPs) > 0 {
			result[jail] = append(result[jail], js.BannedIPs...)
		}
	}
	return result
}
