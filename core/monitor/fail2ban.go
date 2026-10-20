package monitor

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	sab "github.com/ishizakahiroshi/heartdesk/internal"
)

// jailNames は監視対象 jail 一覧（PHP の JAIL_NAMES 定数相当）
var jailNames = []string{"nextcloud", "nginx-suspicious", "nginx-basic-auth", "recidive"}

var defaultJailTooltips = map[string]string{
	"nextcloud":        "Nextcloudログインを10分以内に5回失敗 → 1時間BAN",
	"nginx-suspicious": "ホワイトリスト外パスに10分以内に10回アクセス → 30日BAN",
	"nginx-basic-auth": "Basic認証を10分以内に5回失敗 → 1時間BAN",
	"recidive":         "24時間以内に2回以上BANされた場合 → 30日BAN（重刑化）",
}

// GetFail2ban は fail2ban の状態（全 jail + トレンド + GeoIP フラグ）を返す。
// agentID が指定された場合は Unavailable を返す（fail2ban は VPS 直実行専用のため、
// レポートあり・なしに関わらず Agent 経由では取得不可）。
func GetFail2ban(agentID ...string) Fail2banData {
	if len(agentID) > 0 && agentID[0] != "" {
		if data, ok := getFail2banFromAgent(strings.TrimSpace(agentID[0])); ok {
			return data
		}
		return Fail2banData{Unavailable: true}
	}
	var d Fail2banData
	d.UpdatedAt = sab.FormatDatetime(time.Now().In(sab.JST()))
	d.JailTooltips = getJailTooltips()

	for _, jail := range jailNames {
		js := getJailStatus(jail)
		d.Jails = append(d.Jails, js)
		d.BanTotal += js.BanCount
	}

	// fail2ban.jsonl を読みトレンドと jail 履歴を計算
	f2bEvents, _ := TailJSONL[F2BEvent](f2bJSONLPath(), 50000)
	d.BanTrend7d, d.BanTrendTop,
		d.BanTrend14d, d.BanTrend14dTop,
		d.BanTrend4w, d.BanTrend4wTop = computeBanTrends(f2bEvents)

	// jail 別 BAN 履歴を populate（jail カードクリック時のモーダル用）
	histories := buildJailHistories(f2bEvents)
	for i := range d.Jails {
		if h, ok := histories[d.Jails[i].Name]; ok {
			d.Jails[i].History = h
		} else {
			d.Jails[i].History = []BanHistEntry{}
		}
		d.Jails[i].History = supplementActiveHistoryFromStatus(d.Jails[i].History, d.Jails[i].BannedIPs)
	}

	// 手動 BAN ログ（jail モーダルの manual/auto バッジ用）
	d.ManualBans = loadManualBans()

	// GeoIP フラグ（BAN中 IP + トレンド上位 IP + 履歴 IP）
	ipSet := make(map[string]bool)
	for _, j := range d.Jails {
		for _, ip := range j.BannedIPs {
			ipSet[ip] = true
		}
		for _, h := range j.History {
			ipSet[h.IP] = true
		}
	}
	for _, tops := range d.BanTrendTop {
		for _, t := range tops {
			ipSet[t.IP] = true
		}
	}
	var allIPs []string
	for ip := range ipSet {
		if ip != "" {
			allIPs = append(allIPs, ip)
		}
	}
	d.Flags = GetCountryFlags(allIPs)

	// 分子/分母を設定: total = BAN済みIP累積件数, active = 現在有効なBAN件数
	totalBanCount := 0
	for _, j := range d.Jails {
		totalBanCount += j.TotalBanned
	}
	d.Total = totalBanCount
	d.Active = d.BanTotal

	return d
}

type fail2banCollectorSnapshot struct {
	Active int            `json:"active"`
	Jails  []Fail2banJail `json:"jails"`
}

func getFail2banFromAgent(agentID string) (Fail2banData, bool) {
	events, _ := TailJSONL[F2BEvent](f2bJSONLPath(agentID), 50000)
	raw := loadCollectorRaw(agentID, "fail2ban")

	var snap fail2banCollectorSnapshot
	_ = json.Unmarshal(raw, &snap)

	d := Fail2banData{
		UpdatedAt:    reportReceivedAt(agentID),
		JailTooltips: getJailTooltips(),
		ManualBans:   []ManualBanEntry{},
	}
	if len(snap.Jails) > 0 {
		d.Jails = make([]Fail2banJail, 0, len(snap.Jails))
		d.Jails = append(d.Jails, snap.Jails...)
	}

	d.BanTrend7d, d.BanTrendTop,
		d.BanTrend14d, d.BanTrend14dTop,
		d.BanTrend4w, d.BanTrend4wTop = computeBanTrends(events)

	histories := buildJailHistories(events)
	jailIndex := make(map[string]int, len(d.Jails))
	for i := range d.Jails {
		jailIndex[d.Jails[i].Name] = i
	}
	for jail, history := range histories {
		if idx, ok := jailIndex[jail]; ok {
			d.Jails[idx].History = history
			continue
		}
		d.Jails = append(d.Jails, Fail2banJail{
			Name:    jail,
			History: history,
		})
	}
	for i := range d.Jails {
		if d.Jails[i].History == nil {
			d.Jails[i].History = []BanHistEntry{}
		}
		d.Jails[i].History = supplementActiveHistoryFromStatus(d.Jails[i].History, d.Jails[i].BannedIPs)
	}

	if d.UpdatedAt == "" {
		d.UpdatedAt = sab.FormatDatetime(time.Now().In(sab.JST()))
	}
	if len(d.Jails) == 0 && len(events) == 0 {
		return Fail2banData{}, false
	}

	ipSet := make(map[string]bool)
	totalBanCount := 0
	banTotal := 0
	for i := range d.Jails {
		j := d.Jails[i]
		totalBanCount += j.TotalBanned
		banTotal += j.BanCount
		for _, ip := range j.BannedIPs {
			ipSet[ip] = true
		}
		for _, h := range j.History {
			ipSet[h.IP] = true
		}
	}
	for _, tops := range d.BanTrendTop {
		for _, t := range tops {
			ipSet[t.IP] = true
		}
	}
	var allIPs []string
	for ip := range ipSet {
		if ip != "" {
			allIPs = append(allIPs, ip)
		}
	}
	d.Flags = GetCountryFlags(allIPs)

	d.Total = totalBanCount
	d.BanTotal = banTotal
	d.Active = snap.Active
	if d.Active == 0 {
		d.Active = d.BanTotal
	}
	return d, true
}

// getJailTooltips は jail ごとの BAN 成立条件の説明文を返す。
// 外部の文書は読まず、組み込みの既定文言（defaultJailTooltips）のコピーを返す。
func getJailTooltips() map[string]string {
	tooltips := make(map[string]string, len(defaultJailTooltips))
	for k, v := range defaultJailTooltips {
		tooltips[k] = v
	}
	return tooltips
}

// buildJailHistories は fail2ban.jsonl のイベントリストから jail 別 BAN 履歴を構築する
// Ban/Unban をペアリングして active/unbanned を判定する
func buildJailHistories(events []F2BEvent) map[string][]BanHistEntry {
	type evEntry struct {
		ts     string
		action string
		ip     string
	}
	jailEvents := make(map[string][]evEntry)

	for _, ev := range events {
		action := f2bEffectiveAction(ev.Event)
		if action == "" {
			continue
		}
		jailEvents[ev.Jail] = append(jailEvents[ev.Jail], evEntry{ev.TS, action, ev.IP})
	}

	result := make(map[string][]BanHistEntry)
	for jail, evs := range jailEvents {
		sort.Slice(evs, func(i, j int) bool { return evs[i].ts < evs[j].ts })
		pendingBans := make(map[string][]string) // ip → []ban_time（FIFO）
		var history []BanHistEntry

		for _, ev := range evs {
			if ev.action == "ban" {
				pendingBans[ev.ip] = append(pendingBans[ev.ip], ev.ts)
			} else { // unban
				if times := pendingBans[ev.ip]; len(times) > 0 {
					banTime := times[0]
					pendingBans[ev.ip] = times[1:]
					history = append(history, BanHistEntry{
						IP:         ev.ip,
						BannedAt:   f2bDisplayTime(banTime),
						UnbannedAt: f2bDisplayTime(ev.ts),
						Active:     false,
					})
				}
			}
		}
		// 未解除 = アクティブ
		for ip, times := range pendingBans {
			for _, banTime := range times {
				history = append(history, BanHistEntry{
					IP:       ip,
					BannedAt: f2bDisplayTime(banTime),
					Active:   true,
				})
			}
		}
		// BAN日時の降順でソート
		sort.Slice(history, func(i, j int) bool {
			return history[i].BannedAt > history[j].BannedAt
		})
		result[jail] = history
	}
	return result
}

func f2bIsBanLike(event string) bool {
	return event == "ban" || event == "restore"
}

func f2bEffectiveAction(event string) string {
	switch event {
	case "ban", "restore":
		return "ban"
	case "unban":
		return "unban"
	default:
		return ""
	}
}

func f2bDisplayTime(ts string) string {
	if strings.TrimSpace(ts) == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t.In(sab.JST()).Format("2006-01-02 15:04:05")
	}
	return strings.TrimSpace(ts)
}

func supplementActiveHistoryFromStatus(history []BanHistEntry, bannedIPs []string) []BanHistEntry {
	active := make(map[string]bool)
	for _, h := range history {
		if h.Active {
			active[h.IP] = true
		}
	}
	for _, ip := range bannedIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" || active[ip] {
			continue
		}
		history = append(history, BanHistEntry{
			IP:     ip,
			Active: true,
		})
		active[ip] = true
	}
	sort.Slice(history, func(i, j int) bool {
		return history[i].BannedAt > history[j].BannedAt
	})
	return history
}

// appendManualBan は手動 BAN ログ（data/json/manual_bans_log.csv）に1行追記する。
// jail モーダルの manual/auto バッジ判定で fail2ban イベントの BAN 日時と ±60秒 で照合される。
func appendManualBan(ip string) {
	path := sab.SabPath("data/json/manual_bans_log.csv")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("ERROR: monitor: appendManualBan open failed: %v", err)
		return
	}
	defer f.Close()
	now := time.Now().In(sab.JST()).Format("2006-01-02 15:04:05")
	if _, err := fmt.Fprintf(f, "%s,%s\n", now, ip); err != nil {
		log.Printf("ERROR: monitor: appendManualBan write failed: %v", err)
	}
}

// loadManualBans は manual_bans_log.csv を読み込む
func loadManualBans() []ManualBanEntry {
	f, err := os.Open(sab.SabPath("data/json/manual_bans_log.csv"))
	if err != nil {
		return []ManualBanEntry{}
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return []ManualBanEntry{}
	}
	var result []ManualBanEntry
	for _, rec := range records {
		if len(rec) >= 2 {
			result = append(result, ManualBanEntry{
				DateTime: strings.TrimSpace(rec[0]),
				IP:       strings.TrimSpace(rec[1]),
			})
		}
	}
	return result
}

// getJailStatus は fail2ban-client status で指定 jail の状態を取得する
func getJailStatus(jail string) Fail2banJail {
	out := sab.RunArgs(10*time.Second, "sudo", "/usr/bin/fail2ban-client", "status", jail)
	jd := Fail2banJail{Name: jail, BannedIPs: []string{}}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.Contains(line, "Currently banned:"):
			parts := strings.Fields(line)
			if len(parts) > 0 {
				jd.BanCount, _ = strconv.Atoi(parts[len(parts)-1])
			}
		case strings.Contains(line, "Total banned:"):
			parts := strings.Fields(line)
			if len(parts) > 0 {
				jd.TotalBanned, _ = strconv.Atoi(parts[len(parts)-1])
			}
		case strings.Contains(line, "Total found:"):
			parts := strings.Fields(line)
			if len(parts) > 0 {
				jd.TotalFound, _ = strconv.Atoi(parts[len(parts)-1])
			}
		case strings.Contains(line, "Banned IP list:"):
			idx := strings.Index(line, "Banned IP list:")
			ipPart := strings.TrimSpace(line[idx+len("Banned IP list:"):])
			if ipPart != "" {
				jd.BannedIPs = strings.Fields(ipPart)
			}
		}
	}
	return jd
}

// computeBanTrends は fail2ban.jsonl のイベントリストから 7d/14d/4w のトレンドを計算する
func computeBanTrends(events []F2BEvent) (
	trend7d map[string]int, top7d map[string][]BanTopIP,
	trend14d map[string]int, top14d map[string][]BanTopIP,
	trend4w map[string]int, top4w map[string][]BanTopIP,
) {
	// dayIPCount[date][ip] = 当日のBAN回数
	// dayIPLatest[date][ip] = 当日の最終BANタイムスタンプ
	dayIPCount := make(map[string]map[string]int)
	dayIPLatest := make(map[string]map[string]string)

	for _, ev := range events {
		if ev.Event != "ban" {
			continue
		}
		// ts は RFC3339 形式（例: 2026-04-15T02:56:23+09:00）
		date := ""
		if len(ev.TS) >= 10 {
			date = ev.TS[:10]
		}
		if date == "" {
			continue
		}
		if dayIPCount[date] == nil {
			dayIPCount[date] = make(map[string]int)
			dayIPLatest[date] = make(map[string]string)
		}
		dayIPCount[date][ev.IP]++
		if ev.TS > dayIPLatest[date][ev.IP] {
			dayIPLatest[date][ev.IP] = ev.TS
		}
	}

	jst := sab.JST()
	today := time.Now().In(jst).Truncate(24 * time.Hour)

	// buildDayTrend は指定日付リストからトレンドとトップIPを構築する
	buildDayTrend := func(dates []string) (map[string]int, map[string][]BanTopIP) {
		trend := make(map[string]int, len(dates))
		tops := make(map[string][]BanTopIP, len(dates))

		type ipInfo struct {
			ip     string
			count  int
			latest string
		}
		for _, date := range dates {
			if ips, ok := dayIPCount[date]; ok {
				trend[date] = len(ips)
				var infos []ipInfo
				for ip, cnt := range ips {
					infos = append(infos, ipInfo{ip, cnt, dayIPLatest[date][ip]})
				}
				sort.Slice(infos, func(i, j int) bool {
					if infos[i].latest != infos[j].latest {
						return infos[i].latest > infos[j].latest
					}
					return infos[i].count > infos[j].count
				})
				topList := make([]BanTopIP, 0, 5)
				for k := 0; k < len(infos) && k < 5; k++ {
					topList = append(topList, BanTopIP{IP: infos[k].ip, Count: infos[k].count})
				}
				tops[date] = topList
			} else {
				trend[date] = 0
				tops[date] = []BanTopIP{}
			}
		}
		return trend, tops
	}

	// 7日間
	dates7d := make([]string, 7)
	for i := 6; i >= 0; i-- {
		dates7d[6-i] = today.AddDate(0, 0, -i).Format("2006-01-02")
	}
	trend7d, top7d = buildDayTrend(dates7d)

	// 14日間
	dates14d := make([]string, 14)
	for i := 13; i >= 0; i-- {
		dates14d[13-i] = today.AddDate(0, 0, -i).Format("2006-01-02")
	}
	trend14d, top14d = buildDayTrend(dates14d)

	// 4週間（週次集計）
	trend4w = make(map[string]int, 4)
	top4w = make(map[string][]BanTopIP, 4)
	for w := 3; w >= 0; w-- {
		startDay := today.AddDate(0, 0, -(w*7 + 6))
		endDay := today.AddDate(0, 0, -(w * 7))
		label := startDay.Format("01/02") + "-" + endDay.Format("01/02")

		weekIPCount := make(map[string]int)
		weekIPLatest := make(map[string]string)
		for d := startDay; !d.After(endDay); d = d.AddDate(0, 0, 1) {
			date := d.Format("2006-01-02")
			for ip, cnt := range dayIPCount[date] {
				weekIPCount[ip] += cnt
				if dayIPLatest[date][ip] > weekIPLatest[ip] {
					weekIPLatest[ip] = dayIPLatest[date][ip]
				}
			}
		}
		trend4w[label] = len(weekIPCount)

		type ipInfo struct {
			ip     string
			count  int
			latest string
		}
		var infos []ipInfo
		for ip, cnt := range weekIPCount {
			infos = append(infos, ipInfo{ip, cnt, weekIPLatest[ip]})
		}
		sort.Slice(infos, func(i, j int) bool {
			if infos[i].latest != infos[j].latest {
				return infos[i].latest > infos[j].latest
			}
			return infos[i].count > infos[j].count
		})
		topList := make([]BanTopIP, 0, 5)
		for k := 0; k < len(infos) && k < 5; k++ {
			topList = append(topList, BanTopIP{IP: infos[k].ip, Count: infos[k].count})
		}
		top4w[label] = topList
	}

	return
}

// BanIP は指定 IP を recidive jail に BAN する
func BanIP(ip string) error {
	if !isValidIP(ip) {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	out := sab.RunArgs(10*time.Second, "sudo", "/usr/bin/fail2ban-client", "set", "recidive", "banip", ip)
	if strings.Contains(strings.ToLower(out), "error") || out == "" {
		return fmt.Errorf("ban 失敗: %s", out)
	}
	appendManualBan(ip)
	return nil
}

// UnbanIP は指定 IP を全 jail から UNBAN する（jail 指定時はそのjailのみ）
func UnbanIP(ip, jail string) error {
	if !isValidIP(ip) {
		return fmt.Errorf("invalid IP: %s", ip)
	}
	targets := jailNames
	if jail != "" {
		ok := false
		for _, j := range jailNames {
			if j == jail {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("unknown jail: %s", jail)
		}
		targets = []string{jail}
	}
	for _, j := range targets {
		sab.RunArgs(10*time.Second, "sudo", "/usr/bin/fail2ban-client", "set", j, "unbanip", ip)
	}
	return nil
}

// isValidIP は IPv4 / IPv6 アドレスの形式を検証する
func isValidIP(ip string) bool {
	return net.ParseIP(strings.TrimSpace(ip)) != nil
}
