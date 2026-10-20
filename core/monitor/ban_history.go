package monitor

import (
	"sort"
	"strings"
)

// GetBanHistory は fail2ban.jsonl を読み込み BAN 履歴を返す。
// jail詳細モーダル・BANヒートマップと同じイベントソースに揃える。
func GetBanHistory(agentID ...string) BanHistoryData {
	events, _ := TailJSONL[F2BEvent](f2bJSONLPath(agentID...), 50000)
	history := buildBanHistoryEntries(events)
	manualBans := loadManualBans()

	// フラグ取得用 IP セット（127.0.0.1 は除外）
	ipSet := make(map[string]bool)
	for _, h := range history {
		if h.IP != "" && h.IP != "127.0.0.1" {
			ipSet[h.IP] = true
		}
	}
	var ips []string
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	flags := GetCountryFlags(ips)
	if flags == nil {
		flags = map[string]string{}
	}

	return BanHistoryData{
		History:    history,
		Flags:      flags,
		ManualBans: manualBans,
	}
}

// buildBanHistoryEntries は fail2ban イベントから BAN/Restore Ban の履歴を作る。
func buildBanHistoryEntries(events []F2BEvent) []BanHistoryEntry {
	var history []BanHistoryEntry
	seen := make(map[string]bool)
	for _, ev := range events {
		if !f2bIsBanLike(ev.Event) {
			continue
		}
		ip := strings.TrimSpace(ev.IP)
		jail := strings.TrimSpace(ev.Jail)
		ts := f2bDisplayTime(ev.TS)
		if ip == "" || jail == "" || ts == "" {
			continue
		}
		key := ts + "|" + jail + "|" + ip
		if seen[key] {
			continue
		}
		seen[key] = true
		history = append(history, BanHistoryEntry{
			DateTime: ts,
			IP:       ip,
			Jail:     jail,
		})
	}

	// BAN日時の降順でソート（新しい順）
	sort.Slice(history, func(i, j int) bool {
		return history[i].DateTime > history[j].DateTime
	})

	return history
}
