package alerts

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ResourceLogColumns は resource CSV の列順（単一情報源）。
// collect.go（package daemon）はこの定数を import して参照する。
// import 方向は daemon -> alerts に統一する。daemon/alerts.go が既に
// internal/alerts を import しているため、alerts 側に const を置き daemon が
// import することで循環（daemon -> alerts -> daemon）を避ける。
const ResourceLogColumns = "timestamp,cpu,mem,disk"

// resource CSV の列インデックス（ResourceLogColumns = "timestamp,cpu,mem,disk" に対応）。
const (
	colMem          = 2
	colDisk         = 3
	resourceMinCols = 4
)

// resourceSample は 1 サンプル（mem/disk の有効値）を表す。
type resourceSample struct {
	mem    float64
	memOK  bool
	disk   float64
	diskOK bool
}

// parseResourceLine は 1 行を mem/disk に分解する。mem/disk は独立に有効判定する。
func parseResourceLine(ln string) resourceSample {
	var s resourceSample
	parts := strings.Split(ln, ",")
	if len(parts) < resourceMinCols {
		return s
	}
	if v, err := parseFloat(parts[colMem]); err == nil {
		s.mem, s.memOK = v, true
	}
	if v, err := parseFloat(parts[colDisk]); err == nil {
		s.disk, s.diskOK = v, true
	}
	return s
}

// parseFloat は厳密な float パース（部分一致や空文字を弾く）。
func parseFloat(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	var v float64
	n, err := fmt.Sscanf(s, "%f", &v)
	if err != nil || n != 1 {
		return 0, fmt.Errorf("not a float: %q", s)
	}
	return v, nil
}

// readResourceTail は state.Offsets[path] からの増分を offset ベースで読む。
// ring buffer を使わないためログ行のドロップが起きない。
// 戻り値は読み取った行と、次回再開用の新しい offset。
func readResourceTail(path string, prevOffset int64) ([]string, int64) {
	f, err := os.Open(path)
	if err != nil {
		return nil, prevOffset
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, prevOffset
	}
	size := fi.Size()
	// ローテーション等で縮んでいたら先頭から読み直す。
	start := prevOffset
	if start > size || start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, 0); err != nil {
		return nil, prevOffset
	}

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, size
}

// latestValid は行群から mem/disk それぞれ最後の有効値を独立に取り出す。
// 「mem も disk も両方 OK」を要求する `||`/`&&` ガードを排し、片方が欠損しても
// もう片方は評価できるようにする（last-N-valid）。
func latestValid(lines []string) (mem float64, memOK bool, disk float64, diskOK bool) {
	for _, ln := range lines {
		s := parseResourceLine(ln)
		if s.memOK {
			mem, memOK = s.mem, true
		}
		if s.diskOK {
			disk, diskOK = s.disk, true
		}
	}
	return
}

// evaluateResourceAlerts は resource CSV を offset 方式で tail し、memory_high /
// disk_high ルールを評価する。閾値超過で発報、復帰時は NotifyRecovery に従い復帰通知。
func evaluateResourceAlerts(logPath string, rules AlertRules, state *AlertState) []string {
	prev := state.Offsets[logPath]
	lines, next := readResourceTail(logPath, prev)
	state.Offsets[logPath] = next

	mem, memOK, disk, diskOK := latestValid(lines)
	now := nowFn()

	var out []string
	type metric struct {
		ruleID   string
		value    float64
		ok       bool
		defTh    float64
		breached func(v, th float64) string // 発報文言
		recovery string
	}
	metrics := []metric{
		{
			ruleID: "memory_high", value: mem, ok: memOK, defTh: 90,
			breached: func(v, th float64) string {
				return fmt.Sprintf("メモリ使用率が高騰しています: %.1f%%", v)
			},
			recovery: "メモリ使用率が正常に戻りました",
		},
		{
			ruleID: "disk_high", value: disk, ok: diskOK, defTh: 92,
			breached: func(v, th float64) string {
				return fmt.Sprintf("ディスク使用率が高騰しています: %d%%", int(v))
			},
			recovery: "ディスク使用率が正常に戻りました",
		},
	}

	for _, m := range metrics {
		rule, defined := rules.Rules[m.ruleID]
		if !defined || !rule.Enabled || !m.ok {
			continue
		}
		th := rule.Threshold
		if th == 0 {
			th = m.defTh
		}
		key := m.ruleID
		active := m.value >= th
		if active {
			if !state.Active[key] && shouldAlert(key, rule.SustainSec, rule.CooldownSec, state, now) {
				out = append(out, fire(rules, m.ruleID, m.breached(m.value, th)))
				state.Active[key] = true
			}
		} else {
			clearBreach(key, state)
			if state.Active[key] && rule.NotifyRecovery {
				out = append(out, fire(rules, m.ruleID, m.recovery))
			}
			state.Active[key] = false
		}
	}
	return out
}
