package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

// GetResources はサーバーリソース情報を取得する。
// agentID が指定されている場合は Agent レポートから読み取る。
// agentID が空の場合は VPS 自身のコマンド実行で取得する（後方互換）。
func GetResources(agentID ...string) ResourcesData {
	id := ""
	if len(agentID) > 0 {
		id = agentID[0]
	}
	if id != "" {
		if d, ok := resourcesFromReport(id); ok {
			return d
		}
		return ResourcesData{Unavailable: true, UpdatedAt: heartdesk.FormatDatetime(time.Now().In(heartdesk.JST()))}
	}

	var d ResourcesData
	d.UpdatedAt = heartdesk.FormatDatetime(time.Now().In(heartdesk.JST()))
	s := getResourceSample()

	// ---- 稼働時間 ----
	d.Uptime = strings.TrimSpace(heartdesk.Run("uptime -p 2>/dev/null"))
	d.UptimeSince = strings.TrimSpace(heartdesk.Run("uptime -s 2>/dev/null"))

	// ---- CPU/メモリ/負荷/ネットワーク（5秒周期の共通サンプラー値を使用）----
	d.Load1 = s.Load.Min1
	d.Load5 = s.Load.Min5
	d.Load15 = s.Load.Min15
	d.CPUPct = s.CPUPct
	d.MemTotal = s.Memory.Total
	d.MemUsed = s.Memory.Used
	d.MemPct = s.Memory.Pct
	d.MemFree = s.MemFree
	d.MemBuffers = s.MemBuffers
	d.MemCached = s.MemCached
	d.MemAvail = s.MemAvail
	d.SwapTotal = s.Swap.Total
	d.SwapFree = s.SwapFree

	// ---- ディスク (df -h /) ----
	dfOut := strings.TrimSpace(heartdesk.Run("df -h / 2>/dev/null"))
	lines := strings.Split(dfOut, "\n")
	if len(lines) >= 2 {
		parts := strings.Fields(lines[1])
		if len(parts) >= 5 {
			d.DiskTotal = parts[1]
			d.DiskUsed = parts[2]
			d.DiskFree = parts[3]
			d.DiskPct = parts[4]
		}
	}

	d.NetIface = s.Network.Iface
	d.NetRxBytes = int64(s.Network.RX)
	d.NetTxBytes = int64(s.Network.TX)
	d.NetRxHuman = humanBytes(d.NetRxBytes)
	d.NetTxHuman = humanBytes(d.NetTxBytes)
	d.CPUModel = readCPUModel()
	d.CPUCores = readCPUCores()
	d.RAMTotal = humanGiB(d.MemTotal)
	d.OSLabel = readOSPrettyName()
	d.Kernel = strings.TrimSpace(heartdesk.Run("uname -r 2>/dev/null"))

	// ---- NC メンテナンスモード ----
	raw := heartdesk.Run(`grep "'maintenance'" /var/www/nextcloud/config/config.php 2>/dev/null`)
	d.IsMaint = strings.Contains(raw, "true")

	return d
}

// humanBytes はバイト数を人間が読みやすい文字列に変換する
func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// =============================================================================
// リソース系カード
// =============================================================================

type resourcePoint struct {
	ts   time.Time
	cpu  float64
	mem  float64
	disk float64
}

// readResourcePoints は agent_reports JSONL から直近7日分のリソース履歴を返す
func readResourcePoints(agentID string) []resourcePoint {
	dir := agentReportDirPath()
	pattern := filepath.Join(dir, fmt.Sprintf("report_%s_*.jsonl", agentID))
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}

	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	var points []resourcePoint

	for _, fpath := range matches {
		f, err := os.Open(fpath)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 256*1024), 256*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var rec agentReportRecord
			if err := json.Unmarshal(line, &rec); err != nil {
				continue
			}
			ts, err := time.Parse(time.RFC3339, rec.ReportedAt)
			if err != nil {
				continue
			}
			if ts.Before(cutoff) {
				continue
			}
			sys, ok := decodeSystemCollectorResult(rec.Collectors["system"])
			if !ok {
				continue
			}
			diskPct := 0.0
			for _, d := range sys.Disk {
				if d.MountPoint == "/" {
					diskPct = d.UsagePercent
					break
				}
			}
			points = append(points, resourcePoint{
				ts:   ts.In(heartdesk.JST()),
				cpu:  sys.CPU.UsagePercent,
				mem:  sys.Memory.UsagePercent,
				disk: diskPct,
			})
		}
		_ = f.Close()
	}
	return points
}

// GetResourceGraph は agent_reports JSONL を読んで24h/7d集計を返す
func GetResourceGraph(agentID string) ResourceGraphData {
	points := readResourcePoints(agentID)

	now := time.Now().In(heartdesk.JST())
	cutoff24h := now.Add(-24 * time.Hour)

	type acc struct {
		sumCPU, sumMem, sumDisk float64
		cnt                     int
	}
	hourAcc := map[string]*acc{}
	dayAcc := map[string]*acc{}

	for _, p := range points {
		if p.ts.After(cutoff24h) {
			hk := p.ts.Format("15")
			if hourAcc[hk] == nil {
				hourAcc[hk] = &acc{}
			}
			hourAcc[hk].sumCPU += p.cpu
			hourAcc[hk].sumMem += p.mem
			hourAcc[hk].sumDisk += p.disk
			hourAcc[hk].cnt++
		}
		dk := p.ts.Format("2006-01-02")
		if dayAcc[dk] == nil {
			dayAcc[dk] = &acc{}
		}
		dayAcc[dk].sumCPU += p.cpu
		dayAcc[dk].sumMem += p.mem
		dayAcc[dk].sumDisk += p.disk
		dayAcc[dk].cnt++
	}

	ptrRound := func(v, cnt float64) *float64 {
		if cnt == 0 {
			return nil
		}
		r := math.Round(v/cnt*10) / 10
		return &r
	}

	// 直近24時間: 現在時刻から遡って24時間分のキーを生成（古い→新しい）
	currentHour := now.Hour()
	h24Keys := make([]string, 24)
	h24 := make(map[string]ResourcePoint, 24)
	for i := 23; i >= 0; i-- {
		h := (currentHour - i + 24) % 24
		hk := fmt.Sprintf("%02d", h)
		h24Keys[23-i] = hk
		if a, ok := hourAcc[hk]; ok && a.cnt > 0 {
			h24[hk] = ResourcePoint{
				CPU:  ptrRound(a.sumCPU, float64(a.cnt)),
				Mem:  ptrRound(a.sumMem, float64(a.cnt)),
				Disk: ptrRound(a.sumDisk, float64(a.cnt)),
			}
		} else {
			h24[hk] = ResourcePoint{}
		}
	}

	// 直近7日: 今日から6日前〜今日（古い→新しい）
	d7Keys := make([]string, 7)
	d7 := make(map[string]ResourcePoint, 7)
	for i := 6; i >= 0; i-- {
		dk := now.AddDate(0, 0, -i).Format("2006-01-02")
		d7Keys[6-i] = dk
		if a, ok := dayAcc[dk]; ok && a.cnt > 0 {
			d7[dk] = ResourcePoint{
				CPU:  ptrRound(a.sumCPU, float64(a.cnt)),
				Mem:  ptrRound(a.sumMem, float64(a.cnt)),
				Disk: ptrRound(a.sumDisk, float64(a.cnt)),
			}
		} else {
			d7[dk] = ResourcePoint{}
		}
	}

	empty := len(hourAcc) == 0 && len(dayAcc) == 0
	return ResourceGraphData{H24: h24, D7: d7, H24Keys: h24Keys, D7Keys: d7Keys, Empty: empty}
}

// GetProcesses は ps aux から CPU/MEM Top プロセス一覧を取得する。
// agentID が指定された場合は Unavailable を返す（processes は VPS 直実行専用のため、
// レポートあり・なしに関わらず Agent 経由では取得不可）。
func GetProcesses(agentID ...string) ProcessesResponse {
	id := ""
	if len(agentID) > 0 {
		id = agentID[0]
	}
	if id != "" {
		if resp, ok := processesFromReport(id); ok {
			return resp
		}
		return ProcessesResponse{Unavailable: true}
	}
	topCPURaw, total := runPsSort("--sort=-%cpu")
	topMemRaw, _ := runPsSort("--sort=-%mem")
	return ProcessesResponse{
		TopCPU: parsePsOutput(topCPURaw),
		TopMem: parsePsOutput(topMemRaw),
		Total:  total,
	}
}

func runPsSort(sortFlag string) (string, int) {
	cmd := exec.Command("ps", "aux", sortFlag)
	out, err := cmd.Output()
	if err != nil {
		return "", 0
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 1 {
		lines = lines[1:] // ヘッダ行除去
	}
	total := len(lines)
	if len(lines) > 1000 {
		lines = lines[:1000]
	}
	return strings.Join(lines, "\n"), total
}

func parsePsOutput(raw string) []ProcessInfo {
	var procs []ProcessInfo
	if raw == "" {
		return procs
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cols := strings.Fields(line)
		if len(cols) < 11 {
			continue
		}
		rssKB, _ := strconv.ParseInt(cols[5], 10, 64)
		// COMMAND: フルパスのベース名を取得
		cmdStr := cols[10]
		if idx := strings.Index(cmdStr, " "); idx > 0 {
			cmdStr = cmdStr[:idx]
		}
		if idx := strings.LastIndex(cmdStr, "/"); idx >= 0 {
			cmdStr = cmdStr[idx+1:]
		}
		procs = append(procs, ProcessInfo{
			PID:     cols[1],
			CPU:     cols[2],
			Mem:     cols[3],
			RSS:     rssKB * 1024,
			Command: cmdStr,
		})
	}
	return procs
}

// StatusLabelClass は "ok"/"warning"/"danger" を表示用ラベルとCSSクラスに変換する（複数カードで共用）
func StatusLabelClass(status string) (label, class string) {
	switch status {
	case "danger":
		return "逼迫", "result-fail"
	case "warning":
		return "注意", "result-warning"
	default:
		return "安定", "result-success"
	}
}

// GetStorageForecast は直近7日ディスク使用率を線形回帰して逼迫予測を返す
func GetStorageForecast(agentID string) StorageForecastData {
	points := readResourcePoints(agentID)

	now := time.Now().In(heartdesk.JST())
	cutoff := now.Add(-7 * 24 * time.Hour)

	type pt struct {
		ts   time.Time
		disk float64
	}
	var filtered []pt
	for _, p := range points {
		if p.ts.After(cutoff) {
			filtered = append(filtered, pt{ts: p.ts, disk: p.disk})
		}
	}

	n := len(filtered)
	if n < 2 {
		return StorageForecastData{HasData: false, Status: "ok"}
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].ts.Before(filtered[j].ts)
	})

	// 線形回帰 y = a + bx (x = 基準時刻からの経過日数)
	ref := filtered[0].ts
	var sumX, sumY, sumXY, sumX2 float64
	fn := float64(n)
	for _, p := range filtered {
		x := p.ts.Sub(ref).Hours() / 24.0
		y := p.disk
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}
	denom := fn*sumX2 - sumX*sumX
	var slope float64
	if denom != 0 {
		slope = (fn*sumXY - sumX*sumY) / denom
	}

	current := filtered[n-1].disk
	windowDays := filtered[n-1].ts.Sub(ref).Hours() / 24.0

	var eta90, eta95 *float64
	if slope > 0 {
		v90 := math.Max(0, (90-current)/slope)
		v95 := math.Max(0, (95-current)/slope)
		eta90 = &v90
		eta95 = &v95
	}

	status := "ok"
	if current >= 90 || (eta90 != nil && *eta90 <= 7) {
		status = "danger"
	} else if current >= 80 || (eta90 != nil && *eta90 <= 30) {
		status = "warning"
	}

	// 表示用ラベルを生成
	slopeLabel := "横ばい"
	if slope > 0 {
		slopeLabel = fmt.Sprintf("+%.2f%%/日", slope)
	}
	eta90Label := "—"
	if eta90 != nil {
		eta90Label = fmt.Sprintf("約%d日", int(math.Round(*eta90)))
	}
	eta95Label := "—"
	if eta95 != nil {
		eta95Label = fmt.Sprintf("約%d日", int(math.Round(*eta95)))
	}
	statusLabel, statusClass := StatusLabelClass(status)

	return StorageForecastData{
		HasData:     true,
		Current:     math.Round(current*10) / 10,
		SlopePerDay: math.Round(slope*1000) / 1000,
		ETA90:       eta90,
		ETA95:       eta95,
		WindowDays:  math.Round(windowDays*10) / 10,
		Samples:     n,
		Status:      status,
		SlopeLabel:  slopeLabel,
		ETA90Label:  eta90Label,
		ETA95Label:  eta95Label,
		StatusLabel: statusLabel,
		StatusClass: statusClass,
	}
}

// =============================================================================
// ResourceMetricsGraph — Mackerel 代替グラフ API
// =============================================================================

// ResourceMetricsGraph は ?api=resource_graph のレスポンス
type ResourceMetricsGraph struct {
	Range       string         `json:"range"`
	GeneratedAt string         `json:"generated_at"`
	Series      []MetricSeries `json:"series"`
	Empty       bool           `json:"empty"`
	Warnings    []string       `json:"warnings,omitempty"`
}

type MetricSeries struct {
	Key   string       `json:"key"`
	Label string       `json:"label"`
	Unit  string       `json:"unit"`
	Lines []MetricLine `json:"lines"`
}

type MetricLine struct {
	Key    string        `json:"key"`
	Label  string        `json:"label"`
	Points []MetricPoint `json:"points"`
}

type MetricPoint struct {
	T string   `json:"t"`
	V *float64 `json:"v"`
}

type graphRangeCfg struct {
	duration  time.Duration
	bucketSec int // 0 = 全点そのまま / >0 = この秒数幅でバケット平均
	limit     int
}

var graphRanges = map[string]graphRangeCfg{
	"30min": {30 * time.Minute, 0, 200},
	"1h":    {time.Hour, 0, 200},
	"6h":    {6 * time.Hour, 600, 2000},
	"1d":    {24 * time.Hour, 60, 2000},
	"1W":    {7 * 24 * time.Hour, 3600, 5000},
	"1M":    {30 * 24 * time.Hour, 86400, 10000},
	"6M":    {180 * 24 * time.Hour, 86400, 10000},
	"1Y":    {365 * 24 * time.Hour, 86400, 10000},
}

type graphReport struct {
	ts  time.Time
	sys systemCollectorResult
}

// GetResourceMetricsGraph は agentID と range から時系列グラフデータを返す。
// 範囲不明時は "1d" にフォールバック。
func GetResourceMetricsGraph(agentID, rangeStr string) ResourceMetricsGraph {
	now := time.Now().In(heartdesk.JST())
	rcfg, ok := graphRanges[rangeStr]
	if !ok {
		rangeStr = "1d"
		rcfg = graphRanges["1d"]
	}

	from := now.Add(-rcfg.duration)
	reports := loadGraphReports(agentID, from, now, rcfg.limit)

	if len(reports) == 0 {
		return ResourceMetricsGraph{
			Range:       rangeStr,
			GeneratedAt: now.Format(time.RFC3339),
			Empty:       true,
		}
	}

	sort.Slice(reports, func(i, j int) bool {
		return reports[i].ts.Before(reports[j].ts)
	})

	series := buildMetricSeries(reports, rcfg.bucketSec)
	empty := true
	for _, s := range series {
		for _, l := range s.Lines {
			for _, p := range l.Points {
				if p.V != nil {
					empty = false
					break
				}
			}
			if !empty {
				break
			}
		}
		if !empty {
			break
		}
	}

	return ResourceMetricsGraph{
		Range:       rangeStr,
		GeneratedAt: now.Format(time.RFC3339),
		Series:      series,
		Empty:       empty,
	}
}

func loadGraphReports(agentID string, from, to time.Time, limit int) []graphReport {
	tenantID := tenantIDFromAgentID(agentID)
	if tenantID != "" {
		_, _, rs, ok := currentAgentReportStores()
		if ok {
			raws, err := rs.ListRawReports(context.Background(), tenantID, agentID, from, to, limit)
			if err == nil && len(raws) > 0 {
				out := make([]graphReport, 0, len(raws))
				for _, r := range raws {
					var cols map[string]json.RawMessage
					if err2 := json.Unmarshal([]byte(r.CollectorsJSON), &cols); err2 != nil {
						continue
					}
					raw, ok := cols["system"]
					if !ok {
						continue
					}
					sys, ok := decodeSystemCollectorResult(raw)
					if !ok {
						continue
					}
					out = append(out, graphReport{ts: r.ReceivedAt.In(heartdesk.JST()), sys: sys})
				}
				if len(out) > 0 {
					return out
				}
			}
		}
	}
	return loadGraphReportsJSONL(agentID, from, to)
}

func loadGraphReportsJSONL(agentID string, from, to time.Time) []graphReport {
	dir := agentReportDirPath()
	pattern := filepath.Join(dir, fmt.Sprintf("report_%s_*.jsonl", agentID))
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}
	var out []graphReport
	for _, fpath := range matches {
		f, err := os.Open(fpath)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 256*1024), 256*1024)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			var rec agentReportRecord
			if err2 := json.Unmarshal(line, &rec); err2 != nil {
				continue
			}
			ts, err2 := time.Parse(time.RFC3339, rec.ReportedAt)
			if err2 != nil {
				continue
			}
			if ts.Before(from) || ts.After(to) {
				continue
			}
			raw, ok := rec.Collectors["system"]
			if !ok {
				continue
			}
			sys, ok := decodeSystemCollectorResult(raw)
			if !ok {
				continue
			}
			out = append(out, graphReport{ts: ts.In(heartdesk.JST()), sys: sys})
		}
		_ = f.Close()
	}
	return out
}

func buildMetricSeries(reports []graphReport, bucketSec int) []MetricSeries {
	n := len(reports)
	if n == 0 {
		return nil
	}

	// バケットキー関数
	bucketKey := func(ts time.Time) string {
		if bucketSec == 0 {
			return ts.Format(time.RFC3339)
		}
		t := (ts.Unix() / int64(bucketSec)) * int64(bucketSec)
		return time.Unix(t, 0).In(heartdesk.JST()).Format(time.RFC3339)
	}

	// 累積カウンタの差分レートを各レポートに付与
	type enriched struct {
		ts          time.Time
		sys         systemCollectorResult
		diskIORead  map[string]float64 // device -> B/s
		diskIOWrite map[string]float64
		netRx       map[string]float64 // interface -> B/s
		netTx       map[string]float64
	}
	enr := make([]enriched, n)
	for i, r := range reports {
		enr[i] = enriched{ts: r.ts, sys: r.sys}
		if i == 0 {
			continue
		}
		prev := reports[i-1]
		elapsed := r.ts.Sub(prev.ts).Seconds()
		if elapsed <= 0 || elapsed > 3600 {
			continue
		}
		// Disk I/O
		prevDev := make(map[string]struct{ r, w int64 }, len(prev.sys.DiskIO))
		for _, d := range prev.sys.DiskIO {
			prevDev[d.Device] = struct{ r, w int64 }{d.ReadBytes, d.WriteBytes}
		}
		dr, dw := map[string]float64{}, map[string]float64{}
		for _, d := range r.sys.DiskIO {
			p, ok := prevDev[d.Device]
			if !ok {
				continue
			}
			if d.ReadBytes < p.r || d.WriteBytes < p.w {
				continue // カウンタリセット
			}
			dr[d.Device] = float64(d.ReadBytes-p.r) / elapsed
			dw[d.Device] = float64(d.WriteBytes-p.w) / elapsed
		}
		if len(dr) > 0 {
			enr[i].diskIORead = dr
			enr[i].diskIOWrite = dw
		}
		// Network I/O
		prevIf := make(map[string]struct{ rx, tx int64 }, len(prev.sys.NetworkIO))
		for _, nif := range prev.sys.NetworkIO {
			prevIf[nif.Interface] = struct{ rx, tx int64 }{nif.RxBytes, nif.TxBytes}
		}
		nr, nt := map[string]float64{}, map[string]float64{}
		for _, nif := range r.sys.NetworkIO {
			p, ok := prevIf[nif.Interface]
			if !ok {
				continue
			}
			if nif.RxBytes < p.rx || nif.TxBytes < p.tx {
				continue // カウンタリセット
			}
			nr[nif.Interface] = float64(nif.RxBytes-p.rx) / elapsed
			nt[nif.Interface] = float64(nif.TxBytes-p.tx) / elapsed
		}
		if len(nr) > 0 {
			enr[i].netRx = nr
			enr[i].netTx = nt
		}
	}

	// バケット順序を収集
	seenBkts := map[string]bool{}
	var ordBkts []string
	for _, e := range enr {
		k := bucketKey(e.ts)
		if !seenBkts[k] {
			seenBkts[k] = true
			ordBkts = append(ordBkts, k)
		}
	}

	// 集計用アキュムレータ
	type acc struct {
		sum float64
		n   int
	}
	addAcc := func(m map[string]*acc, k string, v float64) {
		if m[k] == nil {
			m[k] = &acc{}
		}
		m[k].sum += v
		m[k].n++
	}

	load1Acc := map[string]*acc{}
	load5Acc := map[string]*acc{}
	load15Acc := map[string]*acc{}
	cpuPctAcc := map[string]*acc{}
	cpuUserAcc, cpuNiceAcc, cpuSysAcc, cpuIdleAcc := map[string]*acc{}, map[string]*acc{}, map[string]*acc{}, map[string]*acc{}
	cpuIowaitAcc, cpuIrqAcc, cpuSoftirqAcc, cpuStealAcc := map[string]*acc{}, map[string]*acc{}, map[string]*acc{}, map[string]*acc{}
	memUsedAcc, memAvailAcc, memTotalAcc := map[string]*acc{}, map[string]*acc{}, map[string]*acc{}
	swapUsedAcc, swapTotalAcc := map[string]*acc{}, map[string]*acc{}
	diskRAccMap := map[string]map[string]*acc{}
	diskWAccMap := map[string]map[string]*acc{}
	netRxAccMap := map[string]map[string]*acc{}
	netTxAccMap := map[string]map[string]*acc{}
	fsUsedAccMap := map[string]map[string]*acc{}
	fsTotalAccMap := map[string]map[string]*acc{}
	hasCPUTimes := false

	for _, e := range enr {
		k := bucketKey(e.ts)
		addAcc(load1Acc, k, e.sys.Load.Load1)
		addAcc(load5Acc, k, e.sys.Load.Load5)
		addAcc(load15Acc, k, e.sys.Load.Load15)
		addAcc(cpuPctAcc, k, e.sys.CPU.UsagePercent)

		ct := e.sys.CPUTimes
		if ct.UserPct+ct.SystemPct+ct.IdlePct > 0 {
			hasCPUTimes = true
			addAcc(cpuUserAcc, k, ct.UserPct)
			addAcc(cpuNiceAcc, k, ct.NicePct)
			addAcc(cpuSysAcc, k, ct.SystemPct)
			addAcc(cpuIdleAcc, k, ct.IdlePct)
			addAcc(cpuIowaitAcc, k, ct.IowaitPct)
			addAcc(cpuIrqAcc, k, ct.IrqPct)
			addAcc(cpuSoftirqAcc, k, ct.SoftirqPct)
			addAcc(cpuStealAcc, k, ct.StealPct)
		}

		addAcc(memUsedAcc, k, float64(e.sys.Memory.UsedKB*1024))
		addAcc(memAvailAcc, k, float64(e.sys.Memory.AvailableKB*1024))
		addAcc(memTotalAcc, k, float64(e.sys.Memory.TotalKB*1024))
		addAcc(swapUsedAcc, k, float64(e.sys.Swap.UsedKB*1024))
		addAcc(swapTotalAcc, k, float64(e.sys.Swap.TotalKB*1024))

		for dev, rate := range e.diskIORead {
			if diskRAccMap[dev] == nil {
				diskRAccMap[dev] = map[string]*acc{}
			}
			addAcc(diskRAccMap[dev], k, rate)
		}
		for dev, rate := range e.diskIOWrite {
			if diskWAccMap[dev] == nil {
				diskWAccMap[dev] = map[string]*acc{}
			}
			addAcc(diskWAccMap[dev], k, rate)
		}

		for iface, rate := range e.netRx {
			if netRxAccMap[iface] == nil {
				netRxAccMap[iface] = map[string]*acc{}
			}
			addAcc(netRxAccMap[iface], k, rate)
		}
		for iface, rate := range e.netTx {
			if netTxAccMap[iface] == nil {
				netTxAccMap[iface] = map[string]*acc{}
			}
			addAcc(netTxAccMap[iface], k, rate)
		}

		for _, d := range e.sys.Disk {
			if fsUsedAccMap[d.MountPoint] == nil {
				fsUsedAccMap[d.MountPoint] = map[string]*acc{}
				fsTotalAccMap[d.MountPoint] = map[string]*acc{}
			}
			addAcc(fsUsedAccMap[d.MountPoint], k, float64(d.UsedKB*1024))
			addAcc(fsTotalAccMap[d.MountPoint], k, float64(d.TotalKB*1024))
		}
	}

	// バケット集計からポイント列を生成するヘルパー
	makePoints := func(accMap map[string]*acc) []MetricPoint {
		pts := make([]MetricPoint, 0, len(ordBkts))
		for _, bk := range ordBkts {
			if a := accMap[bk]; a != nil && a.n > 0 {
				v := math.Round(a.sum/float64(a.n)*10) / 10
				pts = append(pts, MetricPoint{T: bk, V: &v})
			} else {
				pts = append(pts, MetricPoint{T: bk})
			}
		}
		return pts
	}

	var series []MetricSeries

	// loadavg
	series = append(series, MetricSeries{
		Key: "loadavg", Label: "ロードアベレージ", Unit: "",
		Lines: []MetricLine{
			{Key: "load1", Label: "1分", Points: makePoints(load1Acc)},
			{Key: "load5", Label: "5分", Points: makePoints(load5Acc)},
			{Key: "load15", Label: "15分", Points: makePoints(load15Acc)},
		},
	})

	// cpu
	series = append(series, MetricSeries{
		Key: "cpu", Label: "CPU", Unit: "%",
		Lines: []MetricLine{
			{Key: "usage", Label: "使用率", Points: makePoints(cpuPctAcc)},
		},
	})

	// cpu_times（新 Agent からのデータがある場合のみ）
	if hasCPUTimes {
		series = append(series, MetricSeries{
			Key: "cpu_times", Label: "CPU内訳", Unit: "%",
			Lines: []MetricLine{
				{Key: "user", Label: "user", Points: makePoints(cpuUserAcc)},
				{Key: "nice", Label: "nice", Points: makePoints(cpuNiceAcc)},
				{Key: "system", Label: "system", Points: makePoints(cpuSysAcc)},
				{Key: "iowait", Label: "iowait", Points: makePoints(cpuIowaitAcc)},
				{Key: "irq", Label: "irq", Points: makePoints(cpuIrqAcc)},
				{Key: "softirq", Label: "softirq", Points: makePoints(cpuSoftirqAcc)},
				{Key: "steal", Label: "steal", Points: makePoints(cpuStealAcc)},
				{Key: "idle", Label: "idle", Points: makePoints(cpuIdleAcc)},
			},
		})
	}

	// memory
	series = append(series, MetricSeries{
		Key: "memory", Label: "メモリ", Unit: "bytes",
		Lines: []MetricLine{
			{Key: "used", Label: "使用", Points: makePoints(memUsedAcc)},
			{Key: "available", Label: "利用可能", Points: makePoints(memAvailAcc)},
			{Key: "total", Label: "合計", Points: makePoints(memTotalAcc)},
			{Key: "swap_used", Label: "Swap使用", Points: makePoints(swapUsedAcc)},
			{Key: "swap_total", Label: "Swap合計", Points: makePoints(swapTotalAcc)},
		},
	})

	// disk_io
	if len(diskRAccMap) > 0 {
		devs := make([]string, 0, len(diskRAccMap))
		for dev := range diskRAccMap {
			devs = append(devs, dev)
		}
		sort.Strings(devs)
		var diskLines []MetricLine
		for _, dev := range devs {
			diskLines = append(diskLines,
				MetricLine{Key: dev + "_read", Label: dev + " Read", Points: makePoints(diskRAccMap[dev])},
				MetricLine{Key: dev + "_write", Label: dev + " Write", Points: makePoints(diskWAccMap[dev])},
			)
		}
		series = append(series, MetricSeries{
			Key: "disk_io", Label: "Disk I/O", Unit: "B/s",
			Lines: diskLines,
		})
	}

	// network_io
	if len(netRxAccMap) > 0 {
		ifaces := make([]string, 0, len(netRxAccMap))
		for iface := range netRxAccMap {
			ifaces = append(ifaces, iface)
		}
		sort.Strings(ifaces)
		var netLines []MetricLine
		for _, iface := range ifaces {
			netLines = append(netLines,
				MetricLine{Key: iface + "_rx", Label: iface + " RX", Points: makePoints(netRxAccMap[iface])},
				MetricLine{Key: iface + "_tx", Label: iface + " TX", Points: makePoints(netTxAccMap[iface])},
			)
		}
		series = append(series, MetricSeries{
			Key: "network_io", Label: "ネットワーク I/O", Unit: "B/s",
			Lines: netLines,
		})
	}

	// filesystem
	if len(fsUsedAccMap) > 0 {
		mounts := make([]string, 0, len(fsUsedAccMap))
		for mount := range fsUsedAccMap {
			mounts = append(mounts, mount)
		}
		sort.Strings(mounts)
		var fsLines []MetricLine
		for _, mount := range mounts {
			fsLines = append(fsLines,
				MetricLine{Key: strings.ReplaceAll(mount, "/", "_") + "_used", Label: mount + " 使用", Points: makePoints(fsUsedAccMap[mount])},
				MetricLine{Key: strings.ReplaceAll(mount, "/", "_") + "_total", Label: mount + " 合計", Points: makePoints(fsTotalAccMap[mount])},
			)
		}
		series = append(series, MetricSeries{
			Key: "filesystem", Label: "ファイルシステム", Unit: "bytes",
			Lines: fsLines,
		})
	}

	return series
}
