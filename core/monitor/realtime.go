package monitor

import (
	"strconv"
	"strings"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

// APIRealtimeResources は /proc 系ファイルからリアルタイムリソース情報を取得する
// PHP api/realtime.php api_realtime_resources() 相当
func APIRealtimeResources() RealtimeData {
	s := getResourceSample()

	// ディスク
	diskRaw := strings.TrimSpace(heartdesk.Run("df / | tail -1"))
	var diskPct int
	var diskUsed, diskTotal int64
	if diskRaw != "" {
		// /dev/vda2  51473408 5932396 43298644  12% /
		fields := strings.Fields(diskRaw)
		if len(fields) >= 5 {
			diskTotal, _ = strconv.ParseInt(fields[1], 10, 64)
			diskTotal *= 1024
			diskUsed, _ = strconv.ParseInt(fields[2], 10, 64)
			diskUsed *= 1024
			diskPct, _ = strconv.Atoi(strings.TrimSuffix(fields[4], "%"))
		}
	}

	return RealtimeData{
		CPURaw:    s.CPURaw,
		Memory:    s.Memory,
		Swap:      s.Swap,
		Disk:      DiskStat{Pct: diskPct, Used: diskUsed, Total: diskTotal},
		Network:   s.Network,
		Load:      s.Load,
		Timestamp: s.Timestamp,
	}
}
