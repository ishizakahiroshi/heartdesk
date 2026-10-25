package scheduler

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
)

// jobLockPath は per-job filelock のパスを返す（二重起動防止用）。
// 本番（Linux）は /var/lock/heartdesk-job-<id>.lock。非 Unix では filelock 側が no-op。
func jobLockPath(jobID string) string {
	return filepath.Join("/var/lock", heartdesk.OperationalIdentity().SchedulerLockPrefix+"-job-"+jobID+".lock")
}

// cronSpec は 5 フィールド cron（分 時 日 月 曜）の最小表現。
// 本実装は heartdesk で使う範囲（"M H * * *" の時刻指定、"*/N * * * *" の分間隔、
// "* * * * *" の毎分）だけを解釈する。複雑な式（リスト/範囲/曜日指定）は
// 解釈不能として ok=false を返し、呼び出し側は interval ベースにフォールバックする。
type cronSpec struct {
	minute int // 0-59、-1 は "*"
	hour   int // 0-23、-1 は "*"
	everyN int // "*/N * * * *" の N（分間隔）。0 なら無効。
}

// parseCronSpec は cron 文字列を cronSpec に解釈する。
// 解釈できる形式のみ ok=true を返す。
func parseCronSpec(expr string) (cronSpec, bool) {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) != 5 {
		return cronSpec{}, false
	}
	// 日・月・曜は "*" のみ対応（時刻指定/分間隔ジョブに限定）。
	if fields[2] != "*" || fields[3] != "*" || fields[4] != "*" {
		return cronSpec{}, false
	}

	mn, hr := fields[0], fields[1]

	// "*/N * * * *": 分間隔。
	if strings.HasPrefix(mn, "*/") && hr == "*" {
		n, err := strconv.Atoi(strings.TrimPrefix(mn, "*/"))
		if err != nil || n <= 0 {
			return cronSpec{}, false
		}
		return cronSpec{minute: -1, hour: -1, everyN: n}, true
	}

	// "* * * * *": 毎分（everyN=1 と等価）。
	if mn == "*" && hr == "*" {
		return cronSpec{minute: -1, hour: -1, everyN: 1}, true
	}

	// "M H * * *": 時刻指定（時・分とも数値、または片方 "*"）。
	spec := cronSpec{minute: -1, hour: -1}
	if mn != "*" {
		v, err := strconv.Atoi(mn)
		if err != nil || v < 0 || v > 59 {
			return cronSpec{}, false
		}
		spec.minute = v
	}
	if hr != "*" {
		v, err := strconv.Atoi(hr)
		if err != nil || v < 0 || v > 23 {
			return cronSpec{}, false
		}
		spec.hour = v
	}
	// 分間隔でも毎分でもなく、時 or 分のいずれかが固定された時刻指定のみ受け付ける。
	if spec.minute == -1 && spec.hour == -1 {
		return cronSpec{}, false
	}
	return spec, true
}

// isWallClock は時刻指定（壁時計アライン必須）の cron かを返す。
// everyN > 0（分間隔/毎分）は interval ベースで足りるので false。
func (c cronSpec) isWallClock() bool {
	return c.everyN == 0
}

// next は from 以降で最初に一致する壁時計時刻（JST）を返す。
// 時刻指定（"M H * * *" / "M * * * *" / "* H * * *"）専用。
func (c cronSpec) next(from time.Time) time.Time {
	loc := heartdesk.JST()
	t := from.In(loc).Truncate(time.Minute).Add(time.Minute)
	// 最大 366 日先まで走査すれば必ず一致する（日/月/曜は "*" のみ）。
	for i := 0; i < 366*24*60; i++ {
		if (c.minute == -1 || t.Minute() == c.minute) &&
			(c.hour == -1 || t.Hour() == c.hour) {
			return t
		}
		t = t.Add(time.Minute)
	}
	// 到達しないはずだが、保険として 1 日後を返す。
	return from.Add(24 * time.Hour)
}
