package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// expectedJobIDs は registry.go の jobDefs に登録されているべきジョブ ID 一覧。
// purge_old_reports /
// purge_archived_tenants / alerts の登録漏れ再発をこのテストで検知する。
var expectedJobIDs = []string{
	"collect_resources",
	"score_engine",
	"heartdesk_extract",
	"backup_mariadb",
	"update_geoip_db",
	"collect_r2_metrics",
	"audit_aggregated_cleanup",
	"alerts",
	"purge_old_reports",
	"purge_archived_tenants",
}

// TestListJobsCount は登録ジョブの件数と顔ぶれが期待どおりであることを検証する。
func TestListJobsCount(t *testing.T) {
	jobs := ListJobs()
	if len(jobs) != len(expectedJobIDs) {
		got := make([]string, 0, len(jobs))
		for _, j := range jobs {
			got = append(got, j.ID)
		}
		t.Fatalf("ListJobs() count = %d, want %d; got IDs = %v", len(jobs), len(expectedJobIDs), got)
	}

	have := make(map[string]bool, len(jobs))
	for _, j := range jobs {
		have[j.ID] = true
	}
	for _, want := range expectedJobIDs {
		if !have[want] {
			t.Errorf("expected job %q not registered in jobDefs", want)
		}
	}
}

// TestRetiredJobsNotRegistered は geofilter へ移管した旧 ipset 更新ジョブの
// 再登録を検知する。
func TestRetiredJobsNotRegistered(t *testing.T) {
	for _, id := range []string{"update_japan_ips"} {
		if _, err := GetJobDef(id); err == nil {
			t.Fatalf("retired job %q must not be registered", id)
		}
	}
}

// TestPurgeAndAlertsRegistered は alerts / purge_old_reports / purge_archived_tenants の 3 ジョブが
// CategoryDaemon・Handler 付き・Interval>0 で登録されていることを確認する。
func TestPurgeAndAlertsRegistered(t *testing.T) {
	for _, id := range []string{"alerts", "purge_old_reports", "purge_archived_tenants"} {
		def, err := GetJobDef(id)
		if err != nil {
			t.Fatalf("GetJobDef(%q) error: %v", id, err)
		}
		if def.Category != CategoryDaemon {
			t.Errorf("%s: Category = %q, want %q", id, def.Category, CategoryDaemon)
		}
		if def.Handler == nil {
			t.Errorf("%s: Handler is nil", id)
		}
		if def.Interval <= 0 {
			t.Errorf("%s: Interval = %v, want > 0", id, def.Interval)
		}
	}
}

// TestParseCronSpecWallClock は時刻指定 cron の解釈と次回発火計算を検証する。
func TestParseCronSpecWallClock(t *testing.T) {
	spec, ok := parseCronSpec("0 1 * * *")
	if !ok {
		t.Fatal("parseCronSpec(\"0 1 * * *\") not ok")
	}
	if !spec.isWallClock() {
		t.Fatal("expected wall-clock spec for \"0 1 * * *\"")
	}
	if spec.hour != 1 || spec.minute != 0 {
		t.Fatalf("spec = %+v, want hour=1 minute=0", spec)
	}

	// JST 01:30 起動を模した from。01:00 は過ぎているので次回は翌日 01:00。
	from := time.Date(2026, 5, 31, 1, 30, 0, 0, time.FixedZone("JST", 9*3600))
	next := spec.next(from)
	if next.Hour() != 1 || next.Minute() != 0 {
		t.Fatalf("next(%v) = %v, want 01:00", from, next)
	}
	if !next.After(from) {
		t.Fatalf("next(%v) = %v must be after from", from, next)
	}

	// 分間隔は wall-clock ではない（interval ベース）。
	if s, ok := parseCronSpec("*/5 * * * *"); !ok || s.isWallClock() {
		t.Fatalf("\"*/5 * * * *\" should parse as non-wall-clock interval, got ok=%v spec=%+v", ok, s)
	}
}

// TestRegisterJob は利用側が独自ジョブを足せること（登録の口）と、
// 不正な定義（ID 空・Handler なし）が無視されることを確認する。
func TestRegisterJob(t *testing.T) {
	const id = "register_job_test_job"
	t.Cleanup(func() {
		registryMu.Lock()
		delete(jobDefs, id)
		registryMu.Unlock()
	})

	RegisterJob(nil)
	RegisterJob(&JobDef{ID: "", Handler: func(context.Context, *config.SchedulerConfig) error { return nil }})
	RegisterJob(&JobDef{ID: id})
	if _, err := GetJobDef(id); err == nil {
		t.Fatalf("job without handler must not be registered")
	}

	RegisterJob(&JobDef{
		ID:       id,
		Category: CategoryDaemon,
		Interval: time.Minute,
		Handler:  func(context.Context, *config.SchedulerConfig) error { return nil },
	})
	def, err := GetJobDef(id)
	if err != nil {
		t.Fatalf("GetJobDef(%q): %v", id, err)
	}
	if def.Interval != time.Minute {
		t.Errorf("Interval = %v, want 1m", def.Interval)
	}
	s := NewScheduler(&config.SchedulerConfig{}, nil)
	if _, ok := s.jobs[id]; !ok {
		t.Errorf("registered job must be visible to NewScheduler")
	}
}
