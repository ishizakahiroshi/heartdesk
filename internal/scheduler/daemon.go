package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/filelock"
)

type Scheduler struct {
	cfg             *config.SchedulerConfig
	jobs            map[string]*JobDef
	logger          *log.Logger
	stateFile       string
	apiRunMap       map[string]string
	jobState        map[string]RuntimeState
	stateMu         sync.RWMutex
	stateFileSaveMu sync.Mutex
}

func NewScheduler(cfg *config.SchedulerConfig, logger *log.Logger) *Scheduler {
	if logger == nil {
		logger = log.Default()
	}
	stateFile := ""
	apiRunMap := map[string]string(nil)
	if cfg != nil {
		stateFile = cfg.StateFile
		apiRunMap = cfg.APIRunMap
	}
	s := &Scheduler{
		cfg:       cfg,
		jobs:      make(map[string]*JobDef),
		logger:    logger,
		stateFile: resolveStateFilePath(stateFile),
		apiRunMap: buildAPIRunMap(apiRunMap),
	}
	for _, def := range ListJobs() {
		cloned := *def
		s.jobs[def.ID] = &cloned
	}
	s.jobState = initialRuntimeStates(s.jobs)
	if cfg != nil {
		if job, ok := s.jobs["collect_resources"]; ok && cfg.CollectInterval > 0 {
			job.Interval = cfg.CollectInterval
		}
		if job, ok := s.jobs["score_engine"]; ok && cfg.ScoreInterval > 0 {
			job.Interval = cfg.ScoreInterval
		}
		if job, ok := s.jobs[extractJobID]; ok && cfg.ExtractInterval > 0 {
			job.Interval = cfg.ExtractInterval
		}
		if job, ok := s.jobs["update_geoip_db"]; ok && cfg.UpdateGeoIPDBInterval > 0 {
			job.Interval = cfg.UpdateGeoIPDBInterval
		}
		// AlertsInterval を実際に alerts ジョブへ反映する。
		if job, ok := s.jobs["alerts"]; ok && cfg.AlertsInterval > 0 {
			job.Interval = cfg.AlertsInterval
		}
		if cfg.VendorPurgeIntervalHours > 0 {
			purgeInterval := time.Duration(cfg.VendorPurgeIntervalHours) * time.Hour
			if job, ok := s.jobs["purge_archived_tenants"]; ok {
				job.Interval = purgeInterval
			}
			if job, ok := s.jobs["purge_old_reports"]; ok {
				job.Interval = purgeInterval
			}
		} else {
			// VendorDBPath が未設定 = Vendor DB なし → purge ジョブを無効化
			delete(s.jobs, "purge_archived_tenants")
			delete(s.jobs, "purge_old_reports")
		}
		// GeoIP を使わない構成（DB パスも IPinfo トークンも未設定）では update_geoip_db を
		// 登録しない。登録したままだと起動時と毎日「not configured」エラーになる。
		if !geoIPUpdateConfigured(cfg) {
			delete(s.jobs, "update_geoip_db")
		}
		for id := range cfg.DisabledJobs {
			delete(s.jobs, id)
		}
	}
	return s
}

// geoIPUpdateConfigured は GeoIP DB の更新ジョブに必要な設定のどれかが入っているかを返す。
// DB パス（[paths].geoip_db）も IPinfo トークン（[geoip].token）も空なら、GeoIP を使わない構成。
// どちらか片方でも入っていれば、設定漏れをエラーで知らせられるようにジョブは登録する。
func geoIPUpdateConfigured(cfg *config.SchedulerConfig) bool {
	return strings.TrimSpace(cfg.GeoIPDBPath) != "" || strings.TrimSpace(cfg.GeoIPToken) != ""
}

func (s *Scheduler) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, job := range s.daemonJobs() {
		wg.Add(1)
		go func(def *JobDef) {
			defer wg.Done()
			s.runDaemonJob(ctx, def)
		}(job)
	}

	<-ctx.Done()
	wg.Wait()
	return ctx.Err()
}

func (s *Scheduler) RunJob(ctx context.Context, jobID string) error {
	def, ok := s.jobs[jobID]
	if !ok {
		return fmt.Errorf("job not found: %s", jobID)
	}
	return s.execute(ctx, def)
}

func (s *Scheduler) daemonJobs() []*JobDef {
	items := make([]*JobDef, 0, len(s.jobs))
	for _, def := range s.jobs {
		if def.Category == CategoryDaemon && def.Interval > 0 {
			items = append(items, def)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func (s *Scheduler) runDaemonJob(ctx context.Context, def *JobDef) {
	// DefaultCronSchedule が時刻指定（"0 1 * * *" 等）なら壁時計アラインで
	// 発火させる。これにより daemon の起動時刻に関係なく backup(01:00) /
	// collect_r2(02:00) / update_geoip(04:45) 等が確実にその時刻に走る。interval/分間隔ジョブは従来通り
	// ticker で回す。
	if spec, ok := parseCronSpec(def.DefaultCronSchedule); ok && spec.isWallClock() {
		s.runCronJob(ctx, def, spec)
		return
	}

	ticker := time.NewTicker(def.Interval)
	defer ticker.Stop()

	s.logger.Printf("[scheduler] daemon start: %s interval=%s", def.ID, def.Interval)
	if def.RunOnStartup {
		_ = s.execute(ctx, def)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.execute(ctx, def)
		}
	}
}

// runCronJob は時刻指定 cron ジョブを壁時計（JST）にアラインして実行する。
func (s *Scheduler) runCronJob(ctx context.Context, def *JobDef, spec cronSpec) {
	s.logger.Printf("[scheduler] daemon start (cron): %s schedule=%q", def.ID, def.DefaultCronSchedule)
	if def.RunOnStartup {
		_ = s.execute(ctx, def)
	}
	for {
		next := spec.next(time.Now())
		d := time.Until(next)
		if d < 0 {
			d = 0
		}
		timer := time.NewTimer(d)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			_ = s.execute(ctx, def)
		}
	}
}

func (s *Scheduler) execute(ctx context.Context, def *JobDef) (err error) {
	if def.Handler == nil {
		return fmt.Errorf("handler is nil: %s", def.ID)
	}

	// per-job filelock でプロセス跨ぎの二重起動を防ぐ。
	// daemon ループ・monitor の on-demand 実行・全 on-demand ジョブを一律カバーする。
	// メモリ内 st.Running はプロセス内ガードに留まるためプロセス間排他には flock が必須。
	// 競合（ErrLocked）は「実行中」エラーとして返し、open 失敗等の本物のエラーとは区別する。
	unlock, lerr := filelock.Acquire(jobLockPath(def.ID))
	if lerr != nil {
		if errors.Is(lerr, filelock.ErrLocked) {
			s.logger.Printf("[scheduler] skip (already running): %s", def.ID)
			return fmt.Errorf("job already running: %s", def.ID)
		}
		// ロックファイル open 失敗（権限等）は致命扱いにせず警告して継続する
		// （/var/lock 不在環境でもジョブを止めない）。
		s.logger.Printf("[scheduler] WARN: lock acquire failed for %s: %v (continuing)", def.ID, lerr)
		unlock = func() {}
	}
	defer unlock()

	start := time.Now()
	st := s.snapshotState(def.ID)
	st.Running = true
	st.LastStarted = start
	s.setState(def.ID, st)

	// defer は LIFO。状態保存を先に登録（最後に実行）し、recover を後に登録（最初に実行）する。
	// これにより panic → recover で err へ反映 → 状態保存が確定済み err を 1 回だけ書く順序になる。
	defer func() {
		finish := time.Now()
		st := s.snapshotState(def.ID)
		st.Running = false
		st.LastFinished = finish
		st.LastDuration = finish.Sub(start)
		if err != nil {
			st.LastError = err.Error()
		} else {
			st.LastError = ""
		}
		s.setState(def.ID, st)
		s.logger.Printf("[scheduler] state saved: %s LastFinished=%v LastError=%q", def.ID, st.LastFinished, st.LastError)
	}()

	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("panic recovered on %s: %v", def.ID, rec)
			s.logger.Printf("[scheduler] panic: %s err=%v", def.ID, rec)
		}
	}()

	s.logger.Printf("[scheduler] run start: %s", def.ID)
	err = def.Handler(ctx, s.cfg)
	if err != nil {
		s.logger.Printf("[scheduler] run fail: %s err=%v", def.ID, err)
		return err
	}
	s.logger.Printf("[scheduler] run done: %s", def.ID)
	return nil
}
