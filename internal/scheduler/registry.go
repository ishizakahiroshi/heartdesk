package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/filelock"
	schedulerdaemon "github.com/ishizakahiroshi/heartdesk/internal/scheduler/daemon"
	"github.com/ishizakahiroshi/heartdesk/internal/scheduler/ondemand"
)

const defaultStateFilePath = "/home/sab/data/json/scheduler_state.json" // secrets-scan: allow

func resolveStateFilePath(configured string) string {
	if v := strings.TrimSpace(os.Getenv("SCHED_STATE_FILE")); v != "" {
		return v
	}
	if configured != "" {
		return configured
	}
	return defaultStateFilePath
}

type persistedState struct {
	JobID        string    `json:"job_id"`
	LastStarted  time.Time `json:"last_started"`
	LastFinished time.Time `json:"last_finished"`
	LastDuration int64     `json:"last_duration_ns"`
	LastError    string    `json:"last_error"`
	Running      bool      `json:"running"`
}

func loadStateFile(path string) map[string]RuntimeState {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var items map[string]persistedState
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil
	}
	out := make(map[string]RuntimeState, len(items))
	for id, p := range items {
		out[id] = RuntimeState{
			JobID:        p.JobID,
			LastStarted:  p.LastStarted,
			LastFinished: p.LastFinished,
			LastDuration: time.Duration(p.LastDuration),
			LastError:    p.LastError,
			Running:      p.Running,
		}
	}
	return out
}

func saveStateFile(path string, states map[string]RuntimeState) error {
	items := make(map[string]persistedState, len(states))
	for id, st := range states {
		items[id] = persistedState{
			JobID:        st.JobID,
			LastStarted:  st.LastStarted,
			LastFinished: st.LastFinished,
			LastDuration: int64(st.LastDuration),
			LastError:    st.LastError,
			Running:      st.Running,
		}
	}
	buf, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

const (
	CategoryDaemon   = "daemon"
	CategoryOnDemand = "ondemand"
)

type Handler func(ctx context.Context, cfg *config.SchedulerConfig) error

type JobDef struct {
	ID                  string
	Label               string
	Summary             string
	Category            string
	Interval            time.Duration
	Handler             Handler
	DefaultCronSchedule string
	RunOnStartup        bool
}

type RuntimeState struct {
	JobID        string
	LastStarted  time.Time
	LastFinished time.Time
	LastDuration time.Duration
	LastError    string
	Running      bool
}

var (
	registryMu sync.RWMutex
	jobDefs    map[string]*JobDef
)

func init() {
	jobDefs = map[string]*JobDef{
		"collect_resources": {
			ID:                  "collect_resources",
			Label:               "collect_resources",
			Summary:             "リソース使用率CSV記録",
			Category:            CategoryDaemon,
			Interval:            5 * time.Minute,
			Handler:             schedulerdaemon.CollectResources,
			DefaultCronSchedule: "*/5 * * * *",
			RunOnStartup:        true,
		},
		"score_engine": {
			ID:                  "score_engine",
			Label:               "score_engine",
			Summary:             "脅威スコアCSV出力",
			Category:            CategoryDaemon,
			Interval:            5 * time.Minute,
			Handler:             schedulerdaemon.ScoreEngine,
			DefaultCronSchedule: "*/5 * * * *",
			RunOnStartup:        true,
		},
		"sab_extract": {
			ID:                  "sab_extract",
			Label:               "sab-extract",
			Summary:             "Nextcloud重要イベント抽出JSONL",
			Category:            CategoryDaemon,
			Interval:            1 * time.Minute,
			Handler:             schedulerdaemon.ExtractNextcloudEvents,
			DefaultCronSchedule: "* * * * *",
			RunOnStartup:        true,
		},
		"backup_mariadb": {
			ID:                  "backup_mariadb",
			Label:               "backup_mariadb",
			Summary:             "MariaDBバックアップ + R2アップロード",
			Category:            CategoryOnDemand,
			Handler:             ondemand.BackupMariaDB,
			DefaultCronSchedule: "0 1 * * *",
			RunOnStartup:        false,
		},
		"update_geoip_db": {
			ID:                  "update_geoip_db",
			Label:               "update_geoip_db",
			Summary:             "IPinfo Lite MMDB 日次更新",
			Category:            CategoryDaemon,
			Interval:            24 * time.Hour,
			Handler:             schedulerdaemon.UpdateGeoIPDB,
			DefaultCronSchedule: "45 4 * * *",
			RunOnStartup:        true,
		},
		"collect_r2_metrics": {
			ID:                  "collect_r2_metrics",
			Label:               "collect_r2_metrics",
			Summary:             "Cloudflare R2 ストレージ・操作回数 JSON保存",
			Category:            CategoryDaemon,
			Interval:            24 * time.Hour,
			Handler:             schedulerdaemon.CollectR2Metrics,
			DefaultCronSchedule: "0 2 * * *",
			RunOnStartup:        false,
		},
		"audit_aggregated_cleanup": {
			ID:                  "audit_aggregated_cleanup",
			Label:               "audit_aggregated_cleanup",
			Summary:             "Vendor Console 集約 SQLite から retention_years 超過行を削除",
			Category:            CategoryDaemon,
			Interval:            24 * time.Hour,
			Handler:             schedulerdaemon.AuditAggregatedCleanup,
			DefaultCronSchedule: "0 3 * * *",
			RunOnStartup:        false,
		},
		// C8（alerts-never-invoked）: alerts を別バイナリ（exec.Command）ではなく
		// daemon ジョブとして登録。Interval は ToSchedulerConfig の AlertsInterval を
		// NewScheduler が反映する（cfg.AlertsInterval > 0 のとき上書き）。
		"alerts": {
			ID:                  "alerts",
			Label:               "alerts",
			Summary:             "リソース/アカウントロックアウトのアラート評価・通知",
			Category:            CategoryDaemon,
			Interval:            5 * time.Minute,
			Handler:             schedulerdaemon.RunAlerts,
			DefaultCronSchedule: "*/5 * * * *",
			RunOnStartup:        false,
		},
		// C8（purge-jobs-unregistered）: 実装済みだが未登録だった purge ジョブを
		// CategoryDaemon・24h 既定で登録。VendorPurgeIntervalHours / VendorDBPath が
		// 未設定なら NewScheduler が purge ジョブを無効化する（既存ロジックを活かす）。
		"purge_old_reports": {
			ID:                  "purge_old_reports",
			Label:               "purge_old_reports",
			Summary:             "Vendor 集約 SQLite の古いレポート・監査ログを retention に基づき削除",
			Category:            CategoryDaemon,
			Interval:            24 * time.Hour,
			Handler:             schedulerdaemon.PurgeOldReports,
			DefaultCronSchedule: "30 3 * * *",
			RunOnStartup:        false,
		},
		"purge_archived_tenants": {
			ID:                  "purge_archived_tenants",
			Label:               "purge_archived_tenants",
			Summary:             "soft delete から 30 日経過したテナントの関連データを物理削除",
			Category:            CategoryDaemon,
			Interval:            24 * time.Hour,
			Handler:             schedulerdaemon.PurgeArchivedTenants,
			DefaultCronSchedule: "45 3 * * *",
			RunOnStartup:        false,
		},
	}
}

// RegisterJob は組み込みのジョブに加えて、利用側が独自のジョブを登録する口。
// NewScheduler が呼ばれる前（main の起動時や init）に呼ぶ。同じ ID は上書きする。
// ID が空・Handler が nil のものは登録しない。
func RegisterJob(def *JobDef) {
	if def == nil || strings.TrimSpace(def.ID) == "" || def.Handler == nil {
		return
	}
	cloned := *def
	registryMu.Lock()
	defer registryMu.Unlock()
	jobDefs[cloned.ID] = &cloned
}

func GetJobDef(id string) (*JobDef, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	def, ok := jobDefs[id]
	if !ok {
		return nil, fmt.Errorf("job not found: %s", id)
	}
	return def, nil
}

func ListJobs() []*JobDef {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]*JobDef, 0, len(jobDefs))
	for _, def := range jobDefs {
		out = append(out, def)
	}
	return out
}

func initialRuntimeStates(jobs map[string]*JobDef) map[string]RuntimeState {
	out := make(map[string]RuntimeState, len(jobs))
	for id := range jobs {
		out[id] = RuntimeState{JobID: id}
	}
	return out
}

func (s *Scheduler) snapshotState(id string) RuntimeState {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	st, ok := s.jobState[id]
	if !ok {
		return RuntimeState{JobID: id}
	}
	return st
}

// SnapshotStates はジョブの実行状態を返す。
// 別プロセス（sab 本体）から呼ばれた場合は、scheduler が書き出した state ファイルをマージして返す。
func SnapshotStates() map[string]RuntimeState {
	return snapshotStatesFrom(resolveStateFilePath(""), initialRuntimeStates(jobDefs))
}

func (s *Scheduler) SnapshotStates() map[string]RuntimeState {
	s.stateMu.RLock()
	out := make(map[string]RuntimeState, len(s.jobState))
	for id, st := range s.jobState {
		out[id] = st
	}
	s.stateMu.RUnlock()
	return snapshotStatesFrom(s.stateFile, out)
}

func snapshotStatesFrom(stateFile string, out map[string]RuntimeState) map[string]RuntimeState {
	if fileStates := loadStateFile(stateFile); len(fileStates) > 0 {
		for id, st := range fileStates {
			cur, ok := out[id]
			if !ok {
				out[id] = st
				continue
			}
			// メモリ側が未実行で、ファイル側が実行済みの記録を持っていればそちらを優先
			if cur.LastFinished.IsZero() && !st.LastFinished.IsZero() {
				out[id] = st
			} else if !cur.LastFinished.IsZero() && !st.LastFinished.IsZero() && st.LastFinished.After(cur.LastFinished) {
				out[id] = st
			}
		}
	}
	return out
}

func (s *Scheduler) setState(id string, state RuntimeState) {
	s.stateMu.Lock()
	s.jobState[id] = state
	s.stateMu.Unlock()

	// C8（state-file-cross-process-clobber）: 全 jobState スナップショットを丸ごと
	// 書き戻すと、monitor プロセス（jobState がゼロ値起点）が daemon の記録した
	// 他ジョブの LastFinished/LastError を消してしまう。これを防ぐため
	// 「ファイルから現状ロード → 該当ジョブのみ更新 → 保存」の read-modify-write にする。
	// プロセス跨ぎの後勝ち消失は state ファイルの flock で直列化して避ける。
	s.stateFileSaveMu.Lock()
	defer s.stateFileSaveMu.Unlock()

	if unlock, lerr := filelock.Acquire(s.stateFile + ".lock"); lerr == nil {
		defer unlock()
	}
	// ErrLocked（他プロセスが書込中）等でも read-modify-write 自体は安全に行えるため続行する。

	merged := loadStateFile(s.stateFile)
	if merged == nil {
		merged = map[string]RuntimeState{}
	}
	merged[id] = state
	_ = saveStateFile(s.stateFile, merged)
}

func buildAPIRunMap(configured map[string]string) map[string]string {
	_ = config.LoadDaemonEnvOptional()
	out := map[string]string{
		"backup_run": "backup_mariadb",
	}
	for key, jobID := range configured {
		if key != "" && jobID != "" {
			out[key] = jobID
		}
	}
	raw := strings.TrimSpace(os.Getenv("SCHED_API_RUN_MAP"))
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		jobID := strings.TrimSpace(kv[1])
		if key == "" || jobID == "" {
			continue
		}
		out[key] = jobID
	}
	return out
}

// ResolveOnDemandJobID は API 名から起動対象ジョブIDを解決する。
// SCHED_API_RUN_MAP="backup_run:backup_mariadb" で上書きできる。
func ResolveOnDemandJobID(api string) (string, bool) {
	return resolveOnDemandJobID(api, buildAPIRunMap(nil))
}

func (s *Scheduler) ResolveOnDemandJobID(api string) (string, bool) {
	return resolveOnDemandJobID(api, s.apiRunMap)
}

func resolveOnDemandJobID(api string, apiJobMap map[string]string) (string, bool) {
	api = strings.TrimSpace(api)
	if api == "" {
		return "", false
	}
	jobID, ok := apiJobMap[api]
	return jobID, ok
}
