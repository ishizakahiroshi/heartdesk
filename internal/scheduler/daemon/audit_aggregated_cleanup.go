package daemon

import (
	"context"
	"github.com/ishizakahiroshi/heartdesk/internal"
	"log"

	"github.com/ishizakahiroshi/heartdesk/internal/auditdb"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// AuditAggregatedCleanup は audit_log_aggregated テーブルから retention_years より古い行を削除する。
//
//   - 集約役テナント（audit_aggregated.enabled=true）のみ実働する。
//   - 他テナントでは Init が no-op になるので Cleanup も 0 件で正常終了する。
//   - 24h 間隔で実行（registry.go の Interval 設定。Plan 上の "毎日 03:00" は時刻指定ではなく日次の意。）
func AuditAggregatedCleanup(ctx context.Context, _ *config.SchedulerConfig) error {
	appCfg, err := config.LoadAppConfigForTenant(heartdesk.Env("HEARTDESK_TENANT_ID"))
	if err != nil {
		return err
	}
	if !appCfg.AuditAggregated.Enabled {
		log.Printf("audit_aggregated_cleanup: disabled (tenant=%s)", heartdesk.Env("HEARTDESK_TENANT_ID"))
		return nil
	}

	// 既に初期化済み（同一プロセスの Monitor が起動時に Init 済み）の場合は、その共有
	// グローバルハンドルに対して Cleanup するだけにする。ここで Init/Close すると Monitor の
	// InsertEvents が使うハンドルを閉じて受信を断絶させてしまうため、Init/Close しない。
	if auditdb.Enabled() {
		n, err := auditdb.Cleanup()
		if err != nil {
			return err
		}
		log.Printf("audit_aggregated_cleanup: deleted %d row(s) (shared handle)", n)
		return nil
	}

	// 未初期化（スケジューラ単独プロセス等）の場合のみ自前で Init/Close する。
	if err := auditdb.Init(auditdb.Config{
		Enabled:        appCfg.AuditAggregated.Enabled,
		DBPath:         appCfg.AuditAggregated.DBPath,
		RetentionYears: appCfg.AuditAggregated.RetentionYears,
	}); err != nil {
		return err
	}
	defer auditdb.Close()
	n, err := auditdb.Cleanup()
	if err != nil {
		return err
	}
	log.Printf("audit_aggregated_cleanup: deleted %d row(s)", n)
	return nil
}
