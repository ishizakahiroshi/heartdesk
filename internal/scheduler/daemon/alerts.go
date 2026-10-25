package daemon

import (
	"context"
	"github.com/ishizakahiroshi/heartdesk/internal"
	"log"

	"github.com/ishizakahiroshi/heartdesk/internal/alerts"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// RunAlerts は alerts 評価を daemon ジョブとして 1 回実行する。
// 旧 cmd/alerts バイナリの exec.Command 起動を置き換え、scheduler の Interval
// （AlertsInterval）で in-process 実行する。
//
// 評価ロジックの正本は internal/alerts。AppConfig はテナント設定込みで読み直す
// （SchedulerConfig には Alerts.RulesFile / StateFile が含まれないため）。
func RunAlerts(ctx context.Context, _ *config.SchedulerConfig) error {
	appCfg, err := config.LoadAppConfigForTenant(heartdesk.Env("HEARTDESK_TENANT_ID"))
	if err != nil {
		return err
	}
	fired, err := alerts.Run(appCfg)
	if err != nil {
		return err
	}
	for _, msg := range fired {
		log.Printf("[alerts] %s", msg)
	}
	return nil
}
