// audit_aggregated.go は Vendor Console 集約 SQLiteの
// Monitor 側のラッパー関数群。実体は internal/auditdb パッケージにある。
//
// agent_report.go の AgentReportHandler は audit_log payload を受けたとき
// auditdb.InsertEvents() を呼ぶ。Monitor 起動時は main.go から InitAuditAggregated() を呼んで
// SQLite を開く。
package monitor

import (
	"github.com/ishizakahiroshi/heartdesk/internal/auditdb"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// InitAuditAggregated は config.toml [audit_aggregated] を読んで集約 SQLite を初期化する。
// enabled=false（集約役ではない Monitor 等）の場合は no-op。
func InitAuditAggregated(c config.AuditAggregatedConfig) error {
	return auditdb.Init(auditdb.Config{
		Enabled:        c.Enabled,
		DBPath:         c.DBPath,
		RetentionYears: c.RetentionYears,
	})
}

// AuditAggregatedEnabled は受信パイプラインが INSERT 可能かを返す。
func AuditAggregatedEnabled() bool {
	return auditdb.Enabled()
}
