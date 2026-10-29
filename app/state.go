package app

import (
	"context"
	"fmt"
	"github.com/ishizakahiroshi/heartdesk/core/monitor"
	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc"
	"github.com/ishizakahiroshi/heartdesk/internal/vendorsvc/store"
	"log"
	"path/filepath"
)

// initializeState belongs to Run, not construction. It preserves the standard
// startup restores, optional maintenance and durable report store fallback.
func (r *Runtime) initializeState() error {
	cfg := r.config

	// DB 初期化
	if dsn := cfg.Database.DSN; dsn != "" {
		if err := heartdesk.InitDB(dsn); err != nil {
			return fmt.Errorf("initialize database: %w", err)
		}
		r.ownedDB = heartdesk.DB()
	}

	// 集約 SQLite（Vendor Console 監査ログ集約。enabled=true のテナントのみ）
	if err := monitor.InitAuditAggregated(cfg.AuditAggregated); err != nil {
		log.Printf("audit_aggregated init failed: %v", err)
	} else if cfg.AuditAggregated.Enabled {
		r.ownedAuditDB = true
	}

	// Keep existing report history on JSONL. Tenant is intentionally not
	// injected, so monitor.currentAgentReportStores selects the JSONL path.
	// The vendor database remains available for its existing ledger functions.
	reportDBPath := filepath.Join(r.opts.DataDir, "vendor", "vendor.db")
	if db, err := vendorsvc.OpenDB(reportDBPath); err != nil {
		log.Printf("WARN: agent report SQLite open failed (path=%s): %v — JSONL フォールバックで起動します", reportDBPath, err)
	} else {
		r.reportDB = db
		monitor.SetAgentReportStores(&store.Stores{
			Agent:  store.NewAgentStore(db),
			Report: store.NewReportStore(db),
			Ledger: store.NewLedgerStore(db),
		})
		log.Printf("INFO: agent report store = JSONL; vendor ledger uses SQLite (path=%s)", reportDBPath)

		// 旧 JSON ライセンス台帳（vendor_license_ledger.json）を license_ledger へ一度だけ取り込む。
		// license_ledger に既存行があれば no-op（冪等）。元 JSON はバックアップとして残す。
		dataDir := r.opts.DataDir
		legacyLedgerPath := filepath.Join(dataDir, "vendor_license_ledger.json")
		if n, mErr := store.MigrateLedgerFromJSONFile(context.Background(), db, legacyLedgerPath); mErr != nil {
			log.Printf("WARN: license ledger migration failed: %v", mErr)
		} else if n > 0 {
			log.Printf("INFO: migrated %d license ledger entries from JSON to SQLite", n)
		}
	}
	// Restore existing report state and revocations before accepting requests.
	// Keep the existing store configuration and JSONL fallback during embedding.
	monitor.RestoreAgentLastSeen()
	monitor.RestoreLicenseRevokeStore()
	monitor.RestoreLegacyTokenStore()
	monitor.InitAgentMemoStore()

	return nil
}
