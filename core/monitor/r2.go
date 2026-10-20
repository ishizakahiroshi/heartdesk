package monitor

import (
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/r2"
)

// GetR2Metrics は Cloudflare R2 のストレージ容量と月間操作回数を返す
func GetR2Metrics(cfg *config.AppConfig, agentID ...string) R2MetricsData {
	if len(agentID) > 0 && agentID[0] != "" {
		if data, ok := r2MetricsFromReport(agentID[0]); ok {
			return data
		}
		return R2MetricsData{}
	}

	r2Cfg := r2.Config{}
	if cfg != nil {
		r2Cfg = r2.Config{
			AccountID: cfg.CloudflareR2.AccountID,
			APIToken:  cfg.CloudflareR2.APIToken,
			Buckets:   cfg.CloudflareR2.Buckets,
			Bucket:    cfg.CloudflareR2.Bucket,
		}
	}
	d := r2.GetMetrics(r2Cfg)
	result := R2MetricsData{Error: d.Error}
	if d.Storage != nil {
		storage := &R2StorageInfo{
			PayloadSize: d.Storage.PayloadSize,
			ObjectCount: d.Storage.ObjectCount,
			Buckets:     map[string]R2BucketInfo{},
		}
		for name, b := range d.Storage.Buckets {
			storage.Buckets[name] = R2BucketInfo{
				PayloadSize: b.PayloadSize,
				ObjectCount: b.ObjectCount,
			}
		}
		result.Storage = storage
	}
	if d.Operations != nil {
		result.Operations = &R2OperationsInfo{
			ClassA: d.Operations.ClassA,
			ClassB: d.Operations.ClassB,
			Month:  d.Operations.Month,
		}
	}
	return result
}

// R2ListFiles は R2 バケット/プレフィックス配下のファイル行を新しい順で返す。
func R2ListFiles(cfg *config.AppConfig, bucket, prefix string) []string {
	r2Cfg := r2.Config{}
	if cfg != nil {
		r2Cfg = r2.Config{
			AccountID: cfg.CloudflareR2.AccountID,
			APIToken:  cfg.CloudflareR2.APIToken,
		}
	}
	return r2.ListFiles(r2Cfg, bucket, prefix)
}
