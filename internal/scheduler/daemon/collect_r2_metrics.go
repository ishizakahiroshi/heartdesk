package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/r2"
)

const r2MetricsMonthlyKeep = 3

// defaultR2MetricsOutputPath は HEARTDESK_BASE_DIR 基準の既定の出力先。
func defaultR2MetricsOutputPath() string {
	return heartdesk.PathOrDefault("data/json/r2_metrics.json")
}

type r2MetricsFile struct {
	Current r2MetricsCurrent   `json:"current"`
	Monthly []r2MetricsMonthly `json:"monthly"`
}

type r2MetricsCurrent struct {
	StorageBytes int64                      `json:"storage_bytes"`
	ObjectCount  int64                      `json:"object_count"`
	UpdatedAt    string                     `json:"updated_at"`
	Buckets      map[string]r2BucketSummary `json:"buckets"`
}

type r2BucketSummary struct {
	StorageBytes int64 `json:"storage_bytes"`
	ObjectCount  int64 `json:"object_count"`
}

type r2MetricsMonthly struct {
	Month           string `json:"month"`
	ClassA          int    `json:"class_a"`
	ClassB          int    `json:"class_b"`
	StorageBytesMax int64  `json:"storage_bytes_max"`
}

// CollectR2Metrics は collect_r2_metrics.sh 相当の R2 メトリクス収集・JSON永続化を実行する。
func CollectR2Metrics(ctx context.Context, cfg *config.SchedulerConfig) error {
	outputPath := defaultR2MetricsOutputPath()

	r2Cfg := r2.Config{}
	if cfg != nil {
		r2Cfg = r2.Config{
			AccountID: cfg.R2AccountID,
			APIToken:  cfg.R2APIToken,
			Buckets:   cfg.R2Buckets,
		}
	}
	data := r2.GetMetrics(r2Cfg)
	if data.Error != "" {
		return fmt.Errorf("r2 metrics fetch failed: %s", data.Error)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	existing := r2MetricsFile{Monthly: []r2MetricsMonthly{}}
	if raw, err := os.ReadFile(outputPath); err == nil {
		_ = json.Unmarshal(raw, &existing)
	}
	if existing.Monthly == nil {
		existing.Monthly = []r2MetricsMonthly{}
	}

	now := time.Now()
	current := r2MetricsCurrent{
		UpdatedAt: now.Format(time.RFC3339),
		Buckets:   map[string]r2BucketSummary{},
	}
	if data.Storage != nil {
		fmt.Sscanf(data.Storage.PayloadSize, "%d", &current.StorageBytes)
		fmt.Sscanf(data.Storage.ObjectCount, "%d", &current.ObjectCount)
		for name, b := range data.Storage.Buckets {
			var bSize, bCount int64
			fmt.Sscanf(b.PayloadSize, "%d", &bSize)
			fmt.Sscanf(b.ObjectCount, "%d", &bCount)
			current.Buckets[name] = r2BucketSummary{
				StorageBytes: bSize,
				ObjectCount:  bCount,
			}
		}
	}
	existing.Current = current

	if data.Operations != nil {
		month := now.Format("2006-01")
		classA := data.Operations.ClassA
		classB := data.Operations.ClassB
		found := false
		for i, m := range existing.Monthly {
			if m.Month != month {
				continue
			}
			found = true
			existing.Monthly[i].ClassA = classA
			existing.Monthly[i].ClassB = classB
			if current.StorageBytes > m.StorageBytesMax {
				existing.Monthly[i].StorageBytesMax = current.StorageBytes
			}
			break
		}
		if !found {
			existing.Monthly = append([]r2MetricsMonthly{{
				Month:           month,
				ClassA:          classA,
				ClassB:          classB,
				StorageBytesMax: current.StorageBytes,
			}}, existing.Monthly...)
		}
	}

	sort.Slice(existing.Monthly, func(i, j int) bool {
		return existing.Monthly[i].Month > existing.Monthly[j].Month
	})
	if len(existing.Monthly) > r2MetricsMonthlyKeep {
		existing.Monthly = existing.Monthly[:r2MetricsMonthlyKeep]
	}

	buf, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return fmt.Errorf("r2 metrics marshal failed: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o770); err != nil {
		return fmt.Errorf("r2 metrics dir create failed: %w", err)
	}
	tmp := outputPath + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return fmt.Errorf("r2 metrics write failed: %w", err)
	}
	return os.Rename(tmp, outputPath)
}
