package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResourceHistoryContinuesAfterLargeReport(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	dir := filepath.Join(base, "data", "json", "agent_reports")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-8 * 24 * time.Hour).Format(time.RFC3339)
	current := time.Now().Add(-time.Minute).Format(time.RFC3339)
	record := func(ts string, padding string) string {
		return fmt.Sprintf(`{"reported_at":%q,"padding":%q,"collectors":{"system":{"disk":[{"mount_point":"/","usage_percent":25}]}}}`+"\n", ts, padding)
	}
	body := record(old, strings.Repeat("x", 600000)) + record(old, strings.Repeat("x", 9*1024*1024)) + record(current, "") + record(time.Now().Format(time.RFC3339), "")
	if err := os.WriteFile(filepath.Join(dir, "report_alpha-vps-host_202611.jsonl"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	got := GetStorageForecast("alpha-vps-host")
	if !got.HasData || got.Samples != 2 || got.Current != 25 {
		t.Fatalf("forecast = %+v", got)
	}
}
