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
	body := record(old, strings.Repeat("x", 600000)) + record(current, "") + record(time.Now().Format(time.RFC3339), "")
	path := filepath.Join(dir, "report_alpha-vps-host_202611.jsonl")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	got := GetStorageForecast("alpha-vps-host")
	if !got.HasData || got.Samples != 2 || got.Current != 25 {
		t.Fatalf("forecast = %+v", got)
	}
	if err := os.WriteFile(path, []byte(record(old, strings.Repeat("x", 9*1024*1024))+body), 0600); err != nil {
		t.Fatal(err)
	}
	got = GetStorageForecast("alpha-vps-host")
	if got.HasData || !got.Incomplete {
		t.Fatalf("oversized history should not produce a forecast: %+v", got)
	}
}

func TestResourceHistorySkipsUnchangedOldFilesAndRejectsCorruption(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	dir := filepath.Join(base, "data", "json", "agent_reports")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(dir, "report_alpha-vps-host_202501.jsonl")
	if err := os.WriteFile(oldPath, []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if _, incomplete := readResourcePoints("alpha-vps-host"); incomplete {
		t.Fatal("old file should not affect the recent window")
	}
	currentPath := filepath.Join(dir, "report_alpha-vps-host_202502.jsonl")
	if err := os.WriteFile(currentPath, []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got := GetStorageForecast("alpha-vps-host")
	if got.HasData || !got.Incomplete {
		t.Fatalf("corrupt history should not produce a forecast: %+v", got)
	}
}

func BenchmarkResourceHistory(b *testing.B) {
	base := b.TempDir()
	b.Setenv("HEARTDESK_BASE_DIR", base)
	dir := filepath.Join(base, "data", "json", "agent_reports")
	if err := os.MkdirAll(dir, 0700); err != nil {
		b.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "report_alpha-vps-host_202611.jsonl"))
	if err != nil {
		b.Fatal(err)
	}
	line := fmt.Sprintf(`{"reported_at":%q,"padding":%q,"collectors":{"system":{"disk":[{"mount_point":"/","usage_percent":25}]}}}`+"\n", time.Now().Format(time.RFC3339), strings.Repeat("x", 4096))
	for i := 0; i < 16384; i++ {
		if _, err := f.WriteString(line); err != nil {
			b.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(line) * 16384))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := GetStorageForecast("alpha-vps-host"); !got.HasData {
			b.Fatal("missing forecast")
		}
	}
}
