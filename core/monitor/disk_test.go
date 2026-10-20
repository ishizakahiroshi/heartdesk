package monitor

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestListNextcloudLogFilesSortsAndLimits(t *testing.T) {
	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "nextcloud.log.1.gz"),
		filepath.Join(dir, "nextcloud.log.2.gz"),
		filepath.Join(dir, "nextcloud.log.3.gz"),
		filepath.Join(dir, "other.log.4.gz"),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	base := time.Date(2026, 6, 1, 10, 0, 0, 0, time.Local)
	if err := os.Chtimes(paths[0], base, base); err != nil {
		t.Fatalf("chtimes 1: %v", err)
	}
	if err := os.Chtimes(paths[1], base.Add(time.Hour), base.Add(time.Hour)); err != nil {
		t.Fatalf("chtimes 2: %v", err)
	}
	if err := os.Chtimes(paths[2], base.Add(2*time.Hour), base.Add(2*time.Hour)); err != nil {
		t.Fatalf("chtimes 3: %v", err)
	}

	files := listNextcloudLogFiles(dir, 2)

	if len(files) != 2 {
		t.Fatalf("len(files) = %d, want 2: %+v", len(files), files)
	}
	if files[0].Name != "nextcloud.log.3.gz" || files[1].Name != "nextcloud.log.2.gz" {
		t.Fatalf("unexpected order: %+v", files)
	}
	if files[0].Date != "2026-06-01" {
		t.Fatalf("date = %q, want 2026-06-01", files[0].Date)
	}
}
