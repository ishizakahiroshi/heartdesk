package monitor

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadLocalBackupFilesSortsByModTime(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.sql.zst")
	newPath := filepath.Join(dir, "new.sql.zst")
	ignoredPath := filepath.Join(dir, "ignored.txt")
	if err := os.WriteFile(oldPath, []byte("old"), 0o600); err != nil {
		t.Fatalf("write old: %v", err)
	}
	if err := os.WriteFile(newPath, []byte("newer"), 0o600); err != nil {
		t.Fatalf("write new: %v", err)
	}
	if err := os.WriteFile(ignoredPath, []byte("ignored"), 0o600); err != nil {
		t.Fatalf("write ignored: %v", err)
	}
	oldTime := time.Date(2026, 6, 1, 10, 0, 0, 0, time.Local)
	newTime := time.Date(2026, 6, 2, 10, 0, 0, 0, time.Local)
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes old: %v", err)
	}
	if err := os.Chtimes(newPath, newTime, newTime); err != nil {
		t.Fatalf("chtimes new: %v", err)
	}

	files := loadLocalBackupFiles(dir, "*.sql.zst")

	if len(files) != 2 {
		t.Fatalf("len(files) = %d, want 2: %+v", len(files), files)
	}
	if files[0].Name != "new.sql.zst" || files[1].Name != "old.sql.zst" {
		t.Fatalf("unexpected order: %+v", files)
	}
	if files[0].Size != "5" || files[1].Size != "3" {
		t.Fatalf("unexpected sizes: %+v", files)
	}
	if files[0].Date == "" || files[1].Date == "" {
		t.Fatalf("date should be populated: %+v", files)
	}
}
