package httpclassload

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadBoundsReceipts(t *testing.T) {
	dir := t.TempDir()
	parse := func(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	rc := func(id, ts string) string {
		return fmt.Sprintf(`{"ts":%q,"request_id":%q,"method":"GET","path_hash":"%s","status":404,"operation":"fetch_file","outcome":"integration_error"}`, ts, id, strings.Repeat("a", 64))
	}
	id := func(n int) string { return fmt.Sprintf("%032x", n) }
	old := rc(id(1), now.Add(-48*time.Hour).Format(time.RFC3339))
	cur := rc(id(2), now.Format(time.RFC3339))
	body := strings.Join([]string{old, cur, cur, "garbage"}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, ReceiptFile), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, got := Load(filepath.Join(dir, RawFile), filepath.Join(dir, ReceiptFile), now.Add(-time.Hour), parse, nil)
	if len(got) != 1 || got[0].RequestID != id(2) {
		t.Fatalf("want only the current receipt once, got %+v", got)
	}
}
