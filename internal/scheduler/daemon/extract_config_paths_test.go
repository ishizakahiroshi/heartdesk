package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

func TestExtractUsesConfiguredDirectoriesReadByScore(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HEARTDESK_BASE_DIR", base)
	sourceLog := filepath.Join(base, "source.jsonl")
	accessLog := filepath.Join(base, "access.log")
	if err := os.WriteFile(sourceLog, []byte("{\"level\":2,\"message\":\"synthetic error\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	line := fmt.Sprintf("198.51.100.9 - - [%s] \"GET /nextcloud/example HTTP/1.1\" 403 1 \"-\" \"synthetic\"\n", now.Format("02/Jan/2006:15:04:05 -0700"))
	if err := os.WriteFile(accessLog, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.SchedulerConfig{NCEventBaseDir: filepath.Join(base, "configured-events"), NC4xxDir: filepath.Join(base, "configured-access")}
	for i := 0; i < 2; i++ {
		if err := extractNextcloudEventsAt(context.Background(), cfg, sourceLog, accessLog); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"extract_state.json", "extract_last.csv", "security_events.jsonl"} {
		if _, err := os.Stat(filepath.Join(cfg.NCEventBaseDir, name)); err != nil {
			t.Fatalf("configured event/state output %s missing: %v", name, err)
		}
	}
	records, err := filepath.Glob(filepath.Join(resolveScorePaths(cfg).NC4xxDir, "nc4xx_*.jsonl"))
	if err != nil || len(records) != 1 {
		t.Fatalf("score cannot discover configured producer output: %v %v", records, err)
	}
	body, err := os.ReadFile(records[0])
	if err != nil || strings.Count(strings.TrimSpace(string(body)), "\n") != 0 || !strings.Contains(string(body), `"ip":"198.51.100.9"`) {
		t.Fatalf("one access event should be stored exactly once: %q %v", body, err)
	}
	if _, err := os.Stat(extractNC4xxDir()); !os.IsNotExist(err) {
		t.Fatal("configured extraction also wrote to the unrelated default directory")
	}
}
