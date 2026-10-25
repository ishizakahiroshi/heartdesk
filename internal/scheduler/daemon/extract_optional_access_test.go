package daemon

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

func TestExtractContinuesWhenOptionalAccessDirectoryUnavailable(t *testing.T) {
	for _, accessExists := range []bool{false, true} {
		t.Run(fmt.Sprintf("access_log_exists_%t", accessExists), func(t *testing.T) {
			base := t.TempDir()
			t.Setenv("HEARTDESK_BASE_DIR", base)
			source := filepath.Join(base, "source.jsonl")
			line := []byte("{\"level\":2,\"message\":\"Login failed: synthetic\",\"reqId\":\"example-request\",\"url\":\"/login\"}\n")
			if err := os.WriteFile(source, line, 0600); err != nil {
				t.Fatal(err)
			}
			// A regular-file parent makes MkdirAll fail on every supported OS,
			// including privileged test runners where chmod cannot block writes.
			blocked := filepath.Join(base, "blocked")
			if err := os.WriteFile(blocked, []byte("synthetic sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := &config.SchedulerConfig{NCEventBaseDir: filepath.Join(base, "events"), NC4xxDir: filepath.Join(blocked, "optional-access")}
			if err := os.MkdirAll(cfg.NC4xxDir, 0770); err == nil {
				t.Fatal("fixture did not block optional directory creation")
			}
			access := filepath.Join(base, "access.log")
			if accessExists {
				entry := fmt.Sprintf("198.51.100.9 - - [%s] \"GET /nextcloud/example HTTP/1.1\" 403 1 \"-\" \"synthetic\"\n", time.Now().Format("02/Jan/2006:15:04:05 -0700"))
				if err := os.WriteFile(access, []byte(entry), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for run := 0; run < 2; run++ {
				if err := extractNextcloudEventsAt(context.Background(), cfg, source, access); err != nil {
					t.Fatalf("optional access output failure aborted main extraction: %v", err)
				}
			}
			for _, name := range []string{"login_events.jsonl", "login_context.jsonl", "security_events.jsonl"} {
				body, err := os.ReadFile(filepath.Join(cfg.NCEventBaseDir, name))
				if err != nil || strings.Count(string(body), "\n") != 1 || !strings.Contains(string(body), "example-request") {
					t.Fatalf("main event %s was lost or replayed: %q %v", name, body, err)
				}
			}
			body, err := os.ReadFile(filepath.Join(cfg.NCEventBaseDir, "extract_state.json"))
			if err != nil {
				t.Fatal(err)
			}
			var state extractState
			if err := json.Unmarshal(body, &state); err != nil || state.Offset != int64(len(line)) || state.UpdatedAt == "" {
				t.Fatalf("main source checkpoint did not advance: %s %v", body, err)
			}
			heartbeat, err := os.ReadFile(filepath.Join(cfg.NCEventBaseDir, "extract_last.csv"))
			if err != nil {
				t.Fatal(err)
			}
			rows, err := csv.NewReader(strings.NewReader(string(heartbeat))).ReadAll()
			if err != nil || len(rows) != 3 || rows[1][1] != "1" || rows[2][1] != "0" {
				t.Fatalf("heartbeat did not record both runs and checkpoint reuse: %q %v", heartbeat, err)
			}
			if content, err := os.ReadFile(blocked); err != nil || string(content) != "synthetic sentinel" {
				t.Fatal("blocked optional parent was modified")
			}
			if _, err := os.Stat(extractNC4xxDir()); !os.IsNotExist(err) {
				t.Fatal("optional output failure wrote to an unrelated fallback directory")
			}
		})
	}
}

func TestExtractStillRejectsUnavailableMainInputOrOutput(t *testing.T) {
	for _, blockedMainOutput := range []bool{false, true} {
		t.Run(fmt.Sprintf("blocked_main_output_%t", blockedMainOutput), func(t *testing.T) {
			base := t.TempDir()
			t.Setenv("HEARTDESK_BASE_DIR", base)
			source := filepath.Join(base, "missing-source.jsonl")
			events := filepath.Join(base, "events")
			if blockedMainOutput {
				if err := os.WriteFile(source, []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(events, []byte("synthetic sentinel"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cfg := &config.SchedulerConfig{NCEventBaseDir: events, NC4xxDir: filepath.Join(base, "optional-access")}
			if err := extractNextcloudEventsAt(context.Background(), cfg, source, filepath.Join(base, "missing-access.log")); err == nil {
				t.Fatal("main input/output failure was suppressed")
			}
		})
	}
}
