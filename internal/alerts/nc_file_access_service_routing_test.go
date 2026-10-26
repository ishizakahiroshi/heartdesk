package alerts

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReviewEmbeddedDefaultsNewIPAndBrokenSettings(t *testing.T) {
	for _, mode := range []string{"omitted", "broken", "empty", "custom"} {
		t.Run(mode, func(t *testing.T) {
			env := newNCFATestEnv(t)
			env.cfg.NCFileAccessDefaultServiceAccounts = []string{"svc-embedded"}
			env.cfg.Paths.NextcloudDir = filepath.Join(env.dir, "nc")
			switch mode {
			case "broken":
				writeFile(t, filepath.Join(env.dir, "data", "json", "nc_file_access.json"), "{broken")
			case "empty":
				env.writeSettings(t, map[string]any{"audit_log_path": env.auditPath, "service_accounts": []string{}})
			case "custom":
				env.writeSettings(t, map[string]any{"audit_log_path": env.auditPath, "service_accounts": []string{"svc-custom"}})
			default:
				env.writeSettings(t, map[string]any{"audit_log_path": env.auditPath})
			}
			t0 := ncFABaseNow
			withStubs(t, t0, nil)
			state := newAlertState()
			rules := ncFARules(ruleNCServiceNewIP)
			writeFile(t, env.auditPath, "")
			env.run(rules, state, t0)
			t1 := t0.Add(3*24*time.Hour + time.Hour)
			appendFile(t, env.auditPath, ncFALoginLine(t1.Add(-time.Minute), "svc-embedded", "192.0.2.42")+ncFALoginLine(t1.Add(-time.Minute), "svc-custom", "192.0.2.43"))
			got := env.run(rules, state, t1)
			switch mode {
			case "empty":
				if len(got) != 0 {
					t.Fatalf("explicit empty must suppress service alerts: %v", got)
				}
			case "custom":
				if len(got) != 1 || !strings.Contains(got[0], "svc-custom") || strings.Contains(got[0], "svc-embedded") {
					t.Fatalf("custom list must replace defaults: %v", got)
				}
			default:
				if len(got) != 1 || !strings.Contains(got[0], "svc-embedded") || strings.Contains(got[0], "svc-custom") {
					t.Fatalf("embedded default must reach service new-IP rule: %v", got)
				}
			}
		})
	}
}
