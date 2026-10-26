package alerts

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNCFileAccessServiceDefaultSetsAreIsolated(t *testing.T) {
	first := []string{"svc-app"}
	second := []string{"svc-other"}
	settings := ncFileAccessSettings{}
	a, b := settings.serviceAccountSet(first), settings.serviceAccountSet(second)
	first[0] = "caller-change"
	delete(a, "svc-app")
	a["result-change"] = true
	if !b["svc-other"] || len(b) != 1 || second[0] != "svc-other" {
		t.Fatal("independent config or caller slice modified")
	}
	if got := settings.serviceAccountSet([]string{"svc-app"}); !got["svc-app"] || got["result-change"] {
		t.Fatal("result map leaked into later evaluation")
	}
	if len(settings.serviceAccountSet()) != 0 {
		t.Fatal("embedding defaults changed the standalone default")
	}
}

func TestNCFileAccessEmbeddedServiceDefaults(t *testing.T) {
	for _, tc := range []struct {
		name             string
		missing, generic bool
		settings         map[string]any
		excluded         string
	}{
		{name: "missing", missing: true, excluded: "svc-app"},
		{name: "omitted", settings: map[string]any{}, excluded: "svc-app"},
		{name: "null", settings: map[string]any{"service_accounts": nil}, excluded: "svc-app"},
		{name: "empty", settings: map[string]any{"service_accounts": []string{}}},
		{name: "custom", settings: map[string]any{"service_accounts": []string{"svc-other"}}, excluded: "svc-other"},
		{name: "standalone", generic: true, settings: map[string]any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newNCFATestEnv(t)
			env.cfg.Paths.NextcloudDir = filepath.Dir(filepath.Dir(env.auditPath))
			if !tc.generic {
				env.cfg.NCFileAccessDefaultServiceAccounts = []string{"svc-app"}
			}
			if tc.missing {
				if err := os.Remove(filepath.Join(env.dir, "data", "json", "nc_file_access.json")); err != nil {
					t.Fatal(err)
				}
			} else {
				tc.settings["audit_log_path"] = env.auditPath
				env.writeSettings(t, tc.settings)
			}
			now := ncFABaseNow
			withStubs(t, now, nil)
			rules, state := ncFARules(ruleNCMassAccess), newAlertState()
			writeFile(t, env.auditPath, "")
			env.run(rules, state, now)
			for _, uid := range []string{"svc-app", "svc-other", "alice@example.com"} {
				appendFile(t, env.auditPath, ncFAAccessLines(now.Add(-20*time.Minute), time.Second, 300, uid, "192.0.2.10", uaCurl, nil))
			}
			got := env.run(rules, state, now)
			want := 3
			if tc.excluded != "" {
				want--
			}
			if len(got) != want {
				t.Fatalf("got %d notifications, want %d: %v", len(got), want, got)
			}
			for _, uid := range []string{"svc-app", "svc-other", "alice@example.com"} {
				n := 1
				if uid == tc.excluded {
					n = 0
				}
				if countContaining(got, uid) != n {
					t.Errorf("classification for %s: got %v", uid, got)
				}
			}
		})
	}
}
