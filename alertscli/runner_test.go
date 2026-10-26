package alertscli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeEffects struct {
	files          map[string][]byte
	events         []string
	mails          []string
	stdout, stderr bytes.Buffer
	now            time.Time
	failMail       bool
}

func fakePaths() Paths {
	return Paths{"alpha/resources.csv", "alpha/scores.csv", "alpha/rules.json", "alpha/state.json", "alpha/stamp.csv", "alpha/managed.toml", "alpha/lockout.jsonl"}
}
func newFakeEffects() *fakeEffects {
	return &fakeEffects{files: map[string][]byte{}, now: time.Date(2026, 10, 26, 5, 0, 0, 0, time.UTC)}
}
func (f *fakeEffects) deps() Dependencies {
	return Dependencies{
		Now: func() time.Time { return f.now },
		ReadFile: func(path string) ([]byte, error) {
			f.events = append(f.events, "read:"+path)
			data, ok := f.files[path]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return append([]byte(nil), data...), nil
		},
		Open: func(path string) (io.ReadCloser, error) {
			f.events = append(f.events, "open:"+path)
			data, ok := f.files[path]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return io.NopCloser(bytes.NewReader(data)), nil
		},
		MkdirAll: func(path string, mode os.FileMode) error {
			f.events = append(f.events, "mkdir:"+path)
			if mode != 0770 {
				panic("unexpected directory mode")
			}
			return nil
		},
		WriteFile: func(path string, data []byte, mode os.FileMode) error {
			if mode != 0644 {
				panic("unexpected file mode")
			}
			f.events = append(f.events, "write:"+path)
			f.files[path] = append([]byte(nil), data...)
			return nil
		},
		Command: func(args ...string) string {
			f.events = append(f.events, "command:"+strings.Join(args, " "))
			return "inactive"
		},
		SendMail: func(_ map[string]string, to, subject, body string) error {
			f.events = append(f.events, "mail:"+subject)
			f.mails = append(f.mails, to+"|"+subject+"|"+body)
			if f.failMail {
				return errors.New("synthetic delivery failure")
			}
			return nil
		},
		Stdout: &f.stdout, Stderr: &f.stderr,
	}
}

func TestRunHistoricalPipelineAndBestEffortDelivery(t *testing.T) {
	f := newFakeEffects()
	p := fakePaths()
	f.failMail = true
	rules := map[string]any{"rules": map[string]any{}, "smtp": map[string]string{"mode": "synthetic"}, "recipients": []map[string]any{{"name": "Example A", "email": "a@example.invalid", "enabled": false, "rules": map[string]bool{"memory_high": false}}, {"name": "Example B", "email": "b@example.invalid"}}}
	for _, id := range []string{"memory_high", "disk_high", "service_down_nginx", "service_down_mariadb", "threat_score_critical", "account_lockout"} {
		rules["rules"].(map[string]any)[id] = map[string]any{"enabled": true, "sustain_sec": 86400, "notify_recovery": true}
	}
	f.files[p.Rules], _ = json.Marshal(rules)
	f.files[p.ResourceLog] = []byte("stamp,cpu,95,96\n")
	f.files[p.ScoreLog] = []byte("time,ip,score,a,b,c,d,e,f,g\nnow,192.0.2.20,999,,,,,,,\nnow,198.51.100.10,150,,,,,,,\n")
	f.files[p.ManagedIPs] = []byte("[[ips]]\nip=\"192.0.2.20\"\nname=\"Excluded\"\ntype=\"wlm\"\n[[ips]]\nip=\"198.51.100.10\"\nname=\"Example host\"\ntype=\"known\"\n")
	f.files[p.Lockout] = []byte(`{"timestamp":"2026-10-26T04:59:59Z","username":"alpha-user","ip":"203.0.113.10"}` + "\n")
	runner := New(Options{Paths: p, TestSubject: "Example test", TestBody: "Synthetic body", Dependencies: f.deps()})
	if len(f.events) != 0 {
		t.Fatal("construction performed an effect")
	}
	runner.Run(true)
	if len(f.mails) != 14 {
		t.Fatalf("normal evaluation then test mail must reach every legacy recipient: got %d, want 14; %v", len(f.mails), f.events)
	}
	wantSubjects := []string{"memory_high", "disk_high", "service_down_nginx", "service_down_mariadb", "threat_score_critical", "account_lockout"}
	for i, id := range wantSubjects {
		if !strings.Contains(f.mails[2*i], "【アラート】"+id) || !strings.Contains(f.mails[2*i+1], "【アラート】"+id) {
			t.Fatalf("evaluation order drift for %s", id)
		}
	}
	if !strings.Contains(f.mails[8], "198.51.100.10") || strings.Contains(f.mails[8], "999") {
		t.Fatal("managed-IP exclusion/label contract changed")
	}
	stampIndex, testIndex, stateIndex := -1, -1, -1
	for i, event := range f.events {
		if event == "write:"+p.LastCheck {
			stampIndex = i
		}
		if event == "mail:Example test" && testIndex < 0 {
			testIndex = i
		}
		if event == "write:"+p.State {
			stateIndex = i
		}
	}
	if !(stampIndex >= 0 && stampIndex < testIndex && testIndex < stateIndex) {
		t.Fatalf("stamp/test/state sequence changed: %v", f.events)
	}
	if string(f.files[p.LastCheck]) != f.now.Format("2006-01-02T15:04:05-07:00")+"\n" {
		t.Fatal("last-check timestamp drift")
	}
	var state AlertState
	if err := json.Unmarshal(f.files[p.State], &state); err != nil {
		t.Fatal(err)
	}
	for _, id := range wantSubjects[:5] {
		if !getBool(state[id], "active", false) || getFloat(state[id], "last_alert_time", 0) != float64(f.now.Unix()) {
			t.Errorf("legacy state did not advance despite delivery failure for %s", id)
		}
	}
	if getFloat(state["account_lockout"], "last_check_time", 0) != float64(f.now.Unix()) {
		t.Fatal("lockout offset-time contract drift")
	}
	if strings.Count(f.stderr.String(), "synthetic delivery failure") != 2 {
		t.Fatal("test-mail stderr contract drift")
	}
	f.mails = nil
	f.events = nil
	runner.Run(false)
	if len(f.mails) != 0 {
		t.Fatal("active alerts or old lockout events repeated on second run")
	}
}

func TestIndependentRunnersAndLegacyJSONFallback(t *testing.T) {
	for _, raw := range []string{"not-json", "[]", "null"} {
		t.Run(raw, func(t *testing.T) {
			f := newFakeEffects()
			p := fakePaths()
			f.files[p.Rules] = []byte(raw)
			f.files[p.State] = []byte(raw)
			r := New(Options{Paths: p, Dependencies: f.deps()})
			r.Run(true)
			if len(f.mails) != 0 {
				t.Fatal("invalid/empty rules sent a message")
			}
			if f.stdout.String() != "SMTP config not configured\n" {
				t.Fatal("empty SMTP test output drift")
			}
			var state AlertState
			if json.Unmarshal(f.files[p.State], &state) != nil || len(state) != 0 {
				t.Fatal("invalid state did not save empty nested map")
			}
		})
	}
	first, second := newFakeEffects(), newFakeEffects()
	first.now = first.now.Add(-time.Hour)
	a, b := New(Options{Paths: fakePaths(), Dependencies: first.deps()}), New(Options{Paths: fakePaths(), Dependencies: second.deps()})
	a.Run(false)
	b.Run(false)
	if bytes.Equal(first.files[fakePaths().LastCheck], second.files[fakePaths().LastCheck]) {
		t.Fatal("per-instance clocks leaked")
	}
	if len(first.files) != 2 || len(second.files) != 2 {
		t.Fatal("per-instance IO leaked")
	}
}

func TestDefaultPathsAndOptionsOwnership(t *testing.T) {
	t.Setenv("HEARTDESK_BASE_DIR", "example-base")
	t.Setenv("HEARTDESK_CONFIG_DIR", "example-config")
	want := Paths{filepath.Join("example-base", "data/csv/resource_log.csv"), filepath.Join("example-base", "data/csv/threat_score.csv"), filepath.Join("example-base", "data/json/alert_rules.json"), "/tmp/heartdesk_alert_state.json", filepath.Join("example-base", "data/json/alert_check_last.csv"), filepath.Join("example-config", "managed_ips.toml"), filepath.Join("example-base", "data/nc_extract/lockout_events.jsonl")}
	if got := DefaultPaths(); !reflect.DeepEqual(got, want) {
		t.Fatalf("public defaults drift: got %v want %v", got, want)
	}
	f := newFakeEffects()
	opts := Options{Paths: fakePaths(), Dependencies: f.deps()}
	r := New(opts)
	opts.Paths.State = "other"
	opts.Dependencies.Now = func() time.Time { return time.Time{} }
	if r.paths.State != "alpha/state.json" || r.deps.Now().IsZero() {
		t.Fatal("caller mutation changed constructed runner")
	}
	public := New(Options{Dependencies: f.deps()})
	if public.testSubject != "【テスト】heartdesk アラート通知テスト" || public.testBody == "" {
		t.Fatal("public test identity drift")
	}
}

func TestManagedIPsFallbackAndCooldownContract(t *testing.T) {
	f := newFakeEffects()
	p := fakePaths()
	f.files["alpha/managed.json"] = []byte(`[{"ip":"192.0.2.10","name":"Example","type":"known"}]`)
	r := New(Options{Paths: p, Dependencies: f.deps()})
	entries, err := r.loadSSHIPEntries()
	if err != nil || len(entries) != 1 || entries[0].Name != "Example" {
		t.Fatal("legacy JSON fallback drift")
	}
	if !r.shouldAlert(0, 86400, 0) || r.shouldAlert(float64(f.now.Unix()), 0, 86400) {
		t.Fatal("historical sustain/cooldown contract drift")
	}
	f.files[p.ManagedIPs] = []byte("invalid = [")
	if _, err := r.loadSSHIPEntries(); err == nil {
		t.Fatal("malformed TOML incorrectly fell back to JSON")
	}
}
