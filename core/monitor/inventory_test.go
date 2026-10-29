package monitor

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartdesk/web"
)

func inventoryFixture(at time.Time, version, status string) json.RawMessage {
	stamp := at.UTC().Format(time.RFC3339)
	value := map[string]any{"schema_version": 1, "observed_at": stamp}
	for key, data := range map[string]any{"os": map[string]string{"ID": "debian", "VERSION_ID": "13"}, "kernel": "6.1-fixture", "packages": []map[string]string{{"name": "sample", "version": version, "architecture": "amd64"}}, "runtimes": []any{}, "containers": []any{}} {
		value[key] = map[string]any{"status": status, "source": "synthetic", "observed_at": stamp, "value": data}
	}
	raw, _ := json.Marshal(value)
	return raw
}

func TestInventoryFreshnessAllowsHourlySamplingGrace(t *testing.T) {
	now := time.Date(2026, 10, 29, 3, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		age   time.Duration
		stale bool
	}{
		{"hourly_jitter", time.Hour + 30*time.Second, false},
		{"grace_boundary", 2 * time.Hour, false},
		{"grace_exceeded", 2*time.Hour + time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := inventoryView("alpha-vps-fixture", []json.RawMessage{inventoryFixture(now.Add(-tc.age), "1.0", "ok")}, now)
			if v.Stale != tc.stale {
				t.Fatalf("stale=%v want=%v", v.Stale, tc.stale)
			}
			for _, section := range v.Sections {
				if section.Stale != tc.stale {
					t.Fatalf("%s stale=%v want=%v", section.Key, section.Stale, tc.stale)
				}
			}
		})
	}
}
func TestInventoryChangesNeverTreatFailureAsDeletion(t *testing.T) {
	now := time.Now().UTC()
	older := inventoryFixture(now.Add(-20*time.Minute), "1.0", "ok")
	current := inventoryFixture(now, "2.0", "ok")
	v := inventoryView("alpha-vps-fixture", []json.RawMessage{current, older}, now)
	if v.Status != "ok" || len(v.Changes) != 1 || v.Changes[0].Before != "1.0" || v.Changes[0].After != "2.0" {
		t.Fatalf("changes: %+v", v)
	}
	failed := inventoryFixture(now, "", "permission_denied")
	v = inventoryView("alpha-vps-fixture", []json.RawMessage{failed, current, older}, now)
	if v.Status != "partial" || len(v.Changes) != 0 || v.Sections[2].Items["sample:amd64"] != "2.0" || v.Sections[2].LastSuccessAt == "" {
		t.Fatalf("failure erased last success: %+v", v)
	}
	v = inventoryView("alpha-vps-fixture", []json.RawMessage{older}, now.Add(2*time.Hour))
	if !v.Stale || v.Status != "stale" {
		t.Fatal("old inventory became fresh")
	}
}
func TestInventoryRejectsMalformedAndIgnoresUnknownFields(t *testing.T) {
	for _, raw := range []string{`{}`, `null`, `{"_error":"synthetic"}`, `{"schema_version":99}`} {
		if v := inventoryView("alpha-vps-fixture", []json.RawMessage{json.RawMessage(raw)}, time.Now()); v.Status != "error" || len(v.Changes) > 0 {
			t.Fatal("invalid snapshot accepted")
		}
	}
	items, ok := inventoryItems("os", json.RawMessage(`{"ID":"debian","secret":"synthetic-secret"}`))
	if !ok || len(items) != 1 {
		t.Fatal("OS allowlist failed")
	}
}

func TestInventoryInvalidObservationCannotReplaceLastSuccess(t *testing.T) {
	now := time.Now().UTC()
	good := inventoryFixture(now.Add(-time.Minute), "1.0", "ok")
	for _, badTime := range []string{"invalid", now.Add(time.Hour).Format(time.RFC3339)} {
		var snapshot map[string]any
		_ = json.Unmarshal(inventoryFixture(now, "2.0", "ok"), &snapshot)
		snapshot["packages"].(map[string]any)["observed_at"] = badTime
		bad, _ := json.Marshal(snapshot)
		v := inventoryView("alpha-vps-fixture", []json.RawMessage{bad, good}, now)
		if v.Sections[2].Status != "error" || v.Sections[2].Items["sample:amd64"] != "1.0" || len(v.Changes) != 0 {
			t.Fatalf("invalid observation replaced saved data: %+v", v)
		}
	}
	var poisoned map[string]any
	_ = json.Unmarshal(inventoryFixture(now, "2.0", "ok"), &poisoned)
	poisoned["_error"] = ""
	bad, _ := json.Marshal(poisoned)
	v := inventoryView("alpha-vps-fixture", []json.RawMessage{bad, good}, now)
	if v.Sections[2].Items["sample:amd64"] != "1.0" || len(v.Changes) != 0 {
		t.Fatal("failed historical snapshot treated as success")
	}
}

func TestInventoryPartialMergeDoesNotDeleteUnobservedItems(t *testing.T) {
	now := time.Now().UTC()
	good := inventoryFixture(now.Add(-time.Minute), "1.0", "ok")
	var partial map[string]any
	_ = json.Unmarshal(inventoryFixture(now, "2.0", "partial"), &partial)
	partial["packages"].(map[string]any)["value"] = []map[string]string{{"name": "other", "version": "3.0", "architecture": "amd64"}}
	raw, _ := json.Marshal(partial)
	v := inventoryView("alpha-vps-fixture", []json.RawMessage{raw, good}, now)
	if v.Sections[2].Items["sample:amd64"] != "1.0" || v.Sections[2].Items["other:amd64"] != "3.0" || len(v.Changes) != 0 {
		t.Fatalf("partial discovery lost saved items: %+v", v)
	}
}

func TestInventoryRejectsAmbiguousRuntimeAndContainerValues(t *testing.T) {
	for _, tt := range []struct{ key, value string }{
		{"runtimes", `[{"status":"ok","kind":"php-cli","binary":"php","evidence":"path_probe"}]`},
		{"containers", `[{"id":"one","image_id":"a"},{"id":"one","image_id":"b"}]`},
	} {
		if _, ok := inventoryItems(tt.key, json.RawMessage(tt.value)); ok {
			t.Fatalf("ambiguous %s accepted", tt.key)
		}
	}
}

func TestInventoryRetainsMultipleRunningVersionsAtSamePath(t *testing.T) {
	data := json.RawMessage(`[{"status":"ok","kind":"php-fpm","binary":"/usr/sbin/php-fpm","evidence":"proc_exe","version":"8.4.2","deleted":true},{"status":"ok","kind":"php-fpm","binary":"/usr/sbin/php-fpm","evidence":"proc_exe","version":"8.4.1","deleted":true},{"status":"ok","kind":"php-fpm","binary":"/usr/sbin/php-fpm","evidence":"proc_exe","version":"8.4.3"}]`)
	items, ok := inventoryItems("runtimes", data)
	if !ok || items["php-fpm:proc_exe:/usr/sbin/php-fpm (deleted)"] != "8.4.1 / 8.4.2" || items["php-fpm:proc_exe:/usr/sbin/php-fpm"] != "8.4.3" {
		t.Fatalf("running versions collapsed: %+v", items)
	}
}

func renderInventoryPreview(t *testing.T, data UpdatesData) string {
	t.Helper()
	funcs := template.FuncMap{}
	for _, name := range []string{"fval", "fpct", "barClass", "pctClass", "pctBarClass", "pctClassStr", "pctWidth", "pctWidthStr", "pctBarClassStr", "cardLabel"} {
		funcs[name] = func(...interface{}) string { return "システムアップデート" }
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(web.Templates(), "*.html")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := tmpl.ExecuteTemplate(&out, "card-sec-updates", data); err != nil {
		t.Fatal(err)
	}
	return out.String()
}
func TestInventoryCardPreview(t *testing.T) {
	data := UpdatesData{UbuntuVer: "Synthetic Linux", Unavailable: true}
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	v := inventoryView("alpha-vps-fixture", []json.RawMessage{inventoryFixture(now, "2.0", "ok"), inventoryFixture(now.Add(-time.Hour), "1.0", "ok")}, now)
	data.Inventory = &v
	body := renderInventoryPreview(t, data)
	if !strings.Contains(body, "Synthetic Linux") {
		t.Fatal("preview missing card")
	}
	if dir := os.Getenv("HEARTDESK_INVENTORY_PREVIEW_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		css, err := fs.ReadFile(web.Static(), "css/shared.css")
		if err != nil {
			t.Fatal(err)
		}
		write := func(name, content string) {
			page := "<!doctype html><html lang=ja><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>構成情報・合成データ検証</title><style>" + string(css) + "</style><body style='padding:24px;max-width:1100px;margin:auto'><h1>合成データでの画面検証</h1>" + content + "</body></html>"
			if err := os.WriteFile(filepath.Join(dir, name), []byte(page), 0600); err != nil {
				t.Fatal(err)
			}
		}
		write("index.html", body)
		failed := inventoryView("alpha-vps-fixture", []json.RawMessage{inventoryFixture(now, "", "permission_denied"), inventoryFixture(now.Add(-10*time.Minute), "2.0", "ok")}, now)
		data.Inventory = &failed
		write("failed.html", renderInventoryPreview(t, data))
		stale := inventoryView("alpha-vps-fixture", []json.RawMessage{inventoryFixture(now.Add(-2*time.Hour), "2.0", "ok")}, now)
		data.Inventory = &stale
		write("stale.html", renderInventoryPreview(t, data))
	}
}
