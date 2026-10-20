package monitor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// setupIPMgmtEnv は管理 IP 台帳と config.toml を一時ディレクトリに作り、環境を向ける。
// protectNames が空なら [security].admin_protect_names は書かない。
func setupIPMgmtEnv(t *testing.T, protectNames []string) (base string) {
	t.Helper()
	base = t.TempDir()
	cfgDir := filepath.Join(base, "cfg")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	toml := "[security]\n"
	if len(protectNames) > 0 {
		quoted := make([]string, len(protectNames))
		for i, n := range protectNames {
			quoted[i] = `"` + n + `"`
		}
		toml += "admin_protect_names = [" + strings.Join(quoted, ", ") + "]\n"
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	ledger := `[[ips]]
ip = "203.0.113.1"
name = "Alice Admin"
type = "wlm"

[[ips]]
ip = "203.0.113.2"
name = "Bob"
type = "wla"
`
	if err := os.MkdirAll(filepath.Join(base, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, managedIPsTOMLPath), []byte(ledger), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HEARTDESK_BASE_DIR", base)
	t.Setenv("HEARTDESK_CONFIG_DIR", cfgDir)
	config.ReloadConfigCache()
	t.Cleanup(config.ReloadConfigCache)
	return base
}

func TestMatchAdminProtected(t *testing.T) {
	names := []string{"Alice Admin", "  Carol  ", ""}
	tests := []struct {
		name string
		want bool
	}{
		{"Alice Admin", true},
		{"Carol", true}, // 設定側の前後の空白は無視する
		{"Bob", false},
		{"alice admin", false}, // 大文字小文字は区別する
		{"Alice Admin ", false},
		{"", false}, // 空の名前は、設定に空要素があっても保護対象にしない
	}
	for _, tt := range tests {
		if got := matchAdminProtected(names, tt.name); got != tt.want {
			t.Errorf("matchAdminProtected(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
	if matchAdminProtected(nil, "Alice Admin") {
		t.Error("名前の一覧が空なら、誰も保護対象にならない")
	}
}

// 設定が無いときは誰も保護しない（特定の個人名を既定値にしない）。
func TestIsAdminProtected_DefaultIsEmpty(t *testing.T) {
	setupIPMgmtEnv(t, nil)
	for _, n := range []string{"Alice Admin", "Bob", ""} {
		if isAdminProtected(n) {
			t.Errorf("isAdminProtected(%q) = true, 設定が無いので false のはず", n)
		}
	}
}

func TestGetIPMgmt_AdminProtected(t *testing.T) {
	setupIPMgmtEnv(t, []string{"Alice Admin"})
	d := GetIPMgmt()
	if len(d.IPs) != 2 {
		t.Fatalf("IPs = %d 件, want 2", len(d.IPs))
	}
	got := map[string]bool{}
	for _, e := range d.IPs {
		got[e.Name] = e.AdminProtected
	}
	if !got["Alice Admin"] {
		t.Error("Alice Admin の行は admin_protected=true のはず")
	}
	if got["Bob"] {
		t.Error("Bob の行は admin_protected=false のはず")
	}

	// API の応答（JSON）に admin_protected が bool で含まれる。
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		IPs []map[string]interface{} `json:"ips"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, e := range decoded.IPs {
		v, ok := e["admin_protected"].(bool)
		if !ok {
			t.Fatalf("admin_protected が bool で含まれない: %v", e)
		}
		if want := e["name"] == "Alice Admin"; v != want {
			t.Errorf("name=%v の admin_protected = %v, want %v", e["name"], v, want)
		}
	}
}

func TestGetIPMgmt_NoProtectedByDefault(t *testing.T) {
	setupIPMgmtEnv(t, nil)
	for _, e := range GetIPMgmt().IPs {
		if e.AdminProtected {
			t.Errorf("%q: 設定が無いので admin_protected=false のはず", e.Name)
		}
	}
}

// admin_protected は応答専用の項目で、台帳（TOML）には書き出さない。
func TestAdminProtected_NotWrittenToLedger(t *testing.T) {
	base := setupIPMgmtEnv(t, []string{"Alice Admin"})
	data, err := loadManagedIPs()
	if err != nil {
		t.Fatal(err)
	}
	data[0].AdminProtected = true
	if err := writeManagedIPs(data); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(base, managedIPsTOMLPath))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "admin_protected") {
		t.Errorf("台帳に admin_protected が書き出されている:\n%s", raw)
	}
}

// 保護対象の行は、削除・名称変更・種別変更が拒否され、台帳が変わらない。
func TestAdminProtected_RejectsMutations(t *testing.T) {
	base := setupIPMgmtEnv(t, []string{"Alice Admin"})
	path := filepath.Join(base, managedIPsTOMLPath)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := RemoveIP("203.0.113.1"); err == nil || !strings.Contains(err.Error(), "削除できません") {
		t.Errorf("RemoveIP: 保護対象の削除が拒否されない: %v", err)
	}
	if err := RenameIP("203.0.113.1", "Mallory", "tester"); err == nil || !strings.Contains(err.Error(), "変更できません") {
		t.Errorf("RenameIP: 保護対象の名称変更が拒否されない: %v", err)
	}
	if err := ChangeTypeIP("203.0.113.1", "wla", "tester"); err == nil || !strings.Contains(err.Error(), "変更できません") {
		t.Errorf("ChangeTypeIP: 保護対象の種別変更が拒否されない: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("拒否したのに台帳が変わった:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}
