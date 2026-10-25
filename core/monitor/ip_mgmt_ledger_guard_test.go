package monitor

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// 台帳（managed_ips.toml / 旧 JSON）が無いホストでは、fail2ban の ignoreip 同期を呼ばない。
// 空の台帳から ignoreip を作ると jail.local の手書きの許可 IP が消えるため
// （2026-10-21: 対象ホスト は台帳が無く、手書きの許可 IP を持っていた）。

func writeLedgerFile(t *testing.T, base, rel, body string) {
	t.Helper()
	p := filepath.Join(base, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// syncCalls は syncFail2banIgnoreIPFn を差し替えて、呼ばれた回数と渡されたデータを記録する。
// 実機の /etc/fail2ban や sudo には触れない。
func syncCalls(t *testing.T) *[][]SSHAllowedIP {
	t.Helper()
	var calls [][]SSHAllowedIP
	orig := syncFail2banIgnoreIPFn
	syncFail2banIgnoreIPFn = func(data []SSHAllowedIP) { calls = append(calls, data) }
	t.Cleanup(func() { syncFail2banIgnoreIPFn = orig })
	return &calls
}

// 本番の既定値は syncFail2banIgnoreIP そのもの。差し替え用の変数が無処理の関数に
// 変わると、台帳のあるホスト（既存ホスト）でも ignoreip が同期されなくなるため固定する。
func TestSyncFail2banIgnoreIPFnDefaultsToRealSync(t *testing.T) {
	got := reflect.ValueOf(syncFail2banIgnoreIPFn).Pointer()
	want := reflect.ValueOf(syncFail2banIgnoreIP).Pointer()
	if got != want {
		t.Fatal("syncFail2banIgnoreIPFn の既定値が syncFail2banIgnoreIP ではない")
	}
}

func TestManagedIPsLedgerExists(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"どちらも無い", nil, false},
		{"TOML がある", map[string]string{managedIPsTOMLPath: "ips = []\n"}, true},
		{"旧 JSON だけある", map[string]string{legacyManagedIPsJSONPath: "[]"}, true},
		{"両方ある", map[string]string{managedIPsTOMLPath: "ips = []\n", legacyManagedIPsJSONPath: "[]"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := t.TempDir()
			t.Setenv("HEARTDESK_BASE_DIR", base)
			for rel, body := range c.files {
				writeLedgerFile(t, base, rel, body)
			}
			if got := managedIPsLedgerExists(); got != c.want {
				t.Fatalf("managedIPsLedgerExists() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestSyncIPManageSkipsFail2banWhenNoLedger(t *testing.T) {
	t.Setenv("HEARTDESK_BASE_DIR", t.TempDir())
	calls := syncCalls(t)

	if err := syncIPManage(true); err != nil {
		t.Fatalf("syncIPManage: %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("台帳が無いのに fail2ban 同期が %d 回呼ばれた", len(*calls))
	}
}

func TestSyncIPManageCallsFail2banWhenLedgerExists(t *testing.T) {
	cases := []struct {
		name    string
		rel     string
		body    string
		wantIPs []string
	}{
		{
			"エントリのある TOML",
			managedIPsTOMLPath,
			"[[ips]]\nip = \"192.0.2.10\"\nname = \"example\"\ntype = \"wlm\"\n",
			[]string{"192.0.2.10"},
		},
		{
			// 画面で全エントリを消した場合は、従来どおり ignoreip を空に同期する（ファイルは残る）。
			"空の TOML（全エントリ削除後）",
			managedIPsTOMLPath,
			"ips = []\n",
			nil,
		},
		{
			"旧 JSON",
			legacyManagedIPsJSONPath,
			`[{"ip":"198.51.100.7","name":"legacy","type":"known"}]`,
			[]string{"198.51.100.7"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := t.TempDir()
			t.Setenv("HEARTDESK_BASE_DIR", base)
			writeLedgerFile(t, base, c.rel, c.body)
			calls := syncCalls(t)

			if err := syncIPManage(true); err != nil {
				t.Fatalf("syncIPManage: %v", err)
			}
			if len(*calls) != 1 {
				t.Fatalf("fail2ban 同期の呼び出し回数 = %d, want 1", len(*calls))
			}
			got := (*calls)[0]
			if len(got) != len(c.wantIPs) {
				t.Fatalf("渡された台帳の件数 = %d, want %d (%v)", len(got), len(c.wantIPs), got)
			}
			for i, ip := range c.wantIPs {
				if got[i].IP != ip {
					t.Fatalf("got[%d].IP = %q, want %q", i, got[i].IP, ip)
				}
			}
		})
	}
}

func TestSyncIPManageLedgerReadErrorsDoNotSyncOrFallBack(t *testing.T) {
	for _, asDirectory := range []bool{false, true} {
		t.Run(map[bool]string{false: "malformed TOML", true: "TOML path is a directory"}[asDirectory], func(t *testing.T) {
			base := t.TempDir()
			t.Setenv("HEARTDESK_BASE_DIR", base)
			writeLedgerFile(t, base, legacyManagedIPsJSONPath, `[{"ip":"198.51.100.7","name":"legacy","type":"known"}]`)
			if asDirectory {
				if err := os.MkdirAll(filepath.Join(base, managedIPsTOMLPath), 0755); err != nil {
					t.Fatal(err)
				}
			} else {
				writeLedgerFile(t, base, managedIPsTOMLPath, "ips = [")
			}
			calls := syncCalls(t)
			if !managedIPsLedgerExists() {
				t.Fatal("existing unreadable or malformed TOML must not count as absent")
			}
			if err := syncIPManage(true); err == nil {
				t.Fatal("ledger load error was ignored")
			}
			if len(*calls) != 0 {
				t.Fatal("ledger load failure must return before fail2ban synchronization")
			}
		})
	}
}
